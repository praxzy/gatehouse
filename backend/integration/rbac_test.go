package integration_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/praxzy/gatehouse/backend/internal/auth"
	"github.com/praxzy/gatehouse/backend/internal/httpapi"
)

func TestTenantScopedRBACRejectsForgedPermissions(
	t *testing.T,
) {
	ctx := context.Background()
	invitationSender :=
		&recordingMembershipInvitationSender{}

	authentication, pool :=
		newAuthenticationTestServiceWithSenders(
			t,
			ctx,
			discardEmailVerificationSender{},
			invitationSender,
		)

	registration, err := authentication.Register(
		ctx,
		auth.RegisterInput{
			TenantName:  "RBAC Company",
			TenantSlug:  "rbac-company",
			Email:       "owner@rbac.test",
			DisplayName: "RBAC Owner",
			Password:    "correct horse battery staple",
		},
	)
	if err != nil {
		t.Fatalf("register RBAC tenant: %v", err)
	}

	markTestEmailVerified(
		t,
		ctx,
		pool,
		registration.UserID,
	)

	router := httpapi.NewRouter(
		httpapi.Dependencies{
			Authentication: authentication,
			SessionCookie:  httpapi.NewSessionCookie(true),
		},
	)

	ownerCookie := loginLifecycleUser(
		t,
		router,
		"rbac-company",
		"owner@rbac.test",
		"correct horse battery staple",
	)

	memberRoleID := loadLifecycleRoleID(
		t,
		ctx,
		pool,
		registration.TenantID,
		"member",
	)

	inviteResponse := performLifecycleJSONRequest(
		t,
		router,
		http.MethodPost,
		"/api/v1/members",
		map[string]string{
			"email": "member@rbac.test",
			"role_id": lifecycleUUID(
				t,
				memberRoleID,
			),
		},
		ownerCookie,
	)
	requireResponseStatus(
		t,
		inviteResponse,
		http.StatusCreated,
	)

	if len(invitationSender.deliveries) != 1 {
		t.Fatalf(
			"expected one invitation delivery, got %d",
			len(invitationSender.deliveries),
		)
	}

	acceptResponse := performLifecycleJSONRequest(
		t,
		router,
		http.MethodPost,
		"/api/v1/invitations/accept",
		map[string]string{
			"token":        invitationSender.deliveries[0].Token,
			"display_name": "RBAC Member",
			"password":     "another secure password",
		},
		nil,
	)
	requireResponseStatus(
		t,
		acceptResponse,
		http.StatusOK,
	)

	memberCookie := loginLifecycleUser(
		t,
		router,
		"rbac-company",
		"member@rbac.test",
		"another secure password",
	)

	t.Run(
		"member cannot list roles",
		func(t *testing.T) {
			response := performRequest(
				t,
				router,
				http.MethodGet,
				"/api/v1/roles",
				nil,
				memberCookie,
			)

			requireResponseStatus(
				t,
				response,
				http.StatusForbidden,
			)
		},
	)

	t.Run(
		"member cannot forge an administrative role",
		func(t *testing.T) {
			response := performLifecycleJSONRequest(
				t,
				router,
				http.MethodPost,
				"/api/v1/roles",
				map[string]any{
					"name":        "Forged Administrator",
					"description": "Attempted privilege escalation",
					"permissions": []string{
						auth.PermissionMemberManage,
						auth.PermissionRoleManage,
					},
				},
				memberCookie,
			)

			requireResponseStatus(
				t,
				response,
				http.StatusForbidden,
			)

			assertDatabaseCount(
				t,
				ctx,
				pool,
				`
					SELECT count(*)
					FROM roles
					WHERE tenant_id = $1
					  AND name = $2
				`,
				0,
				registration.TenantID,
				"Forged Administrator",
			)
		},
	)

	t.Run(
		"service layer independently rejects member",
		func(t *testing.T) {
			session, err := authentication.ResolveSession(
				ctx,
				memberCookie.Value,
			)
			if err != nil {
				t.Fatalf(
					"resolve member session: %v",
					err,
				)
			}

			_, err = authentication.CreateRole(
				ctx,
				session,
				auth.CreateRoleInput{
					Name: "Service Layer Forgery",
					Permissions: []string{
						auth.PermissionRoleManage,
					},
				},
			)
			if !errors.Is(
				err,
				auth.ErrRoleManagementForbidden,
			) {
				t.Fatalf(
					"expected role management rejection, got %v",
					err,
				)
			}

			assertDatabaseCount(
				t,
				ctx,
				pool,
				`
					SELECT count(*)
					FROM roles
					WHERE tenant_id = $1
					  AND name = $2
				`,
				0,
				registration.TenantID,
				"Service Layer Forgery",
			)
		},
	)

	var customRoleID string

	t.Run(
		"owner creates a catalog-backed custom role",
		func(t *testing.T) {
			response := performLifecycleJSONRequest(
				t,
				router,
				http.MethodPost,
				"/api/v1/roles",
				map[string]any{
					"name":        "Support Operator",
					"description": "Reviews tenant members",
					"permissions": []string{
						auth.PermissionTenantRead,
						auth.PermissionMemberRead,
					},
				},
				ownerCookie,
			)

			body := requireResponseStatus(
				t,
				response,
				http.StatusCreated,
			)

			var created struct {
				RoleID      string   `json:"role_id"`
				Name        string   `json:"name"`
				IsSystem    bool     `json:"is_system"`
				Permissions []string `json:"permissions"`
			}
			if err := json.Unmarshal(
				body,
				&created,
			); err != nil {
				t.Fatalf(
					"decode created role: %v",
					err,
				)
			}

			if created.RoleID == "" {
				t.Fatal("created role did not include an ID")
			}
			if created.Name != "Support Operator" {
				t.Fatalf(
					"unexpected role name %q",
					created.Name,
				)
			}
			if created.IsSystem {
				t.Fatal("custom role was marked as system")
			}
			if len(created.Permissions) != 2 {
				t.Fatalf(
					"expected two permissions, got %v",
					created.Permissions,
				)
			}

			customRoleID = created.RoleID

			assertDatabaseCount(
				t,
				ctx,
				pool,
				`
					SELECT count(*)
					FROM role_permissions
					WHERE tenant_id = $1
					  AND role_id = $2
				`,
				2,
				registration.TenantID,
				customRoleID,
			)
		},
	)

	t.Run(
		"owner updates a custom role",
		func(t *testing.T) {
			response := performLifecycleJSONRequest(
				t,
				router,
				http.MethodPut,
				"/api/v1/roles/"+customRoleID,
				map[string]any{
					"name":        "Support Administrator",
					"description": "Manages tenant members",
					"permissions": []string{
						auth.PermissionTenantRead,
						auth.PermissionMemberRead,
						auth.PermissionMemberManage,
					},
				},
				ownerCookie,
			)

			body := requireResponseStatus(
				t,
				response,
				http.StatusOK,
			)

			var updated struct {
				Name        string   `json:"name"`
				Permissions []string `json:"permissions"`
			}
			if err := json.Unmarshal(
				body,
				&updated,
			); err != nil {
				t.Fatalf(
					"decode updated role: %v",
					err,
				)
			}

			if updated.Name != "Support Administrator" {
				t.Fatalf(
					"unexpected updated role name %q",
					updated.Name,
				)
			}
			if len(updated.Permissions) != 3 {
				t.Fatalf(
					"expected three permissions, got %v",
					updated.Permissions,
				)
			}
		},
	)

	t.Run(
		"unknown permission rolls back role creation",
		func(t *testing.T) {
			response := performLifecycleJSONRequest(
				t,
				router,
				http.MethodPost,
				"/api/v1/roles",
				map[string]any{
					"name": "Unknown Permission Role",
					"permissions": []string{
						"system.take_over",
					},
				},
				ownerCookie,
			)

			requireResponseStatus(
				t,
				response,
				http.StatusBadRequest,
			)

			assertDatabaseCount(
				t,
				ctx,
				pool,
				`
					SELECT count(*)
					FROM roles
					WHERE tenant_id = $1
					  AND name = $2
				`,
				0,
				registration.TenantID,
				"Unknown Permission Role",
			)
		},
	)

	t.Run(
		"built-in owner role is immutable",
		func(t *testing.T) {
			response := performLifecycleJSONRequest(
				t,
				router,
				http.MethodPut,
				"/api/v1/roles/"+
					lifecycleUUID(
						t,
						registration.OwnerRoleID,
					),
				map[string]any{
					"name": "Modified Owner",
					"permissions": []string{
						auth.PermissionTenantRead,
					},
				},
				ownerCookie,
			)

			requireResponseStatus(
				t,
				response,
				http.StatusConflict,
			)
		},
	)

	t.Run(
		"foreign tenant role ID is not visible",
		func(t *testing.T) {
			foreignRegistration, err :=
				authentication.Register(
					ctx,
					auth.RegisterInput{
						TenantName:  "Foreign Company",
						TenantSlug:  "foreign-company",
						Email:       "owner@foreign.test",
						DisplayName: "Foreign Owner",
						Password:    "correct horse battery staple",
					},
				)
			if err != nil {
				t.Fatalf(
					"register foreign tenant: %v",
					err,
				)
			}

			response := performLifecycleJSONRequest(
				t,
				router,
				http.MethodPut,
				"/api/v1/roles/"+
					lifecycleUUID(
						t,
						foreignRegistration.OwnerRoleID,
					),
				map[string]any{
					"name": "Cross Tenant Mutation",
					"permissions": []string{
						auth.PermissionRoleManage,
					},
				},
				ownerCookie,
			)

			requireResponseStatus(
				t,
				response,
				http.StatusNotFound,
			)
		},
	)

	t.Run(
		"final owner invariant remains enforced",
		func(t *testing.T) {
			response := performLifecycleJSONRequest(
				t,
				router,
				http.MethodPatch,
				"/api/v1/members/"+
					lifecycleUUID(
						t,
						registration.MembershipID,
					),
				map[string]string{
					"status": "disabled",
				},
				ownerCookie,
			)

			requireResponseStatus(
				t,
				response,
				http.StatusConflict,
			)
		},
	)
}
