package auth

const (
	PermissionTenantRead   = "tenant.read"
	PermissionMemberRead   = "member.read"
	PermissionMemberManage = "member.manage"
	PermissionRoleRead     = "role.read"
	PermissionRoleManage   = "role.manage"
)

func (session SessionContext) HasPermission(
	required string,
) bool {
	for _, permission := range session.Permissions {
		if permission == required {
			return true
		}
	}

	return false
}
