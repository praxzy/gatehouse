import { screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import type { CurrentUser } from '@/api/auth'
import { applicationsQueryKey } from '@/applications/queries'
import { currentUserQueryKey } from '@/auth/currentUser'
import { permissions } from '@/auth/permissions'
import { membersQueryKey } from '@/members/queries'
import { DashboardPage } from '@/pages/DashboardPage'
import { rolesQueryKey } from '@/roles/queries'
import { createTestQueryClient, renderWithProviders } from '@/test/render'

const dashboardUser: CurrentUser = {
  user_id: '11111111-1111-4111-8111-111111111111',
  email: 'owner@example.test',
  display_name: 'Owner',
  tenant_id: '22222222-2222-4222-8222-222222222222',
  tenant_name: 'Example Company',
  tenant_slug: 'example-company',
  membership_id: '33333333-3333-4333-8333-333333333333',
  authentication_level: 'mfa',
  session_expires_at: '2099-01-01T00:00:00Z',
  mfa_required: true,
  mfa_enrolled: true,
  fully_authenticated: true,
  permissions: [],
  capabilities: { manage_members: false },
}

describe('DashboardPage activity preview', () => {
  it('shows recent audit events to users with audit.read', async () => {
    const fetchMock = vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            events: [
              {
                event_id: 'event-1',
                actor_kind: 'user',
                actor_display_name: 'Alice',
                event_type: 'auth.login',
                outcome: 'success',
                metadata: {},
                occurred_at: '2026-09-16T10:00:00Z',
              },
            ],
          }),
          {
            headers: { 'Content-Type': 'application/json' },
          },
        ),
    )
    vi.stubGlobal('fetch', fetchMock)

    const queryClient = createTestQueryClient()
    queryClient.setQueryData(currentUserQueryKey, {
      ...dashboardUser,
      permissions: [permissions.auditRead],
    })

    renderWithProviders(<DashboardPage />, { queryClient })

    expect(await screen.findByText('Auth login')).toBeInTheDocument()
    expect(screen.getByText('Alice')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'View all' })).toHaveAttribute('href', '/app/audit')
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/v1/audit-events?page_size=3',
      expect.objectContaining({ credentials: 'include' }),
    )
  })

  it('does not show or request audit events without audit.read', () => {
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)

    const queryClient = createTestQueryClient()
    queryClient.setQueryData(currentUserQueryKey, dashboardUser)

    renderWithProviders(<DashboardPage />, { queryClient })

    expect(screen.queryByText('Recent activity')).not.toBeInTheDocument()
    expect(screen.queryByText('No activity yet.')).not.toBeInTheDocument()
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('summarizes live workspace state and surfaces access policy actions', () => {
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)

    const queryClient = createTestQueryClient()
    queryClient.setQueryData(currentUserQueryKey, {
      ...dashboardUser,
      permissions: [
        permissions.memberRead,
        permissions.memberManage,
        permissions.roleRead,
        permissions.applicationRead,
        permissions.applicationManage,
      ],
    })
    queryClient.setQueryData(membersQueryKey, {
      members: [
        {
          membership_id: 'membership-1',
          user_id: 'user-1',
          email: 'alice@example.test',
          display_name: 'Alice',
          status: 'active',
          role_id: 'role-owner',
          role_key: 'owner',
          role_name: 'Owner',
          created_at: '2026-09-01T10:00:00Z',
          updated_at: '2026-09-01T10:00:00Z',
        },
        {
          membership_id: 'membership-2',
          user_id: 'user-2',
          email: 'bob@example.test',
          display_name: 'Bob',
          status: 'active',
          role_id: 'role-viewer',
          role_key: 'viewer',
          role_name: 'Viewer',
          created_at: '2026-09-01T10:00:00Z',
          updated_at: '2026-09-01T10:00:00Z',
        },
        {
          membership_id: 'membership-3',
          user_id: 'user-3',
          email: 'disabled@example.test',
          display_name: 'Disabled user',
          status: 'disabled',
          role_id: 'role-viewer',
          role_key: 'viewer',
          role_name: 'Viewer',
          created_at: '2026-09-01T10:00:00Z',
          updated_at: '2026-09-01T10:00:00Z',
        },
      ],
      invitations: [
        {
          invitation_id: 'invitation-1',
          email: 'invitee@example.test',
          role_id: 'role-viewer',
          role_name: 'Viewer',
          created_at: '2026-09-01T10:00:00Z',
          expires_at: '2099-09-08T10:00:00Z',
          expired: false,
        },
      ],
      roles: [],
    })
    queryClient.setQueryData(rolesQueryKey, {
      permissions: [],
      roles: [
        {
          role_id: 'role-owner',
          role_key: 'owner',
          name: 'Owner',
          description: 'Built-in owner',
          is_system: true,
          permissions: [],
        },
        {
          role_id: 'role-viewer',
          role_key: 'viewer',
          name: 'Viewer',
          description: 'Built-in viewer',
          is_system: true,
          permissions: [],
        },
        {
          role_id: 'role-support',
          name: 'Support',
          description: 'Custom support role',
          is_system: false,
          permissions: [],
        },
      ],
    })
    queryClient.setQueryData(applicationsQueryKey, {
      applications: [
        {
          application_id: 'application-1',
          name: 'Employee Portal',
          description: 'Demo portal',
          client_id: 'client-1',
          client_type: 'confidential',
          status: 'active',
          access_mode: 'all_active_members',
          redirect_uri_count: 1,
          allowed_role_count: 0,
          created_at: '2026-09-01T10:00:00Z',
          updated_at: '2026-09-01T10:00:00Z',
        },
        {
          application_id: 'application-2',
          name: 'Admin Portal',
          description: 'Restricted portal',
          client_id: 'client-2',
          client_type: 'public',
          status: 'active',
          access_mode: 'allowed_roles',
          redirect_uri_count: 1,
          allowed_role_count: 0,
          created_at: '2026-09-01T10:00:00Z',
          updated_at: '2026-09-01T10:00:00Z',
        },
      ],
    })

    renderWithProviders(<DashboardPage />, { queryClient })

    expect(screen.getByRole('heading', { name: 'Workspace at a glance' })).toBeInTheDocument()
    expect(screen.getByText('1 pending invite')).toBeInTheDocument()
    expect(screen.getByText('1 custom role')).toBeInTheDocument()
    expect(screen.getByText('2 active')).toBeInTheDocument()
    expect(screen.getByText('1 application has no allowed roles')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /Review access policies/ })).toHaveAttribute(
      'href',
      '/app/applications',
    )
    expect(fetchMock).not.toHaveBeenCalled()
  })
})
