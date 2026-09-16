import { screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import type { CurrentUser } from '@/api/auth'
import { currentUserQueryKey } from '@/auth/currentUser'
import { permissions } from '@/auth/permissions'
import { DashboardPage } from '@/pages/DashboardPage'
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
})
