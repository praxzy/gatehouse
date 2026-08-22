import { screen, waitFor, within } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { permissions } from '@/auth/permissions'
import { ApplicationsPage } from '@/pages/ApplicationsPage'
import { renderWithProviders } from '@/test/render'

describe('ApplicationsPage', () => {
  it('renders registered applications without secrets', async () => {
    vi.stubGlobal(
      'fetch',
      createApplicationsFetchMock({
        applications: [
          {
            application_id: 'application-1',
            name: 'Employee Portal',
            description: 'Internal employee application',
            client_id: 'ghc_test_client',
            client_type: 'confidential',
            status: 'active',
            access_mode: 'all_active_members',
            redirect_uri_count: 1,
            allowed_role_count: 0,
            created_at: '2026-08-22T08:00:00Z',
            updated_at: '2026-08-22T08:00:00Z',
          },
        ],
      }),
    )

    renderWithProviders(<ApplicationsPage />, {
      route: '/app/applications',
    })

    expect(
      await screen.findByRole('heading', {
        name: 'Applications',
      }),
    ).toBeInTheDocument()

    expect(
      screen.getByRole('heading', {
        name: 'Employee Portal',
      }),
    ).toBeInTheDocument()

    expect(screen.getByText('ghc_test_client')).toBeInTheDocument()
    expect(screen.queryByText(/^ghs_/)).not.toBeInTheDocument()
  })

  it('shows a confidential secret once after creation', async () => {
    const fetchMock = createApplicationsFetchMock({
      applications: [],
    })

    vi.stubGlobal('fetch', fetchMock)

    const { user } = renderWithProviders(<ApplicationsPage />, {
      route: '/app/applications',
    })

    await user.click(
      await screen.findByRole('button', {
        name: 'Create application',
      }),
    )

    const dialog = await screen.findByRole('dialog', {
      name: 'Create application',
    })

    await user.type(
      within(dialog).getByRole('textbox', {
        name: 'Application name',
      }),
      'Employee Portal',
    )

    await user.type(
      within(dialog).getByRole('textbox', {
        name: 'Redirect URI 1',
      }),
      'https://portal.example.test/callback',
    )

    await user.click(
      within(dialog).getByRole('button', {
        name: 'Create application',
      }),
    )

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        '/api/v1/applications',
        expect.objectContaining({
          method: 'POST',
          credentials: 'include',
          body: JSON.stringify({
            name: 'Employee Portal',
            description: '',
            client_type: 'confidential',
            redirect_uris: ['https://portal.example.test/callback'],
            access_mode: 'all_active_members',
            allowed_role_ids: [],
          }),
        }),
      )
    })

    expect(
      await screen.findByRole('heading', {
        name: 'Application created',
      }),
    ).toBeInTheDocument()

    expect(screen.getByText('ghs_one_time_secret')).toBeInTheDocument()

    await user.click(
      screen.getByRole('button', {
        name: 'I’ve saved the secret',
      }),
    )

    await waitFor(() => {
      expect(screen.queryByText('ghs_one_time_secret')).not.toBeInTheDocument()
    })
  })
})

function createApplicationsFetchMock(listResponse: { applications: unknown[] }) {
  return vi.fn(async (input: RequestInfo | URL, options?: RequestInit) => {
    const path =
      typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url

    const method = options?.method ?? 'GET'

    if (path === '/api/v1/auth/current-user' && method === 'GET') {
      return jsonResponse({
        permissions: [
          permissions.applicationRead,
          permissions.applicationManage,
          permissions.roleRead,
        ],
      })
    }

    if (path === '/api/v1/applications' && method === 'GET') {
      return jsonResponse(listResponse)
    }

    if (path === '/api/v1/roles' && method === 'GET') {
      return jsonResponse({
        permissions: [],
        roles: [
          {
            role_id: 'role-owner',
            role_key: 'owner',
            name: 'Owner',
            description: 'Full organization access.',
            is_system: true,
            permissions: [],
          },
        ],
      })
    }

    if (path === '/api/v1/applications' && method === 'POST') {
      return jsonResponse(
        {
          application: {
            application_id: 'application-created',
            name: 'Employee Portal',
            description: '',
            client_id: 'ghc_created_client',
            client_type: 'confidential',
            status: 'active',
            access_mode: 'all_active_members',
            created_at: '2026-08-22T08:00:00Z',
            updated_at: '2026-08-22T08:00:00Z',
            redirect_uris: [
              {
                redirect_uri_id: 'redirect-1',
                uri: 'https://portal.example.test/callback',
                created_at: '2026-08-22T08:00:00Z',
              },
            ],
            allowed_roles: [],
          },
          client_secret: 'ghs_one_time_secret',
        },
        201,
      )
    }

    throw new Error(`Unexpected request: ${method} ${path}`)
  })
}

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json',
    },
  })
}
