import { screen, waitFor, within } from '@testing-library/react'
import { Route, Routes } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'
import { permissions } from '@/auth/permissions'
import { ApplicationDetailPage } from '@/pages/ApplicationDetailPage'
import { renderWithProviders } from '@/test/render'

describe('ApplicationDetailPage', () => {
  it('shows configuration without exposing a client secret', async () => {
    vi.stubGlobal('fetch', createApplicationDetailFetchMock())

    renderWithProviders(
      <Routes>
        <Route path="/app/applications/:applicationId" element={<ApplicationDetailPage />} />
      </Routes>,
      {
        route: '/app/applications/application-1',
      },
    )

    expect(
      await screen.findByRole('heading', {
        name: 'Employee Portal',
      }),
    ).toBeInTheDocument()

    expect(screen.getByText('ghc_test_client')).toBeInTheDocument()

    expect(screen.getByText('Client secret is not retrievable')).toBeInTheDocument()

    expect(screen.queryByText(/^ghs_/)).not.toBeInTheDocument()

    expect(
      screen.queryByRole('button', {
        name: /copy client secret/i,
      }),
    ).not.toBeInTheDocument()
  })

  it('updates application access to selected roles', async () => {
    const fetchMock = createApplicationDetailFetchMock()
    vi.stubGlobal('fetch', fetchMock)

    const { user } = renderWithProviders(
      <Routes>
        <Route path="/app/applications/:applicationId" element={<ApplicationDetailPage />} />
      </Routes>,
      {
        route: '/app/applications/application-1',
      },
    )

    await user.click(
      await screen.findByRole('button', {
        name: 'Edit access',
      }),
    )

    const dialog = await screen.findByRole('dialog', {
      name: 'Application access',
    })

    await user.click(within(dialog).getByRole('combobox'))

    await user.click(
      await screen.findByRole('option', {
        name: 'Selected roles',
      }),
    )

    await user.click(
      within(dialog).getByRole('checkbox', {
        name: /Admin/,
      }),
    )

    await user.click(
      within(dialog).getByRole('button', {
        name: 'Save access',
      }),
    )

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        '/api/v1/applications/application-1/access-policy',
        expect.objectContaining({
          method: 'PATCH',
          credentials: 'include',
          body: JSON.stringify({
            access_mode: 'allowed_roles',
            allowed_role_ids: ['role-admin'],
          }),
        }),
      )
    })

    expect(await screen.findByText('Limited to selected roles')).toBeInTheDocument()
    expect(screen.getByText('Admin')).toBeInTheDocument()
  })
})

function createApplicationDetailFetchMock() {
  let accessMode = 'all_active_members'
  let allowedRoleIDs: string[] = []

  const roles = [
    {
      role_id: 'role-admin',
      name: 'Admin',
      description: 'Can administer the employee portal.',
      is_system: false,
      permissions: [],
    },
    {
      role_id: 'role-member',
      role_key: 'member',
      name: 'Member',
      description: 'Standard organization member.',
      is_system: true,
      permissions: [],
    },
  ]

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

    if (path === '/api/v1/roles' && method === 'GET') {
      return jsonResponse({
        permissions: [],
        roles,
      })
    }

    if (path === '/api/v1/applications/application-1' && method === 'GET') {
      return jsonResponse({
        application_id: 'application-1',
        name: 'Employee Portal',
        description: 'Internal employee application',
        client_id: 'ghc_test_client',
        client_type: 'confidential',
        status: 'active',
        access_mode: accessMode,
        created_at: '2026-08-22T08:00:00Z',
        updated_at: '2026-08-22T08:00:00Z',
        redirect_uris: [
          {
            redirect_uri_id: 'redirect-1',
            uri: 'https://portal.example.test/callback',
            created_at: '2026-08-22T08:00:00Z',
          },
        ],
        allowed_roles: roles.filter((role) => allowedRoleIDs.includes(role.role_id)),
      })
    }

    if (path === '/api/v1/applications/application-1/access-policy' && method === 'PATCH') {
      const body = JSON.parse(String(options?.body)) as {
        access_mode: string
        allowed_role_ids: string[]
      }

      accessMode = body.access_mode
      allowedRoleIDs = body.allowed_role_ids

      return jsonResponse({
        access_mode: accessMode,
        allowed_roles: roles.filter((role) => allowedRoleIDs.includes(role.role_id)),
        updated_at: '2026-08-22T09:00:00Z',
      })
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
