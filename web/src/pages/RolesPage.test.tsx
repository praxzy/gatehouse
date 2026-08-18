import { screen, waitFor, within } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { permissions } from '@/auth/permissions'
import { RolesPage } from '@/pages/RolesPage'
import { renderWithProviders } from '@/test/render'

const roleResponse = {
  permissions: [
    {
      permission: permissions.memberRead,
      name: 'View members',
      description: 'View tenant members and pending invitations.',
    },
    {
      permission: permissions.memberManage,
      name: 'Manage members',
      description: 'Invite members and change their role or status.',
    },
  ],
  roles: [
    {
      role_id: 'role-owner',
      role_key: 'owner',
      name: 'Owner',
      description: 'Full organization access.',
      is_system: true,
      permissions: [permissions.memberRead, permissions.memberManage],
    },
    {
      role_id: 'role-support',
      name: 'Support',
      description: 'Reviews organization members.',
      is_system: false,
      permissions: [permissions.memberRead],
    },
  ],
}

describe('RolesPage', () => {
  it('shows roles without management controls to read-only users', async () => {
    const fetchMock = createRolesFetchMock([permissions.roleRead])

    vi.stubGlobal('fetch', fetchMock)

    renderWithProviders(<RolesPage />, {
      route: '/app/roles',
    })

    expect(
      await screen.findByRole('heading', {
        name: 'Roles',
      }),
    ).toBeInTheDocument()

    expect(screen.getByRole('heading', { name: 'Owner' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Support' })).toBeInTheDocument()

    expect(
      screen.queryByRole('button', {
        name: 'Create role',
      }),
    ).not.toBeInTheDocument()

    expect(
      screen.queryByRole('button', {
        name: 'Edit role',
      }),
    ).not.toBeInTheDocument()
  })

  it('creates a catalog-backed custom role', async () => {
    const fetchMock = createRolesFetchMock([permissions.roleRead, permissions.roleManage])

    vi.stubGlobal('fetch', fetchMock)

    const { user } = renderWithProviders(<RolesPage />, {
      route: '/app/roles',
    })

    await user.click(
      await screen.findByRole('button', {
        name: 'Create role',
      }),
    )

    const editor = await screen.findByRole('dialog', {
      name: 'Create role',
    })

    await user.type(
      within(editor).getByRole('textbox', {
        name: 'Role name',
      }),
      'Member Auditor',
    )

    await user.type(
      within(editor).getByRole('textbox', {
        name: 'Description',
      }),
      'Reviews the member directory.',
    )

    await user.click(
      within(editor).getByRole('checkbox', {
        name: /View members/,
      }),
    )

    await user.click(
      within(editor).getByRole('button', {
        name: 'Create role',
      }),
    )

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        '/api/v1/roles',
        expect.objectContaining({
          method: 'POST',
          credentials: 'include',
          body: JSON.stringify({
            name: 'Member Auditor',
            description: 'Reviews the member directory.',
            permissions: [permissions.memberRead],
          }),
        }),
      )
    })
  })
})

function createRolesFetchMock(grantedPermissions: string[]) {
  return vi.fn(async (input: RequestInfo | URL, options?: RequestInit) => {
    const path =
      typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url

    const method = options?.method ?? 'GET'

    if (path === '/api/v1/auth/current-user' && method === 'GET') {
      return jsonResponse({
        permissions: grantedPermissions,
      })
    }

    if (path === '/api/v1/roles' && method === 'GET') {
      return jsonResponse(roleResponse)
    }

    if (path === '/api/v1/roles' && method === 'POST') {
      return jsonResponse(
        {
          role_id: 'role-auditor',
          name: 'Member Auditor',
          description: 'Reviews the member directory.',
          is_system: false,
          permissions: [permissions.memberRead],
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
