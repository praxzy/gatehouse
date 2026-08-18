import { screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { permissions } from '@/auth/permissions'
import { MembersPage } from './MembersPage'
import { renderWithProviders } from '@/test/render'

describe('MembersPage', () => {
  it('confirms a role change before sending the request', async () => {
    let selectedRole = {
      role_id: 'role-member',
      role_key: 'member',
      role_name: 'Member',
    }

    const fetchMock = vi.fn(async (input: RequestInfo | URL, options?: RequestInit) => {
      const path =
        typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url

      const method = options?.method ?? 'GET'

      if (path === '/api/v1/auth/current-user' && method === 'GET') {
        return new Response(
          JSON.stringify({
            permissions: [permissions.memberManage],
          }),
          {
            status: 200,
            headers: {
              'Content-Type': 'application/json',
            },
          },
        )
      }

      if (path === '/api/v1/members' && method === 'GET') {
        return new Response(
          JSON.stringify({
            members: [
              {
                membership_id: 'membership-jordan',
                user_id: 'user-jordan',
                email: 'jordan@alpha.test',
                display_name: 'Jordan Lee',
                status: 'active',
                role_id: selectedRole.role_id,
                role_key: selectedRole.role_key,
                role_name: selectedRole.role_name,
                created_at: '2026-08-18T08:00:00Z',
                updated_at: '2026-08-18T08:00:00Z',
              },
            ],
            invitations: [],
            roles: [
              {
                role_id: 'role-owner',
                role_key: 'owner',
                role_name: 'Owner',
              },
              {
                role_id: 'role-member',
                role_key: 'member',
                role_name: 'Member',
              },
            ],
          }),
          {
            status: 200,
            headers: {
              'Content-Type': 'application/json',
            },
          },
        )
      }

      if (path === '/api/v1/members/membership-jordan' && method === 'PATCH') {
        selectedRole = {
          role_id: 'role-owner',
          role_key: 'owner',
          role_name: 'Owner',
        }

        return new Response(null, {
          status: 204,
        })
      }

      throw new Error(`Unexpected request: ${method} ${path}`)
    })

    vi.stubGlobal('fetch', fetchMock)

    const { user } = renderWithProviders(<MembersPage />, {
      route: '/app/members',
    })

    expect(
      await screen.findByRole('heading', {
        name: 'Members',
      }),
    ).toBeInTheDocument()

    await user.click(
      screen.getByRole('combobox', {
        name: 'Role for Jordan Lee',
      }),
    )

    await user.click(
      await screen.findByRole('option', {
        name: 'Owner',
      }),
    )

    expect(
      screen.getByRole('alertdialog', {
        name: 'Change Jordan Lee’s role?',
      }),
    ).toBeInTheDocument()

    expect(fetchMock).not.toHaveBeenCalledWith(
      '/api/v1/members/membership-jordan',
      expect.objectContaining({
        method: 'PATCH',
      }),
    )

    await user.click(
      screen.getByRole('button', {
        name: 'Change role',
      }),
    )

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        '/api/v1/members/membership-jordan',
        expect.objectContaining({
          method: 'PATCH',
          credentials: 'include',
          body: JSON.stringify({
            role_id: 'role-owner',
          }),
        }),
      )
    })

    await waitFor(() => {
      expect(
        screen.getByRole('combobox', {
          name: 'Role for Jordan Lee',
        }),
      ).toHaveTextContent('Owner')
    })
  })
})
