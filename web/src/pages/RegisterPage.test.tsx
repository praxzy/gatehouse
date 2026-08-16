import { screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { RegisterPage } from './RegisterPage'
import { renderWithProviders } from '@/test/render'

describe('RegisterPage', () => {
  it('shows email verification instructions after registration', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          tenant_id: 'tenant-alpha',
          user_id: 'user-alpha',
          membership_id: 'membership-alpha',
          owner_role_id: 'role-owner',
        }),
        {
          status: 201,
          headers: {
            'Content-Type': 'application/json',
          },
        },
      ),
    )

    vi.stubGlobal('fetch', fetchMock)

    const { user } = renderWithProviders(<RegisterPage />, {
      route: '/register',
    })

    await user.type(screen.getByLabelText('Organization name'), 'Alpha Labs')
    await user.type(screen.getByLabelText('Organization slug'), 'alpha-labs')
    await user.click(
      screen.getByRole('button', {
        name: 'Continue to Owner account',
      }),
    )

    await user.type(screen.getByLabelText('Your name'), 'Alpha Owner')
    await user.type(screen.getByLabelText('Work email'), 'owner@alpha.test')
    await user.type(screen.getByLabelText('Password'), 'correct horse battery staple')
    await user.type(screen.getByLabelText('Confirm'), 'correct horse battery staple')

    await user.click(
      screen.getByRole('button', {
        name: 'Create organization',
      }),
    )

    expect(
      await screen.findByRole('heading', {
        name: 'Check your email',
      }),
    ).toBeInTheDocument()

    expect(screen.getByText('owner@alpha.test')).toBeInTheDocument()
    expect(screen.getByText('alpha-labs')).toBeInTheDocument()

    expect(fetchMock).toHaveBeenCalledWith(
      '/api/v1/auth/register',
      expect.objectContaining({
        method: 'POST',
        credentials: 'include',
        body: JSON.stringify({
          tenant_name: 'Alpha Labs',
          tenant_slug: 'alpha-labs',
          display_name: 'Alpha Owner',
          email: 'owner@alpha.test',
          password: 'correct horse battery staple',
        }),
      }),
    )
  })
})
