import { screen, within } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { LoginPage } from './LoginPage'
import { renderWithProviders } from '@/test/render'

describe('LoginPage', () => {
  it('shows an API error with a collapsed error reference', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          error: 'invalid email or password',
          request_id: 'req-login-error',
        }),
        {
          status: 401,
          headers: {
            'Content-Type': 'application/json',
          },
        },
      ),
    )

    vi.stubGlobal('fetch', fetchMock)

    const { user } = renderWithProviders(<LoginPage />, {
      route: '/login',
    })

    await user.type(screen.getByLabelText('Organization slug'), 'alpha')
    await user.type(screen.getByLabelText('Email address'), 'owner@alpha.test')
    await user.type(screen.getByLabelText('Password'), 'incorrect-password')

    await user.click(
      screen.getByRole('button', {
        name: 'Sign in',
      }),
    )

    expect(await screen.findByText('invalid email or password')).toBeInTheDocument()

    const ErrorReference = screen.getByText('Error reference').closest('details')

    expect(ErrorReference).not.toBeNull()
    expect(ErrorReference).not.toHaveAttribute('open')

    expect(within(ErrorReference!).getByText('Request ID: req-login-error')).toBeInTheDocument()

    expect(fetchMock).toHaveBeenCalledOnce()
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/v1/auth/login',
      expect.objectContaining({
        method: 'POST',
        credentials: 'include',
      }),
    )
  })
})
