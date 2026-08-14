import { screen, within } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import type { CurrentUser } from '@/api/auth'
import { currentUserQueryKey } from '@/auth/currentUser'
import { renderWithProviders, createTestQueryClient } from '@/test/render'
import { MFAChallengePage } from './MFAChallengePage'

const passwordSession: CurrentUser = {
  user_id: 'user-alpha',
  email: 'owner@alpha.test',
  display_name: 'Alpha Owner',
  tenant_id: 'tenant-alpha',
  tenant_name: 'Alpha Corporation',
  tenant_slug: 'alpha',
  membership_id: 'membership-alpha',
  authentication_level: 'password',
  session_expires_at: '2026-08-12T12:00:00Z',
  mfa_required: true,
  mfa_enrolled: true,
  fully_authenticated: false,
}

describe('MFAChallengePage', () => {
  it('shows an invalid TOTP error with a collapsed error reference', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          error: 'invalid authentication code',
          request_id: 'req-mfa-error',
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

    const queryClient = createTestQueryClient()
    queryClient.setQueryData(currentUserQueryKey, passwordSession)

    const { user } = renderWithProviders(<MFAChallengePage />, {
      route: '/mfa/challenge',
      queryClient,
    })

    await user.type(screen.getByLabelText('Six-digit code'), '123456')

    await user.click(
      screen.getByRole('button', {
        name: 'Verify and continue',
      }),
    )

    expect(await screen.findByText('invalid authentication code')).toBeInTheDocument()

    const errorReference = screen.getByText('Error reference').closest('details')

    expect(errorReference).not.toBeNull()
    expect(errorReference).not.toHaveAttribute('open')

    expect(within(errorReference!).getByText('Request ID: req-mfa-error')).toBeInTheDocument()

    expect(fetchMock).toHaveBeenCalledWith(
      '/api/v1/auth/mfa/challenge/totp',
      expect.objectContaining({
        method: 'POST',
        credentials: 'include',
      }),
    )
  })
})
