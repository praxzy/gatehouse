import { screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import type { CurrentUser } from '@/api/auth'
import { currentUserQueryKey } from '@/auth/currentUser'
import { createTestQueryClient, renderWithProviders } from '@/test/render'
import { MFAEnrollmentPage } from './MFAEnrollmentPage'

const passwordSession: CurrentUser = {
  user_id: 'user-alpha',
  email: 'owner@alpha.test',
  display_name: 'Alpha Owner',
  tenant_id: 'tenant-alpha',
  tenant_name: 'Alpha Corporation',
  tenant_slug: 'alpha',
  membership_id: 'membership-alpha',
  authentication_level: 'password',
  session_expires_at: '2099-08-17T12:00:00Z',
  mfa_required: true,
  mfa_enrolled: false,
  fully_authenticated: false,
  capabilities: { manage_members: false },
}

describe('MFAEnrollmentPage', () => {
  it('hides an expired setup key and generates a fresh one', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        enrollmentResponse({
          provisioning_uri: 'otpauth://totp/Gatehouse:expired',
          manual_key: 'EXPIREDKEY',
          expires_at: '2000-01-01T00:00:00Z',
        }),
      )
      .mockResolvedValueOnce(
        enrollmentResponse({
          provisioning_uri: 'otpauth://totp/Gatehouse:fresh',
          manual_key: 'FRESHKEY',
          expires_at: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
        }),
      )

    vi.stubGlobal('fetch', fetchMock)

    const queryClient = createTestQueryClient()
    queryClient.setQueryData(currentUserQueryKey, passwordSession)

    const { user } = renderWithProviders(<MFAEnrollmentPage />, {
      route: '/mfa/enroll',
      queryClient,
    })

    await user.click(
      screen.getByRole('button', {
        name: 'Start authenticator setup',
      }),
    )

    expect(await screen.findByText('Setup key expired')).toBeInTheDocument()
    expect(screen.queryByText('EXPIREDKEY')).not.toBeInTheDocument()
    expect(screen.queryByTitle('Gatehouse authenticator QR code')).not.toBeInTheDocument()

    await user.click(
      screen.getByRole('button', {
        name: 'Generate new setup key',
      }),
    )

    expect(await screen.findByText('FRESHKEY')).toBeInTheDocument()
    expect(screen.getByTitle('Gatehouse authenticator QR code')).toBeInTheDocument()
    expect(screen.queryByText('Setup key expired')).not.toBeInTheDocument()

    expect(fetchMock).toHaveBeenCalledTimes(2)
  })
})

function enrollmentResponse(body: {
  provisioning_uri: string
  manual_key: string
  expires_at: string
}) {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
    },
  })
}
