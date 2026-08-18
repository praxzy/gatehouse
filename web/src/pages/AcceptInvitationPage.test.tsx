import { screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { AcceptInvitationPage } from './AcceptInvitationPage'
import { renderWithProviders } from '@/test/render'

describe('AcceptInvitationPage', () => {
  it('creates an account when the invited email is new', async () => {
    window.history.replaceState(
      window.history.state,
      '',
      '/accept-invitation#token=new-user-invitation',
    )

    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            tenant_name: 'Alpha Labs',
            tenant_slug: 'alpha-labs',
            email: 'new.member@alpha.test',
            role_name: 'Member',
            expires_at: '2026-08-19T12:00:00Z',
            account_setup_required: true,
          }),
          {
            status: 200,
            headers: {
              'Content-Type': 'application/json',
            },
          },
        ),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            tenant_id: 'tenant-alpha',
            membership_id: 'membership-new-member',
            user_id: 'user-new-member',
            email: 'new.member@alpha.test',
          }),
          {
            status: 200,
            headers: {
              'Content-Type': 'application/json',
            },
          },
        ),
      )

    vi.stubGlobal('fetch', fetchMock)

    const { user } = renderWithProviders(<AcceptInvitationPage />, {
      route: '/accept-invitation',
    })

    expect(
      await screen.findByRole('heading', {
        name: 'Join Alpha Labs',
      }),
    ).toBeInTheDocument()

    expect(window.location.hash).toBe('')

    await user.type(screen.getByLabelText('Your name'), 'New Member')
    await user.type(screen.getByLabelText('Create password'), 'correct horse battery staple')
    await user.type(screen.getByLabelText('Confirm password'), 'correct horse battery staple')

    await user.click(
      screen.getByRole('button', {
        name: 'Accept invitation',
      }),
    )

    expect(
      await screen.findByRole('heading', {
        name: 'You’ve joined Alpha Labs',
      }),
    ).toBeInTheDocument()

    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      '/api/v1/invitations/preview',
      expect.objectContaining({
        method: 'POST',
        credentials: 'include',
        body: JSON.stringify({
          token: 'new-user-invitation',
        }),
      }),
    )

    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      '/api/v1/invitations/accept',
      expect.objectContaining({
        method: 'POST',
        credentials: 'include',
        body: JSON.stringify({
          token: 'new-user-invitation',
          display_name: 'New Member',
          password: 'correct horse battery staple',
        }),
      }),
    )

    expect(
      screen.getByRole('link', {
        name: 'Continue to sign in',
      }),
    ).toHaveAttribute('href', '/login?tenant=alpha-labs')
  })

  it('does not request another password for an existing account', async () => {
    window.history.replaceState(
      window.history.state,
      '',
      '/accept-invitation#token=existing-user-invitation',
    )

    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            tenant_name: 'Beta Works',
            tenant_slug: 'beta-works',
            email: 'existing@beta.test',
            role_name: 'Member',
            expires_at: '2026-08-19T12:00:00Z',
            account_setup_required: false,
          }),
          {
            status: 200,
            headers: {
              'Content-Type': 'application/json',
            },
          },
        ),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            tenant_id: 'tenant-beta',
            membership_id: 'membership-existing',
            user_id: 'user-existing',
            email: 'existing@beta.test',
          }),
          {
            status: 200,
            headers: {
              'Content-Type': 'application/json',
            },
          },
        ),
      )

    vi.stubGlobal('fetch', fetchMock)

    const { user } = renderWithProviders(<AcceptInvitationPage />, {
      route: '/accept-invitation',
    })

    expect(
      await screen.findByRole('heading', {
        name: 'Join Beta Works',
      }),
    ).toBeInTheDocument()

    expect(screen.queryByLabelText('Create password')).not.toBeInTheDocument()

    await user.click(
      screen.getByRole('button', {
        name: 'Accept invitation',
      }),
    )

    expect(
      await screen.findByRole('heading', {
        name: 'You’ve joined Beta Works',
      }),
    ).toBeInTheDocument()

    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      '/api/v1/invitations/accept',
      expect.objectContaining({
        method: 'POST',
        credentials: 'include',
        body: JSON.stringify({
          token: 'existing-user-invitation',
        }),
      }),
    )
  })
})
