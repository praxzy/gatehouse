import { screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { Route, Routes } from 'react-router-dom'
import type { CurrentUser } from '@/api/auth'
import { RequireFullyAuthenticated, RequirePermission, PublicOnlyRoute } from './routeGuards'
import { renderWithProviders } from '@/test/render'
import { permissions } from '@/auth/permissions'

const authenticatedUser: CurrentUser = {
  user_id: 'user-alpha',
  email: 'owner@alpha.test',
  display_name: 'Alpha Owner',
  tenant_id: 'tenant-alpha',
  tenant_name: 'Alpha Corporation',
  tenant_slug: 'alpha',
  membership_id: 'membership-alpha',
  authentication_level: 'mfa',
  session_expires_at: '2026-08-12T12:00:00Z',
  mfa_required: true,
  mfa_enrolled: true,
  fully_authenticated: true,
  permissions: [],
  capabilities: { manage_members: false },
}

describe('PublicOnlyRoute', () => {
  it('continues an existing SSO session to the requested authorization transaction', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(authenticatedUser), {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
        },
      }),
    )

    vi.stubGlobal('fetch', fetchMock)

    const returnTo =
      '/oauth/authorize/continue?transaction_id=transaction-123&state=state-0123456789'
    const browserNavigate = vi.fn()

    renderWithProviders(
      <Routes>
        <Route element={<PublicOnlyRoute browserNavigate={browserNavigate} />}>
          <Route path="/login" element={<p>Login page</p>} />
        </Route>
      </Routes>,
      {
        route: `/login?return_to=${encodeURIComponent(returnTo)}`,
      },
    )

    await waitFor(() => {
      expect(browserNavigate).toHaveBeenCalledWith(returnTo)
    })
    expect(screen.queryByText('Login page')).not.toBeInTheDocument()
  })

  it('allows forced login when switching authorization tenants', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(authenticatedUser), {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
        },
      }),
    )

    vi.stubGlobal('fetch', fetchMock)

    const returnTo =
      '/oauth/authorize/continue?transaction_id=transaction-456&state=state-9876543210'
    const browserNavigate = vi.fn()

    renderWithProviders(
      <Routes>
        <Route element={<PublicOnlyRoute browserNavigate={browserNavigate} />}>
          <Route path="/login" element={<p>Login page</p>} />
        </Route>
      </Routes>,
      {
        route: `/login?force=1&tenant_slug=beta&return_to=` + encodeURIComponent(returnTo),
      },
    )

    expect(await screen.findByText('Login page')).toBeInTheDocument()
    expect(browserNavigate).not.toHaveBeenCalled()
  })
})

describe('RequireFullyAuthenticated', () => {
  it('waits for current-user bootstrap before deciding where to navigate', async () => {
    let resolveCurrentUser: ((response: Response) => void) | undefined

    const pendingResponse = new Promise<Response>((resolve) => {
      resolveCurrentUser = resolve
    })

    const fetchMock = vi.fn().mockReturnValue(pendingResponse)

    vi.stubGlobal('fetch', fetchMock)

    renderWithProviders(
      <Routes>
        <Route element={<RequireFullyAuthenticated />}>
          <Route path="/app" element={<p>Administration console</p>} />
        </Route>

        <Route path="/login" element={<p>Login page</p>} />
      </Routes>,
      {
        route: '/app',
      },
    )

    expect(screen.getByText('Checking your session…')).toBeInTheDocument()

    expect(screen.queryByText('Administration console')).not.toBeInTheDocument()

    expect(screen.queryByText('Login page')).not.toBeInTheDocument()

    resolveCurrentUser?.(
      new Response(JSON.stringify(authenticatedUser), {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
        },
      }),
    )

    expect(await screen.findByText('Administration console')).toBeInTheDocument()

    expect(screen.queryByText('Login page')).not.toBeInTheDocument()
  })

  it('offers a retry when the current-user service is unavailable', async () => {
    const fetchMock = vi
      .fn()
      .mockRejectedValueOnce(new TypeError('fetch failed'))
      .mockRejectedValueOnce(new TypeError('fetch failed'))
      .mockRejectedValueOnce(new TypeError('fetch failed'))
      .mockResolvedValueOnce(
        new Response(JSON.stringify(authenticatedUser), {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
          },
        }),
      )

    vi.stubGlobal('fetch', fetchMock)

    const { user } = renderWithProviders(
      <Routes>
        <Route element={<RequireFullyAuthenticated />}>
          <Route path="/app" element={<p>Administration console</p>} />
        </Route>
      </Routes>,
      {
        route: '/app',
      },
    )

    expect(
      await screen.findByRole(
        'heading',
        {
          name: 'Gatehouse is temporarily unavailable',
        },
        {
          timeout: 3_000,
        },
      ),
    ).toBeInTheDocument()

    expect(fetchMock).toHaveBeenCalledTimes(3)

    await user.click(screen.getByRole('button', { name: 'Try again' }))

    expect(await screen.findByText('Administration console')).toBeInTheDocument()
    expect(fetchMock).toHaveBeenCalledTimes(4)
  })
})

describe('RequirePermission', () => {
  it('redirects users without member-management capability', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(authenticatedUser), {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
        },
      }),
    )

    vi.stubGlobal('fetch', fetchMock)

    renderWithProviders(
      <Routes>
        <Route element={<RequirePermission permission={permissions.memberRead} />}>
          <Route path="/app/members" element={<p>Member directory</p>} />
        </Route>

        <Route path="/app" element={<p>Overview page</p>} />
      </Routes>,
      {
        route: '/app/members',
      },
    )

    expect(await screen.findByText('Overview page')).toBeInTheDocument()

    expect(screen.queryByText('Member directory')).not.toBeInTheDocument()
  })

  it('allows users with member-management capability', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          ...authenticatedUser,
          permissions: [permissions.memberRead],
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

    renderWithProviders(
      <Routes>
        <Route element={<RequirePermission permission={permissions.memberRead} />}>
          <Route path="/app/members" element={<p>Member directory</p>} />
        </Route>

        <Route path="/app" element={<p>Overview page</p>} />
      </Routes>,
      {
        route: '/app/members',
      },
    )

    expect(await screen.findByText('Member directory')).toBeInTheDocument()

    expect(screen.queryByText('Overview page')).not.toBeInTheDocument()
  })
})
