import { screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { Route, Routes } from 'react-router-dom'
import type { CurrentUser } from '@/api/auth'
import { RequireFullyAuthenticated } from './routeGuards'
import { renderWithProviders } from '@/test/render'

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
}

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
})
