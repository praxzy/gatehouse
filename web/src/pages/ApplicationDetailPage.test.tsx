import { screen } from '@testing-library/react'
import { Route, Routes } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'
import { ApplicationDetailPage } from '@/pages/ApplicationDetailPage'
import { renderWithProviders } from '@/test/render'

describe('ApplicationDetailPage', () => {
  it('shows configuration without exposing a client secret', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        jsonResponse({
          application_id: 'application-1',
          name: 'Employee Portal',
          description: 'Internal employee application',
          client_id: 'ghc_test_client',
          client_type: 'confidential',
          status: 'active',
          access_mode: 'all_active_members',
          created_at: '2026-08-22T08:00:00Z',
          updated_at: '2026-08-22T08:00:00Z',
          redirect_uris: [
            {
              redirect_uri_id: 'redirect-1',
              uri: 'https://portal.example.test/callback',
              created_at: '2026-08-22T08:00:00Z',
            },
          ],
          allowed_roles: [],
        }),
      ),
    )

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
})

function jsonResponse(body: unknown) {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
    },
  })
}
