import { screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { AuditPage } from '@/pages/AuditPage'
import { renderWithProviders } from '@/test/render'

const event = (id: string, eventType: string, outcome = 'success') => ({
  event_id: id,
  actor_kind: 'user',
  actor_user_id: '11111111-1111-4111-8111-111111111111',
  actor_display_name: 'Alice',
  event_type: eventType,
  outcome,
  metadata: {},
  occurred_at: '2026-09-16T10:00:00Z',
})

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

describe('AuditPage', () => {
  it('applies filters only after submission', async () => {
    const requestedURLs: URL[] = []

    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        const path =
          typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
        const url = new URL(path, 'http://localhost')
        requestedURLs.push(url)

        if (url.searchParams.get('event_type') === 'auth.login') {
          return jsonResponse({
            events: [event('filtered', 'auth.login', 'failure')],
          })
        }

        return jsonResponse({
          events: [event('initial', 'session.created')],
        })
      }),
    )

    const { user } = renderWithProviders(<AuditPage />)

    expect(await screen.findByRole('heading', { name: 'session.created' })).toBeInTheDocument()

    await user.type(screen.getByRole('textbox', { name: 'Event type' }), 'auth.login')
    await user.selectOptions(screen.getByRole('combobox', { name: 'Outcome' }), 'failure')

    expect(requestedURLs).toHaveLength(1)

    await user.click(screen.getByRole('button', { name: 'Apply filters' }))

    expect(await screen.findByRole('heading', { name: 'auth.login' })).toBeInTheDocument()

    await waitFor(() => {
      const filtered = requestedURLs.at(-1)
      expect(filtered?.searchParams.get('event_type')).toBe('auth.login')
      expect(filtered?.searchParams.get('outcome')).toBe('failure')
      expect(filtered?.searchParams.get('page_size')).toBe('25')
    })
  })

  it('loads the next cursor page without losing earlier events', async () => {
    const requestedURLs: URL[] = []

    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        const path =
          typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
        const url = new URL(path, 'http://localhost')
        requestedURLs.push(url)

        if (url.searchParams.get('cursor') === 'next-page') {
          return jsonResponse({
            events: [event('second', 'session.revoked')],
          })
        }

        return jsonResponse({
          events: [event('first', 'session.created')],
          next_cursor: 'next-page',
        })
      }),
    )

    const { user } = renderWithProviders(<AuditPage />)

    expect(await screen.findByRole('heading', { name: 'session.created' })).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Load more' }))

    expect(await screen.findByRole('heading', { name: 'session.revoked' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'session.created' })).toBeInTheDocument()
    expect(requestedURLs.at(-1)?.searchParams.get('cursor')).toBe('next-page')
    expect(screen.queryByRole('button', { name: 'Load more' })).not.toBeInTheDocument()
  })

  it('shows an API error with a retry action', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        jsonResponse({ error: 'Audit service unavailable', request_id: 'audit-request-1' }, 503),
      )
      .mockResolvedValueOnce(jsonResponse({ events: [] }))

    vi.stubGlobal('fetch', fetchMock)

    const { user } = renderWithProviders(<AuditPage />)

    expect(
      await screen.findByRole('heading', { name: 'Audit events couldn’t be loaded' }),
    ).toBeInTheDocument()
    expect(screen.getByText('Audit service unavailable')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Try again' }))

    expect(await screen.findByRole('heading', { name: 'No matching events' })).toBeInTheDocument()
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })
})
