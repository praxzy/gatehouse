import { useState } from 'react'
import type { AuditEvent, AuditOutcome } from '@/api/audit'
import { useAuditEvents } from '@/audit/queries'
import type { AuditEventQueryFilters } from '@/audit/queries'
import { RequestError } from '@/components/RequestError'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Spinner } from '@/components/ui/spinner'
import { Surface } from '@/components/ui/surface'

type FilterForm = {
  actor: string
  application: string
  eventType: string
  outcome: '' | AuditOutcome
  from: string
  until: string
}

const emptyForm: FilterForm = {
  actor: '',
  application: '',
  eventType: '',
  outcome: '',
  from: '',
  until: '',
}

export function AuditPage() {
  const [form, setForm] = useState<FilterForm>(emptyForm)
  const [filters, setFilters] = useState<AuditEventQueryFilters>({
    page_size: 25,
  })
  const audit = useAuditEvents(filters)
  const events = audit.data?.pages.flatMap((page) => page.events) ?? []

  function applyFilters() {
    setFilters({
      actor_user_id: form.actor.trim() || undefined,
      application_id: form.application.trim() || undefined,
      event_type: form.eventType.trim() || undefined,
      outcome: form.outcome || undefined,
      from: form.from ? new Date(form.from).toISOString() : undefined,
      until: form.until ? new Date(form.until).toISOString() : undefined,
      page_size: 25,
    })
  }

  function clearFilters() {
    setForm(emptyForm)
    setFilters({ page_size: 25 })
  }

  return (
    <div className="mx-auto w-full max-w-376 px-5 py-7 sm:px-7 lg:px-10 lg:py-9">
      <header className="motion-enter">
        <p className="font-mono text-[0.67rem] tracking-[0.14em] text-muted-foreground uppercase">
          Activity
        </p>
        <h1 className="mt-2 font-heading text-4xl font-medium tracking-[-0.035em]">Audit events</h1>
        <p className="mt-3 text-sm text-muted-foreground">
          Identity and access activity for this organization.
        </p>
      </header>

      <Surface className="motion-enter motion-enter-delay-1 mt-8 p-5">
        <form
          onSubmit={(event) => {
            event.preventDefault()
            applyFilters()
          }}
        >
          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
            <FilterInput
              id="audit-actor"
              label="Actor user ID"
              value={form.actor}
              placeholder="User UUID"
              onChange={(actor) => setForm((current) => ({ ...current, actor }))}
            />
            <FilterInput
              id="audit-application"
              label="Application ID"
              value={form.application}
              placeholder="Application UUID"
              onChange={(application) => setForm((current) => ({ ...current, application }))}
            />
            <FilterInput
              id="audit-event-type"
              label="Event type"
              value={form.eventType}
              placeholder="e.g. auth.login"
              onChange={(eventType) => setForm((current) => ({ ...current, eventType }))}
            />

            <label className="grid gap-2 text-sm font-medium">
              Outcome
              <select
                className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm"
                value={form.outcome}
                onChange={(event) =>
                  setForm((current) => ({
                    ...current,
                    outcome: event.target.value as FilterForm['outcome'],
                  }))
                }
              >
                <option value="">All outcomes</option>
                <option value="success">Success</option>
                <option value="failure">Failure</option>
                <option value="denied">Denied</option>
              </select>
            </label>

            <FilterInput
              id="audit-from"
              label="From"
              type="datetime-local"
              value={form.from}
              onChange={(from) => setForm((current) => ({ ...current, from }))}
            />
            <FilterInput
              id="audit-until"
              label="Until"
              type="datetime-local"
              value={form.until}
              onChange={(until) => setForm((current) => ({ ...current, until }))}
            />
          </div>

          <div className="mt-5 flex flex-wrap gap-2">
            <Button type="submit">Apply filters</Button>
            <Button type="button" variant="outline" onClick={clearFilters}>
              Clear
            </Button>
          </div>
        </form>
      </Surface>

      <div className="mt-6">
        {audit.isPending ? (
          <div
            className="motion-enter motion-enter-delay-2 flex min-h-64 items-center justify-center gap-3 text-sm text-muted-foreground"
            aria-live="polite"
          >
            <Spinner />
            Loading audit events
          </div>
        ) : audit.isError ? (
          <Surface className="motion-enter motion-enter-delay-2 p-6">
            <h2 className="font-heading text-2xl">Audit events couldn’t be loaded</h2>
            <div className="mt-4">
              <RequestError error={audit.error} />
            </div>
            <Button
              type="button"
              variant="outline"
              className="mt-5"
              onClick={() => audit.refetch()}
            >
              Try again
            </Button>
          </Surface>
        ) : events.length === 0 ? (
          <Surface className="motion-enter motion-enter-delay-2 p-8 text-center">
            <h2 className="font-heading text-2xl">No matching events</h2>
            <p className="mt-2 text-sm text-muted-foreground">
              Try adjusting the filters or check back later.
            </p>
          </Surface>
        ) : (
          <div className="motion-enter motion-enter-delay-2">
            <div className="space-y-3">
              {events.map((event) => (
                <AuditEventRow key={event.event_id} event={event} />
              ))}
            </div>

            {audit.hasNextPage && (
              <div className="mt-6 flex justify-center">
                <Button
                  type="button"
                  variant="outline"
                  disabled={audit.isFetchingNextPage}
                  onClick={() => audit.fetchNextPage()}
                >
                  {audit.isFetchingNextPage ? 'Loading…' : 'Load more'}
                </Button>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

function FilterInput({
  id,
  label,
  value,
  onChange,
  type = 'text',
  placeholder,
}: {
  id: string
  label: string
  value: string
  onChange: (value: string) => void
  type?: string
  placeholder?: string
}) {
  return (
    <label htmlFor={id} className="grid gap-2 text-sm font-medium">
      {label}
      <Input
        id={id}
        type={type}
        value={value}
        placeholder={placeholder}
        onChange={(event) => onChange(event.target.value)}
      />
    </label>
  )
}

function AuditEventRow({ event }: { event: AuditEvent }) {
  const actor =
    event.actor_display_name || event.actor_email || event.actor_user_id || event.actor_kind

  return (
    <Surface className="p-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h2 className="text-sm font-semibold">{event.event_type}</h2>
          <p className="mt-1 text-sm text-muted-foreground">
            {actor}
            {event.application_name ? ` · ${event.application_name}` : ''}
          </p>
        </div>
        <span className="rounded-full border border-border px-2.5 py-1 text-xs font-medium capitalize">
          {event.outcome}
        </span>
      </div>

      <div className="mt-4 flex flex-wrap gap-x-5 gap-y-1 text-xs text-muted-foreground">
        <time dateTime={event.occurred_at}>{new Date(event.occurred_at).toLocaleString()}</time>
        {event.request_id && <span>Request ID: {event.request_id}</span>}
      </div>

      {Object.keys(event.metadata).length > 0 && (
        <details className="mt-4 border-t border-border pt-3 text-xs">
          <summary className="cursor-pointer text-muted-foreground">Event details</summary>
          <pre className="mt-3 overflow-x-auto break-all whitespace-pre-wrap">
            {JSON.stringify(event.metadata, null, 2)}
          </pre>
        </details>
      )}
    </Surface>
  )
}
