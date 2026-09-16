import { apiRequest } from '@/api/client'

export type AuditOutcome = 'success' | 'failure' | 'denied'

export type AuditEvent = {
  event_id: string
  actor_kind: string
  actor_user_id?: string
  actor_membership_id?: string
  actor_email?: string
  actor_display_name?: string
  application_id?: string
  application_name?: string
  session_id?: string
  event_type: string
  outcome: AuditOutcome
  subject_type?: string
  subject_id?: string
  request_id?: string
  source_ip?: string
  user_agent?: string
  metadata: Record<string, unknown>
  occurred_at: string
}

export type AuditEventListResponse = {
  events: AuditEvent[]
  next_cursor?: string
}

export type AuditEventFilters = {
  actor_user_id?: string
  application_id?: string
  event_type?: string
  outcome?: AuditOutcome
  from?: string
  until?: string
  cursor?: string
  page_size?: number
}

export function getAuditEvents(filters: AuditEventFilters, signal?: AbortSignal) {
  const parameters = new URLSearchParams()

  for (const [key, value] of Object.entries(filters)) {
    if (value !== undefined && value !== '') {
      parameters.set(key, String(value))
    }
  }

  const query = parameters.toString()

  return apiRequest<AuditEventListResponse>(`/audit-events${query === '' ? '' : `?${query}`}`, {
    signal,
  })
}
