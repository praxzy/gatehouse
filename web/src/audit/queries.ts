import { infiniteQueryOptions, useInfiniteQuery, useQuery } from '@tanstack/react-query'
import { getAuditEvents, type AuditEventFilters } from '@/api/audit'

export const auditEventsQueryKey = ['audit-events'] as const

export type AuditEventQueryFilters = Omit<AuditEventFilters, 'cursor'>

export function auditEventsQueryOptions(filters: AuditEventQueryFilters) {
  return infiniteQueryOptions({
    queryKey: [...auditEventsQueryKey, filters],
    queryFn: ({ pageParam, signal }) =>
      getAuditEvents(
        {
          ...filters,
          cursor: pageParam || undefined,
        },
        signal,
      ),
    initialPageParam: '',
    getNextPageParam: (page) => page.next_cursor || undefined,
    staleTime: 5_000,
  })
}

export function useAuditEvents(filters: AuditEventQueryFilters) {
  return useInfiniteQuery(auditEventsQueryOptions(filters))
}

export function useRecentAuditEvents(enabled: boolean) {
  return useQuery({
    queryKey: [...auditEventsQueryKey, 'recent'],
    queryFn: ({ signal }) => getAuditEvents({ page_size: 3 }, signal),
    enabled,
    staleTime: 10_000,
  })
}
