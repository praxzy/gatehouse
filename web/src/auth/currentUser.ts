import { queryOptions, useQuery } from '@tanstack/react-query'
import { getCurrentUser } from '@/api/auth'

export const currentUserQueryKey = ['auth', 'current-user'] as const

export function currentUserQueryOptions() {
  return queryOptions({
    queryKey: currentUserQueryKey,
    queryFn: ({ signal }) => getCurrentUser(signal),
    retry: false,
    staleTime: 15_000,
  })
}

export function useCurrentUser() {
  return useQuery(currentUserQueryOptions())
}
