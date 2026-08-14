import { queryOptions, useQuery } from '@tanstack/react-query'
import { getCurrentUser } from '@/api/auth'
import { isServiceUnavailableError } from '@/api/client'

export const currentUserQueryKey = ['auth', 'current-user'] as const

export function currentUserQueryOptions() {
  return queryOptions({
    queryKey: currentUserQueryKey,
    queryFn: ({ signal }) => getCurrentUser(signal),
    retry: shouldRetryCurrentUserRequest,
    retryDelay: (attemptIndex) => Math.min(400 * 2 ** attemptIndex, 1_500),
    staleTime: 15_000,
  })
}

export function shouldRetryCurrentUserRequest(failureCount: number, error: unknown) {
  return failureCount < 2 && isServiceUnavailableError(error)
}

export function useCurrentUser() {
  return useQuery(currentUserQueryOptions())
}
