import { queryOptions, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  createApplication,
  getApplication,
  getApplications,
  type CreateApplicationInput,
} from '@/api/applications'

export const applicationsQueryKey = ['applications'] as const

export function applicationQueryKey(applicationId: string) {
  return [...applicationsQueryKey, applicationId] as const
}

export function applicationsQueryOptions() {
  return queryOptions({
    queryKey: applicationsQueryKey,
    queryFn: ({ signal }) => getApplications(signal),
    staleTime: 10_000,
  })
}

export function applicationQueryOptions(applicationId: string) {
  return queryOptions({
    queryKey: applicationQueryKey(applicationId),
    queryFn: ({ signal }) => getApplication(applicationId, signal),
    staleTime: 10_000,
    enabled: applicationId !== '',
  })
}

export function useApplications() {
  return useQuery(applicationsQueryOptions())
}

export function useApplication(applicationId: string) {
  return useQuery(applicationQueryOptions(applicationId))
}

export function useCreateApplication() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (input: CreateApplicationInput) => createApplication(input),
    onSuccess: async (result) => {
      queryClient.setQueryData(
        applicationQueryKey(result.application.application_id),
        result.application,
      )

      await queryClient.invalidateQueries({
        queryKey: applicationsQueryKey,
      })
    },
  })
}
