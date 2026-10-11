import { queryOptions, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  createApplication,
  getApplication,
  getApplications,
  updateApplicationAccessPolicy,
  type ApplicationDetail,
  type CreateApplicationInput,
  type UpdateApplicationAccessPolicyInput,
} from '@/api/applications'

export const applicationsQueryKey = ['applications'] as const

export function applicationQueryKey(applicationId: string) {
  return [...applicationsQueryKey, applicationId] as const
}

export function applicationsQueryOptions(enabled = true) {
  return queryOptions({
    queryKey: applicationsQueryKey,
    queryFn: ({ signal }) => getApplications(signal),
    staleTime: 10_000,
    enabled,
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

export function useApplications(enabled = true) {
  return useQuery(applicationsQueryOptions(enabled))
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

export function useUpdateApplicationAccessPolicy(applicationId: string) {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (input: UpdateApplicationAccessPolicyInput) =>
      updateApplicationAccessPolicy(applicationId, input),

    onSuccess: async (policy) => {
      queryClient.setQueryData<ApplicationDetail>(applicationQueryKey(applicationId), (current) =>
        current
          ? {
              ...current,
              access_mode: policy.access_mode,
              allowed_roles: policy.allowed_roles,
              updated_at: policy.updated_at,
            }
          : current,
      )

      await queryClient.invalidateQueries({
        queryKey: applicationsQueryKey,
      })
    },
  })
}
