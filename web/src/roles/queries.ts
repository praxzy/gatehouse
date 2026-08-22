import { queryOptions, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { createRole, getRoles, updateRole, type RoleWriteInput } from '@/api/roles'
import { currentUserQueryKey } from '@/auth/currentUser'
import { membersQueryKey } from '@/members/queries'

export const rolesQueryKey = ['roles'] as const

export function rolesQueryOptions(enabled = true) {
  return queryOptions({
    queryKey: rolesQueryKey,
    queryFn: ({ signal }) => getRoles(signal),
    staleTime: 10_000,
    enabled,
  })
}

export function useRoles(enabled = true) {
  return useQuery(rolesQueryOptions(enabled))
}

export function useCreateRole() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (input: RoleWriteInput) => createRole(input),
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({
          queryKey: rolesQueryKey,
        }),
        queryClient.invalidateQueries({
          queryKey: membersQueryKey,
        }),
      ])
    },
  })
}

export function useUpdateRole() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ roleId, input }: { roleId: string; input: RoleWriteInput }) =>
      updateRole(roleId, input),

    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({
          queryKey: rolesQueryKey,
        }),
        queryClient.invalidateQueries({
          queryKey: membersQueryKey,
        }),
        queryClient.invalidateQueries({
          queryKey: currentUserQueryKey,
        }),
      ])
    },
  })
}
