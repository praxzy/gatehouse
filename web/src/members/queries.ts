import { queryOptions, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  getMembers,
  inviteMember,
  updateMember,
  type InviteMemberInput,
  type UpdateMemberInput,
} from '@/api/members'
import { currentUserQueryKey } from '@/auth/currentUser'

export const membersQueryKey = ['members'] as const

export function membersQueryOptions(enabled = true) {
  return queryOptions({
    queryKey: membersQueryKey,
    queryFn: ({ signal }) => getMembers(signal),
    staleTime: 10_000,
    enabled,
  })
}

export function useMembers(enabled = true) {
  return useQuery(membersQueryOptions(enabled))
}

export function useInviteMember() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (input: InviteMemberInput) => inviteMember(input),
    onSuccess: async () => {
      await queryClient.invalidateQueries({
        queryKey: membersQueryKey,
      })
    },
  })
}

export function useUpdateMember() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ membershipId, input }: { membershipId: string; input: UpdateMemberInput }) =>
      updateMember(membershipId, input),
    onSuccess: async () => {
      await Promise.all([
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
