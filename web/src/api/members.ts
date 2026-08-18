import { apiRequest } from './client'

export type MembershipStatus = 'active' | 'disabled'

export type Member = {
  membership_id: string
  user_id: string
  email: string
  display_name: string
  status: MembershipStatus
  role_id: string
  role_key: string
  role_name: string
  created_at: string
  updated_at: string
}

export type OpenMembershipInvitation = {
  invitation_id: string
  email: string
  role_id: string
  role_name: string
  created_at: string
  expires_at: string
  expired: boolean
}

export type MembershipRole = {
  role_id: string
  role_key: string
  role_name: string
}

export type MemberListResponse = {
  members: Member[]
  invitations: OpenMembershipInvitation[]
  roles: MembershipRole[]
}

export type InviteMemberInput = {
  email: string
  role_id: string
}

export type InviteMemberResponse = {
  invitation_id: string
  email: string
  role_id: string
  role_name: string
  expires_at: string
}

export type UpdateMemberInput = {
  role_id?: string
  status?: MembershipStatus
}

export type MembershipInvitationPreview = {
  tenant_name: string
  tenant_slug: string
  email: string
  role_name: string
  expires_at: string
  account_setup_required: boolean
}

export type AcceptMembershipInvitationInput = {
  token: string
  display_name?: string
  password?: string
}

export type AcceptMembershipInvitationResponse = {
  tenant_id: string
  membership_id: string
  user_id: string
  email: string
}

export function getMembers(signal?: AbortSignal) {
  return apiRequest<MemberListResponse>('/members', {
    signal,
  })
}

export function inviteMember(input: InviteMemberInput) {
  return apiRequest<InviteMemberResponse>('/members', {
    method: 'POST',
    body: input,
  })
}

export function updateMember(membershipId: string, input: UpdateMemberInput) {
  return apiRequest<void>(`/members/${encodeURIComponent(membershipId)}`, {
    method: 'PATCH',
    body: input,
  })
}

export function previewMembershipInvitation(token: string) {
  return apiRequest<MembershipInvitationPreview>('/invitations/preview', {
    method: 'POST',
    body: { token },
  })
}

export function acceptMembershipInvitation(input: AcceptMembershipInvitationInput) {
  return apiRequest<AcceptMembershipInvitationResponse>('/invitations/accept', {
    method: 'POST',
    body: input,
  })
}
