import { apiRequest } from '@/api/client'

export type ApplicationClientType = 'public' | 'confidential'

export type ApplicationAccessMode = 'all_active_members' | 'allowed_roles'

export type ApplicationSummary = {
  application_id: string
  name: string
  description: string
  client_id: string
  client_type: ApplicationClientType
  status: string
  access_mode: ApplicationAccessMode
  redirect_uri_count: number
  allowed_role_count: number
  created_at: string
  updated_at: string
}

export type ApplicationRedirectURI = {
  redirect_uri_id: string
  uri: string
  created_at: string
}

export type ApplicationAccessRole = {
  role_id: string
  role_key?: string
  name: string
  is_system: boolean
}

export type ApplicationDetail = {
  application_id: string
  name: string
  description: string
  client_id: string
  client_type: ApplicationClientType
  status: string
  access_mode: ApplicationAccessMode
  created_at: string
  updated_at: string
  redirect_uris: ApplicationRedirectURI[]
  allowed_roles: ApplicationAccessRole[]
}

export type ApplicationListResponse = {
  applications: ApplicationSummary[]
}

export type CreateApplicationInput = {
  name: string
  description: string
  client_type: ApplicationClientType
  redirect_uris: string[]
  access_mode: ApplicationAccessMode
  allowed_role_ids: string[]
}

export type CreateApplicationResponse = {
  application: ApplicationDetail
  client_secret?: string
}

export function getApplications(signal?: AbortSignal) {
  return apiRequest<ApplicationListResponse>('/applications', {
    signal,
  })
}

export function getApplication(applicationId: string, signal?: AbortSignal) {
  return apiRequest<ApplicationDetail>(`/applications/${encodeURIComponent(applicationId)}`, {
    signal,
  })
}

export function createApplication(input: CreateApplicationInput) {
  return apiRequest<CreateApplicationResponse>('/applications', {
    method: 'POST',
    body: input,
  })
}
