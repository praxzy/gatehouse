import { apiRequest } from './client'

export type PermissionCatalogEntry = {
  permission: string
  name: string
  description: string
}

export type Role = {
  role_id: string
  role_key?: string
  name: string
  description: string
  is_system: boolean
  permissions: string[]
}

export type RoleListResponse = {
  permissions: PermissionCatalogEntry[]
  roles: Role[]
}

export type RoleWriteInput = {
  name: string
  description: string
  permissions: string[]
}

export function getRoles(signal?: AbortSignal) {
  return apiRequest<RoleListResponse>('/roles', {
    signal,
  })
}

export function createRole(input: RoleWriteInput) {
  return apiRequest<Role>('/roles', {
    method: 'POST',
    body: input,
  })
}

export function updateRole(roleId: string, input: RoleWriteInput) {
  return apiRequest<Role>(`/roles/${encodeURIComponent(roleId)}`, {
    method: 'PUT',
    body: input,
  })
}
