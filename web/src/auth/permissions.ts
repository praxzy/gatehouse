export const permissions = {
  tenantRead: 'tenant.read',
  memberRead: 'member.read',
  memberManage: 'member.manage',
  roleRead: 'role.read',
  roleManage: 'role.manage',
  applicationRead: 'application.read',
  applicationManage: 'application.manage',
  auditRead: 'audit.read',
} as const

export type Permission = (typeof permissions)[keyof typeof permissions]

export function hasPermission(grantedPermissions: string[], requiredPermission: Permission) {
  return grantedPermissions.includes(requiredPermission)
}
