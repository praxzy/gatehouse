import { apiRequest } from './client'

export type AuthenticationLevel = 'password' | 'mfa' | 'upstream'

export type RegisterInput = {
  tenant_name: string
  tenant_slug: string
  email: string
  display_name: string
  password: string
}

export type RegisterResponse = {
  tenant_id: string
  user_id: string
  membership_id: string
  owner_role_id: string
}

export type LoginInput = {
  tenant_slug: string
  email: string
  password: string
}

export type LoginResponse = {
  user_id: string
  email: string
  expires_at: string
}

export type CurrentUser = {
  user_id: string
  email: string
  display_name: string
  tenant_id: string
  tenant_name: string
  tenant_slug: string
  membership_id: string
  authentication_level: AuthenticationLevel
  session_expires_at: string
  mfa_required: boolean
  mfa_enrolled: boolean
  fully_authenticated: boolean
  capabilities: {
    manage_members: boolean
  }
}

export type TOTPEnrollment = {
  provisioning_uri: string
  manual_key: string
  expires_at: string
}

export type MFAConfirmation = {
  authentication_level: 'mfa'
  recovery_codes: string[]
}

export type MFAChallenge = {
  authentication_level: 'mfa'
  expires_at: string
}

export function register(input: RegisterInput) {
  return apiRequest<RegisterResponse>('/auth/register', {
    method: 'POST',
    body: input,
  })
}

export function login(input: LoginInput) {
  return apiRequest<LoginResponse>('/auth/login', {
    method: 'POST',
    body: input,
  })
}

export function getCurrentUser(signal?: AbortSignal) {
  return apiRequest<CurrentUser>('/auth/current-user', {
    signal,
  })
}

export function logout() {
  return apiRequest<void>('/auth/logout', {
    method: 'POST',
  })
}

export function beginTOTPEnrollment() {
  return apiRequest<TOTPEnrollment>('/auth/mfa/enroll', {
    method: 'POST',
  })
}

export function confirmTOTPEnrollment(code: string) {
  return apiRequest<MFAConfirmation>('/auth/mfa/enroll/confirm', {
    method: 'POST',
    body: { code },
  })
}

export function completeTOTPChallenge(code: string) {
  return apiRequest<MFAChallenge>('/auth/mfa/challenge/totp', {
    method: 'POST',
    body: { code },
  })
}

export function completeRecoveryChallenge(recoveryCode: string) {
  return apiRequest<MFAChallenge>('/auth/mfa/challenge/recovery', {
    method: 'POST',
    body: {
      recovery_code: recoveryCode,
    },
  })
}

export function verifyEmail(token: string) {
  return apiRequest<void>('/auth/email/verify', {
    method: 'POST',
    body: { token },
  })
}
