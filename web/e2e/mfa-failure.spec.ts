import { createHmac } from 'node:crypto'
import { expect, test } from '@playwright/test'

const gatehouseURL = 'http://localhost:5173'
const password = 'correct horse battery staple'
const totpSecret = Buffer.from('01234567890123456789')

test('invalid MFA code cannot bypass the challenge', async ({ page }) => {
  await page.goto(`${gatehouseURL}/login`)

  await page.getByRole('textbox', { name: 'Organization slug' }).fill('mfa-lab')
  await page.getByRole('textbox', { name: 'Email address' }).fill('morgan@mfa.test')
  await page.getByLabel('Password').fill(password)
  await page.getByRole('button', { name: 'Sign in' }).click()

  await expect(page).toHaveURL(/\/mfa\/challenge/)
  await expect(
    page.getByRole('heading', {
      name: 'Enter a verification code',
    }),
  ).toBeVisible()

  const invalidCode = selectInvalidCode()

  await page.getByLabel('Six-digit code').fill(invalidCode)
  await page.getByRole('button', { name: 'Verify and continue' }).click()

  await expect(page.getByText('invalid MFA challenge')).toBeVisible()
  await expect(page).toHaveURL(/\/mfa\/challenge/)
})

function selectInvalidCode() {
  const currentStep = Math.floor(Date.now() / 1000 / 30)
  const acceptedCodes = new Set<string>()

  for (let offset = -2; offset <= 2; offset += 1) {
    acceptedCodes.add(generateTOTP(currentStep + offset))
  }

  for (let value = 0; value < 10; value += 1) {
    const candidate = value.toString().padStart(6, '0')

    if (!acceptedCodes.has(candidate)) {
      return candidate
    }
  }

  throw new Error('could not select an invalid TOTP code')
}

function generateTOTP(step: number) {
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(step))

  const digest = createHmac('sha1', totpSecret).update(counter).digest()
  const offset = digest[digest.length - 1] & 0x0f

  const value =
    ((digest[offset] & 0x7f) << 24) |
    (digest[offset + 1] << 16) |
    (digest[offset + 2] << 8) |
    digest[offset + 3]

  return (value % 1_000_000).toString().padStart(6, '0')
}
