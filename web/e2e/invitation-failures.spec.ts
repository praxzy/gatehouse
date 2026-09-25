import { expect, test } from '@playwright/test'

const gatehouseURL = 'http://localhost:5173'

const invitationCases = [
  {
    name: 'unknown',
    token: 'MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTE',
  },
  {
    name: 'expired',
    token: 'MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA',
  },
] as const

for (const invitation of invitationCases) {
  test(`${invitation.name} invitation is rejected safely`, async ({ page }) => {
    await page.goto(`${gatehouseURL}/accept-invitation#token=${invitation.token}`)

    await expect(
      page.getByRole('heading', {
        name: 'This invitation isn’t available',
      }),
    ).toBeVisible()

    await expect(
      page.getByText(
        'It may have expired, already been accepted, or been replaced by a newer invitation.',
      ),
    ).toBeVisible()

    await expect(
      page.getByRole('link', {
        name: 'Return to sign in',
      }),
    ).toBeVisible()

    await expect(page).toHaveURL(`${gatehouseURL}/accept-invitation`)

    await expect(page.getByText(invitation.token)).toHaveCount(0)
  })
}
