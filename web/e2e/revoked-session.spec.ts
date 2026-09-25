import { expect, test, type BrowserContext, type Page } from '@playwright/test'

const gatehouseURL = 'http://localhost:5173'
const tenantSlug = 'northstar'
const password = 'correct horse battery staple'

const revokedSessionMembershipID = '15000000-0000-4000-8000-000000000015'

test('revoked member session requires reauthentication', async ({ browser }) => {
  const aliceContext = await browser.newContext()
  const rileyContext = await browser.newContext()

  let aliceAuthenticated = false

  try {
    const alicePage = await aliceContext.newPage()

    await loginToGatehouse(alicePage, 'alice@northstar.test')

    aliceAuthenticated = true

    // Make the test retry-safe if a previous attempt stopped after
    // disabling Riley.
    await updateMemberStatus(aliceContext, 'active')

    const rileyPage = await rileyContext.newPage()

    await loginToGatehouse(rileyPage, 'riley@northstar.test')

    await expect(rileyPage).toHaveURL(`${gatehouseURL}/app`)

    await updateMemberStatus(aliceContext, 'disabled')

    await rileyPage.reload()

    await expect(rileyPage).toHaveURL(/localhost:5173\/login\?return_to=%2Fapp/)

    await expect(
      rileyPage.getByRole('heading', {
        name: 'Welcome back',
      }),
    ).toBeVisible()
  } finally {
    if (aliceAuthenticated) {
      await updateMemberStatus(aliceContext, 'active')
    }

    await aliceContext.close()
    await rileyContext.close()
  }
})

async function loginToGatehouse(page: Page, email: string) {
  await page.goto(`${gatehouseURL}/login`)

  await page
    .getByRole('textbox', {
      name: 'Organization slug',
    })
    .fill(tenantSlug)

  await page
    .getByRole('textbox', {
      name: 'Email address',
    })
    .fill(email)

  await page.getByLabel('Password').fill(password)

  await page
    .getByRole('button', {
      name: 'Sign in',
    })
    .click()

  await expect(page).toHaveURL(`${gatehouseURL}/app`)
}

async function updateMemberStatus(context: BrowserContext, status: 'active' | 'disabled') {
  const csrfResponse = await context.request.get(`${gatehouseURL}/api/v1/auth/csrf`, {
    headers: {
      Origin: gatehouseURL,
    },
  })

  expect(csrfResponse.status()).toBe(200)

  const csrf = (await csrfResponse.json()) as {
    csrf_token: string
  }

  const response = await context.request.patch(
    `${gatehouseURL}/api/v1/members/${revokedSessionMembershipID}`,
    {
      headers: {
        Origin: gatehouseURL,
        'X-CSRF-Token': csrf.csrf_token,
      },
      data: {
        status,
      },
    },
  )

  expect(response.status(), await response.text()).toBe(204)
}
