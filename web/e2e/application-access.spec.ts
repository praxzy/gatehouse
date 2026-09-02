import { expect, test, type Page } from '@playwright/test'

const tenantSlug = 'northstar'
const password = 'correct horse battery staple'

test('Alice succeeds, Bob is denied, and a role change allows Bob', async ({ browser }) => {
  const aliceContext = await browser.newContext()
  const bobContext = await browser.newContext()

  try {
    const alicePage = await aliceContext.newPage()

    await beginGatehouseLogin(alicePage)
    await submitCredentials(alicePage, 'alice@northstar.test')

    await expect(alicePage).toHaveURL('http://localhost:8090/')
    await expect(
      alicePage.getByRole('heading', {
        name: 'Welcome back, Alice Admin.',
      }),
    ).toBeVisible()

    await alicePage.getByRole('link', { name: 'Open admin workspace' }).click()

    await expect(
      alicePage.getByRole('heading', {
        name: 'Admin workspace',
      }),
    ).toBeVisible()

    const bobPage = await bobContext.newPage()

    await beginGatehouseLogin(bobPage)
    await submitCredentials(bobPage, 'bob@northstar.test')

    await expect(
      bobPage.getByRole('heading', {
        name: 'Access denied',
      }),
    ).toBeVisible()

    await expect(bobPage).toHaveURL(/localhost:8090\/oauth\/callback/)

    await alicePage.goto('http://localhost:5173/app/members')

    await expect(
      alicePage.getByRole('heading', {
        name: 'Members',
      }),
    ).toBeVisible()

    const bobRole = alicePage.getByRole('combobox', {
      name: 'Role for Bob Viewer',
    })

    await bobRole.click()

    await alicePage
      .getByRole('option', {
        name: 'Admin',
        exact: true,
      })
      .click()

    const confirmation = alicePage.getByRole('alertdialog')

    await expect(
      confirmation.getByRole('heading', {
        name: 'Change Bob Viewer’s role?',
      }),
    ).toBeVisible()

    const roleChangeResponse = alicePage.waitForResponse(
      (response) =>
        response.request().method() === 'PATCH' &&
        response.url().includes('/api/v1/members/') &&
        response.status() === 204,
    )

    await confirmation
      .getByRole('button', {
        name: 'Change role',
      })
      .click()

    await roleChangeResponse
    await expect(bobRole).toContainText('Admin')

    await bobPage.getByRole('link', { name: 'Return to the portal' }).click()
    await bobPage.getByRole('link', { name: 'Continue with Gatehouse' }).click()

    await expect(bobPage).toHaveURL('http://localhost:8090/')

    await expect(
      bobPage.getByRole('heading', {
        name: 'Welcome back, Bob Viewer.',
      }),
    ).toBeVisible()

    await bobPage.getByRole('link', { name: 'Open admin workspace' }).click()

    await expect(
      bobPage.getByRole('heading', {
        name: 'Admin workspace',
      }),
    ).toBeVisible()
  } finally {
    await aliceContext.close()
    await bobContext.close()
  }
})

async function beginGatehouseLogin(page: Page) {
  await page.goto('/')

  await page
    .getByRole('link', {
      name: 'Continue with Gatehouse',
    })
    .click()

  await expect(page).toHaveURL(/localhost:5173\/login/)
}

async function submitCredentials(page: Page, email: string) {
  await page.getByRole('textbox', { name: 'Organization slug' }).fill(tenantSlug)
  await page.getByRole('textbox', { name: 'Email address' }).fill(email)
  await page.getByLabel('Password').fill(password)

  await page
    .getByRole('button', {
      name: 'Sign in',
    })
    .click()
}
