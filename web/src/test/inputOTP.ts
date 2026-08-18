import { act } from '@testing-library/react'

export async function flushInputOTPTimers() {
  await act(async () => {
    await new Promise((resolve) => window.setTimeout(resolve, 60))
  })
}
