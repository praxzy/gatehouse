import { CircleAlert } from 'lucide-react'
import { APIError, APIUnavailableError } from '@/api/client'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { ErrorReference } from '@/components/ErrorReference'

type RequestErrorProps = {
  error: unknown
}

export function RequestError({ error }: RequestErrorProps) {
  if (!error) {
    return null
  }

  const message =
    error instanceof APIError || error instanceof APIUnavailableError
      ? error.message
      : 'Something went wrong. Please try again.'

  const requestID = error instanceof APIError ? error.requestId : undefined

  return (
    <Alert variant="destructive" className="rounded-lg border-destructive/20 bg-destructive/6">
      <CircleAlert aria-hidden="true" />

      <AlertTitle>{message}</AlertTitle>

      {requestID && (
        <AlertDescription>
          <ErrorReference requestId={requestID} />
        </AlertDescription>
      )}
    </Alert>
  )
}
