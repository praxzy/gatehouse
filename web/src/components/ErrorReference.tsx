type ErrorReferenceProps = {
  requestId?: string
}

export function ErrorReference({ requestId }: ErrorReferenceProps) {
  if (!requestId) {
    return null
  }

  return (
    <details className="mt-2 text-xs">
      <summary className="w-fit cursor-pointer font-medium opacity-75 transition-opacity hover:opacity-100">
        Error reference
      </summary>

      <code className="overflow-wrap-anywhere mt-2 block opacity-75">Request ID: {requestId}</code>
    </details>
  )
}
