import { cn } from '@/lib/utils'

type GatehouseBrandProps = {
  inverse?: boolean
  compact?: boolean
  showDescriptor?: boolean
  className?: string
}

export function GatehouseBrand({
  inverse = false,
  compact = false,
  showDescriptor = true,
  className,
}: GatehouseBrandProps) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-3',
        inverse ? 'text-white' : 'text-foreground',
        className,
      )}
    >
      <span
        className={cn(
          'grid size-10 shrink-0 place-items-center rounded-lg border',
          inverse
            ? 'border-white/15 bg-white/10 text-emerald-100'
            : 'border-primary/15 bg-primary text-primary-foreground',
        )}
      >
        <svg
          viewBox="0 0 36 36"
          className="size-7"
          fill="none"
          stroke="currentColor"
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth="1.8"
          aria-hidden="true"
        >
          <path d="M8 28V16a10 10 0 0 1 20 0v12" />
          <path d="M13 28V17a5 5 0 0 1 10 0v11" />
          <path d="M6 28h24" />
          <path d="M18 21v7" />
        </svg>
      </span>

      {!compact && (
        <span className="grid leading-none">
          <strong className="text-[1.05rem] font-semibold tracking-tight">Gatehouse</strong>
          {showDescriptor && (
            <span
              className={cn(
                'mt-1 text-[0.68rem] font-medium tracking-[0.12em] uppercase',
                inverse ? 'text-white/55' : 'text-muted-foreground',
              )}
            >
              Identity control plane
            </span>
          )}
        </span>
      )}
    </span>
  )
}
