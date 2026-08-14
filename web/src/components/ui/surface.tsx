import type { ComponentProps } from 'react'
import { cn } from '@/lib/utils'

type SurfaceTone = 'default' | 'primary' | 'brass' | 'inverse'

type SurfaceDepth = 'flat' | 'soft' | 'raised'

type SurfaceProps = ComponentProps<'article'> & {
  tone?: SurfaceTone
  depth?: SurfaceDepth
  interactive?: boolean
}

const toneClasses: Record<SurfaceTone, string> = {
  default: 'border-border bg-card text-card-foreground',
  primary: 'border-primary/15 bg-primary/[0.055] text-card-foreground',
  brass: 'border-gatehouse-brass/25 bg-gatehouse-brass/[0.09] text-card-foreground',
  inverse: 'border-white/10 bg-gatehouse-forest text-white',
}

const depthClasses: Record<SurfaceDepth, string> = {
  flat: '',
  soft: 'shadow-[var(--shadow-surface)]',
  raised: 'shadow-[var(--shadow-surface-raised)]',
}

export function Surface({
  tone = 'default',
  depth = 'soft',
  interactive = false,
  className,
  ...props
}: SurfaceProps) {
  return (
    <article
      data-slot="surface"
      className={cn(
        'relative overflow-hidden rounded-xl border',
        toneClasses[tone],
        depthClasses[depth],
        interactive && 'surface-interactive',
        className,
      )}
      {...props}
    />
  )
}
