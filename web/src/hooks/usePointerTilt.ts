import { useEffect, useRef } from 'react'
import type { PointerEvent } from 'react'

export function usePointerTilt<Element extends HTMLElement>(maximumTilt = 0.45) {
  const elementRef = useRef<Element>(null)
  const animationFrame = useRef<number | null>(null)

  useEffect(() => {
    return () => {
      if (animationFrame.current !== null) {
        window.cancelAnimationFrame(animationFrame.current)
      }
    }
  }, [])

  function handlePointerMove(event: PointerEvent<Element>) {
    if (
      event.pointerType !== 'mouse' ||
      window.matchMedia('(prefers-reduced-motion: reduce)').matches
    ) {
      return
    }

    const element = elementRef.current
    if (!element) {
      return
    }

    const bounds = element.getBoundingClientRect()
    const horizontal = (event.clientX - bounds.left) / bounds.width
    const vertical = (event.clientY - bounds.top) / bounds.height

    if (animationFrame.current !== null) {
      window.cancelAnimationFrame(animationFrame.current)
    }

    animationFrame.current = window.requestAnimationFrame(() => {
      element.style.setProperty('--surface-tilt-x', `${(0.5 - vertical) * maximumTilt * 2}deg`)
      element.style.setProperty('--surface-tilt-y', `${(horizontal - 0.5) * maximumTilt * 2}deg`)
      animationFrame.current = null
    })
  }

  function handlePointerLeave() {
    if (animationFrame.current !== null) {
      window.cancelAnimationFrame(animationFrame.current)
      animationFrame.current = null
    }

    const element = elementRef.current
    if (!element) {
      return
    }

    element.style.setProperty('--surface-tilt-x', '0deg')
    element.style.setProperty('--surface-tilt-y', '0deg')
  }

  return {
    ref: elementRef,
    onPointerMove: handlePointerMove,
    onPointerLeave: handlePointerLeave,
  }
}
