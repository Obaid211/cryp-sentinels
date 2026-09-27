// ============================================================================
// AuroraAvatar — Minimalist aurora-glow character (login page only)
// ============================================================================
// Design brief (user-supplied):
//   "A minimalistic character, head only, floating gently on a clean light
//    off-white background. The character is a diffused, glowing sphere of
//    flowing aurora light, blending cyan, violet, and soft blue gradients,
//    with soft, foggy edges blending into the background. The face is
//    outlined by glowing, clean geometric white vector lines, featuring
//    distinct Notion-style high curved eyebrows, simple dot eyes, and a
//    prominent 'L' shaped nose line. The expression is neutral and calm.
//    Ethereal, translucent, abstract, 3D render, soft light."
//
// v2 (superdesign draft dbe4903e — "cursor tracking + fading enlarged glow"):
//   • ENLARGED, FADING aurora: halo/core radii grew (~20%) with a progressive
//     foggy opacity falloff — the enlarged outer region dissolves into the
//     ivory background with no hard rim. The glow intentionally bleeds past
//     the SVG bounds (overflow: visible).
//   • FACE SIZE UNCHANGED: the face-line geometry and the container size are
//     identical to v1, so the face renders at exactly the same pixel size —
//     only the aurora around it got bigger and softer.
//   • CURSOR TRACKING: the dot eyes drift toward the pointer and the whole
//     face group parallax-translates gently with it (rAF lerp for smooth,
//     eased motion; springs back to neutral calm on pointer leave). Disabled
//     under prefers-reduced-motion or `interactive={false}`.
//   • Neutral calm expression (no mouth), float/drift/pulse animations kept.
//
// Implementation: layered SVG — blurred radial gradients for the aurora orb,
// drifting blurred blobs for the "flowing" light, and a white glowing vector
// face. Animations live in index.css. Used ONLY on the LoginPage.
// ============================================================================

import React, { useEffect, useId, useRef } from 'react'

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------
export interface AuroraAvatarProps {
  /** Rendered size in px (square). Defaults to 260. */
  size?: number
  /** Accessibility label for screen readers. */
  ariaLabel?: string
  /** Float/drift/pulse animation (also gated by prefers-reduced-motion). */
  animated?: boolean
  /** Eyes/face follow the mouse cursor. Defaults to true. */
  interactive?: boolean
  /** Optional CSS class for layout tweaks. */
  className?: string
}

// ---------------------------------------------------------------------------
// Cursor-tracking constants. Face/eye coordinates are the SAME as v1 — the
// face must remain the exact same size while the aurora grows around it.
// ---------------------------------------------------------------------------
const EYE_L_BASE = { x: 76, y: 98 }
const EYE_R_BASE = { x: 124, y: 98 }
/** Max face-group translation, in viewBox units (prominently reactive to cursor). */
const FACE_RANGE = 15.0
/** Max pupil drift, in viewBox units (enhanced parallax relative to face). */
const EYE_RANGE = 9.0
/** Max 3D tilt rotation in degrees. */
const TILT_RANGE = 7.5
/** Snappy lerp factor per frame (0..1) for instantaneous, smooth tracking. */
const LERP = 0.20

// ---------------------------------------------------------------------------
// AuroraAvatar
// ---------------------------------------------------------------------------
export const AuroraAvatar: React.FC<AuroraAvatarProps> = ({
  size = 260,
  ariaLabel = 'Aurora light character — calm neutral expression',
  animated = true,
  interactive = true,
  className = '',
}) => {
  // Unique-per-instance gradient IDs (avoids collisions if multiple mounts).
  const uid = useId().replace(/[^a-zA-Z0-9_-]/g, '')

  const containerRef = useRef<HTMLDivElement>(null)
  const faceRef = useRef<SVGGElement>(null)
  const eyeLRef = useRef<SVGCircleElement>(null)
  const eyeRRef = useRef<SVGCircleElement>(null)

  // ---- Cursor tracking: eyes drift toward the pointer, face follows -------
  useEffect(() => {
    if (!interactive || !animated) return
    if (typeof window === 'undefined') return
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return

    let target = { x: 0, y: 0 } // normalized -1..1 from avatar center
    let current = { x: 0, y: 0 }
    let raf = 0

    const onMove = (e: MouseEvent) => {
      const el = containerRef.current
      if (!el) return
      const rect = el.getBoundingClientRect()
      const cx = rect.left + rect.width / 2
      const cy = rect.top + rect.height / 2
      const dx = e.clientX - cx
      const dy = e.clientY - cy

      const dist = Math.hypot(dx, dy)
      if (dist < 1) {
        target = { x: 0, y: 0 }
        return
      }

      // Responsive power-curve sensitivity:
      // High initial gain for micro-movements, with seamless tracking across full screen
      const maxDist = Math.max(window.innerWidth, window.innerHeight) * 0.72
      const normalized = Math.min(dist / maxDist, 1)
      const saturation = Math.pow(normalized, 0.58)
      const angle = Math.atan2(dy, dx)

      target = {
        x: Math.cos(angle) * saturation,
        y: Math.sin(angle) * saturation,
      }
    }

    const onLeave = () => {
      target = { x: 0, y: 0 }
    }

    const tick = () => {
      // Ease toward target, then ease back to neutral when pointer leaves
      current.x += (target.x - current.x) * LERP
      current.y += (target.y - current.y) * LERP

      if (faceRef.current) {
        const tx = (current.x * FACE_RANGE).toFixed(2)
        const ty = (current.y * FACE_RANGE).toFixed(2)
        const rot = (current.x * TILT_RANGE).toFixed(2)
        faceRef.current.style.transform = `translate(${tx}px, ${ty}px) rotate(${rot}deg)`
        faceRef.current.style.transformOrigin = '100px 100px'
      }
      if (eyeLRef.current) {
        eyeLRef.current.setAttribute('cx', (EYE_L_BASE.x + current.x * EYE_RANGE).toFixed(2))
        eyeLRef.current.setAttribute('cy', (EYE_L_BASE.y + current.y * EYE_RANGE).toFixed(2))
      }
      if (eyeRRef.current) {
        eyeRRef.current.setAttribute('cx', (EYE_R_BASE.x + current.x * EYE_RANGE).toFixed(2))
        eyeRRef.current.setAttribute('cy', (EYE_R_BASE.y + current.y * EYE_RANGE).toFixed(2))
      }
      raf = requestAnimationFrame(tick)
    }

    raf = requestAnimationFrame(tick)
    window.addEventListener('mousemove', onMove)
    document.addEventListener('mouseleave', onLeave)

    return () => {
      cancelAnimationFrame(raf)
      window.removeEventListener('mousemove', onMove)
      document.removeEventListener('mouseleave', onLeave)
    }
  }, [interactive, animated])

  const anim = animated ? 'aurora-anim' : ''

  return (
    <div
      ref={containerRef}
      className={`relative inline-block select-none ${className}`}
      style={{ width: size, height: size }}
      role="img"
      aria-label={ariaLabel}
    >
      <svg
        viewBox="0 0 200 200"
        width="100%"
        height="100%"
        style={{ display: 'block', overflow: 'visible' }}
        aria-hidden="true"
      >
        <defs>
          {/* Aurora orb core: cyan → soft blue → violet. The enlarged core
              now fades fully to zero opacity at the rim — no hard edge. */}
          <radialGradient id={`${uid}-core`} cx="42%" cy="38%" r="75%">
            <stop offset="0%" stopColor="#bdf3fb" stopOpacity="0.95" />
            <stop offset="22%" stopColor="#7fe3f2" stopOpacity="0.9" />
            <stop offset="48%" stopColor="#8fb3f7" stopOpacity="0.85" />
            <stop offset="70%" stopColor="#a78bfa" stopOpacity="0.6" />
            <stop offset="88%" stopColor="#b9aefc" stopOpacity="0.28" />
            <stop offset="100%" stopColor="#c4b5fd" stopOpacity="0" />
          </radialGradient>

          {/* Wide ambient halo — enlarged (~20%) and fainter so the bigger
              region reads as fading light rather than a bigger disc. */}
          <radialGradient id={`${uid}-halo`} cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#9deef8" stopOpacity="0.4" />
            <stop offset="38%" stopColor="#a5b8fc" stopOpacity="0.2" />
            <stop offset="72%" stopColor="#c4b5fd" stopOpacity="0.07" />
            <stop offset="100%" stopColor="#c4b5fd" stopOpacity="0" />
          </radialGradient>

          {/* Outermost veil — the extra "fading region" gained by the
              enlargement: barely-there color that dissolves into the page. */}
          <radialGradient id={`${uid}-veil`} cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#b8ecf7" stopOpacity="0.16" />
            <stop offset="55%" stopColor="#bcc8fd" stopOpacity="0.08" />
            <stop offset="100%" stopColor="#ddd6fe" stopOpacity="0" />
          </radialGradient>

          {/* Soft top-left specular highlight (3D-render feel). */}
          <radialGradient id={`${uid}-spec`} cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#ffffff" stopOpacity="0.7" />
            <stop offset="100%" stopColor="#ffffff" stopOpacity="0" />
          </radialGradient>

          {/* Foggy-edge blurs of increasing strength (heavier than v1). */}
          <filter id={`${uid}-blur-xl`} x="-80%" y="-80%" width="260%" height="260%">
            <feGaussianBlur stdDeviation="18" />
          </filter>
          <filter id={`${uid}-blur-lg`} x="-60%" y="-60%" width="220%" height="220%">
            <feGaussianBlur stdDeviation="12" />
          </filter>
          <filter id={`${uid}-blur-md`} x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="7" />
          </filter>
          <filter id={`${uid}-blur-sm`} x="-40%" y="-40%" width="180%" height="180%">
            <feGaussianBlur stdDeviation="3.5" />
          </filter>

          {/* White face-line glow: blur the source, then merge a crisp copy
              on top so the lines stay geometric but read as luminous. */}
          <filter id={`${uid}-line-glow`} x="-40%" y="-40%" width="180%" height="180%">
            <feGaussianBlur stdDeviation="1.6" result="blurred" />
            <feMerge>
              <feMergeNode in="blurred" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        {/* Everything floats gently as one unit (see .aurora-float). */}
        <g className={animated ? 'aurora-float' : undefined}>
          {/* Outermost fading veil — the enlarged aurora region. Bleeds past
              the viewBox with zero opacity at its rim (overflow: visible). */}
          <circle
            cx="100"
            cy="102"
            r="112"
            fill={`url(#${uid}-veil)`}
            filter={`url(#${uid}-blur-xl)`}
          />

          {/* Ambient halo — enlarged + fainter than v1. */}
          <circle
            className={anim ? 'aurora-pulse' : undefined}
            cx="100"
            cy="102"
            r="94"
            fill={`url(#${uid}-halo)`}
            filter={`url(#${uid}-blur-lg)`}
          />

          {/* Aurora orb body — bigger, softer edge via medium blur and a
              gradient that reaches zero opacity before its rim. */}
          <circle
            cx="100"
            cy="102"
            r="63"
            fill={`url(#${uid}-core)`}
            filter={`url(#${uid}-blur-md)`}
          />

          {/* Flowing internal light bands (screen-blended, slow drift).
              Slightly larger and fainter than v1 to match the fade. */}
          <g style={{ mixBlendMode: 'screen' }}>
            <ellipse
              className={animated ? 'aurora-drift-1' : undefined}
              cx="86"
              cy="118"
              rx="38"
              ry="20"
              fill="#22d3ee"
              opacity="0.42"
              filter={`url(#${uid}-blur-md)`}
            />
            <ellipse
              className={animated ? 'aurora-drift-2' : undefined}
              cx="116"
              cy="86"
              rx="33"
              ry="18"
              fill="#a78bfa"
              opacity="0.46"
              filter={`url(#${uid}-blur-md)`}
            />
            <ellipse
              className={animated ? 'aurora-drift-1' : undefined}
              cx="104"
              cy="132"
              rx="28"
              ry="13"
              fill="#60a5fa"
              opacity="0.36"
              filter={`url(#${uid}-blur-md)`}
            />
          </g>

          {/* Specular highlight — translucent, top-left, extra soft. */}
          <ellipse
            cx="78"
            cy="66"
            rx="24"
            ry="14"
            fill={`url(#${uid}-spec)`}
            filter={`url(#${uid}-blur-lg)`}
            transform="rotate(-24 78 66)"
          />

          {/* -----------------------------------------------------------------
              Face — glowing white geometric vector lines. Coordinates are
              IDENTICAL to v1 (face stays the same size). Notion-style high
              curved eyebrows · simple dot eyes · prominent L-shaped nose.
              Neutral, calm: no mouth. The group parallax-follows the cursor.
             ----------------------------------------------------------------- */}
          <g ref={faceRef} style={{ willChange: 'transform' }}>
            <g
              stroke="#ffffff"
              strokeWidth="3.2"
              strokeLinecap="round"
              strokeLinejoin="round"
              fill="none"
              filter={`url(#${uid}-line-glow)`}
            >
              {/* Left eyebrow — high, smooth curve */}
              <path d="M 62 82 Q 74 70, 88 79" />
              {/* Right eyebrow — mirrored high curve */}
              <path d="M 112 79 Q 126 70, 138 82" />
              {/* L-shaped nose: vertical stem, then a horizontal foot to the right */}
              <path d="M 102 92 L 102 116 L 114 116" />
            </g>

            {/* Simple dot eyes (refs driven by the cursor-tracking loop) */}
            <circle
              ref={eyeLRef}
              cx={EYE_L_BASE.x}
              cy={EYE_L_BASE.y}
              r="4.6"
              fill="#ffffff"
              filter={`url(#${uid}-line-glow)`}
            />
            <circle
              ref={eyeRRef}
              cx={EYE_R_BASE.x}
              cy={EYE_R_BASE.y}
              r="4.6"
              fill="#ffffff"
              filter={`url(#${uid}-line-glow)`}
            />
          </g>
        </g>
      </svg>
    </div>
  )
}

export default AuroraAvatar
