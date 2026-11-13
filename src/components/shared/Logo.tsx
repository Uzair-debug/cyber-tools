// Same mark as public/logo.svg, drawn in the active theme's accent colour
export function Logo({ className = 'w-6 h-6' }: { className?: string }) {
  return (
    <svg viewBox="0 0 64 64" className={className} role="img" aria-label="Cyber Tools Portal">
      <rect width="64" height="64" rx="16" style={{ fill: 'rgb(var(--a-600))' }} />
      <path
        d="M44.9 20.4A17.3 17.3 0 1 0 44.9 43.6"
        fill="none"
        stroke="#fff"
        strokeWidth="4.7"
        strokeLinecap="round"
      />
      <path d="M32 32h17.3" style={{ stroke: 'rgb(var(--a-200))' }} strokeWidth="3.3" strokeLinecap="round" />
      <circle cx="32" cy="32" r="6" style={{ fill: 'rgb(var(--a-200))' }} />
    </svg>
  );
}
