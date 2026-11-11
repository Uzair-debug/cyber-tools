// Same mark as public/logo.svg, drawn in the active theme's accent colour
export function Logo({ className = 'w-6 h-6' }: { className?: string }) {
  return (
    <svg viewBox="0 0 64 64" className={className} role="img" aria-label="Cyber Tools Portal">
      <rect width="64" height="64" rx="15" style={{ fill: 'rgb(var(--a-600))' }} />
      <path
        d="M32 9.5 51 16.5v14c0 12.2-8 21.3-19 25-11-3.7-19-12.8-19-25v-14z"
        fill="none"
        stroke="#fff"
        strokeWidth="4.2"
        strokeLinejoin="round"
      />
      <path d="m23.5 26 7 6-7 6" fill="none" stroke="#fff" strokeWidth="4.2" strokeLinecap="round" strokeLinejoin="round" />
      <path d="M34 39.5h8" stroke="#fff" strokeWidth="4.2" strokeLinecap="round" />
    </svg>
  );
}
