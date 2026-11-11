'use client';

// Replaces the root layout when it fails, so it can't rely on globals.css or the theme variables
export default function GlobalError({ retry }: { error: unknown; retry: () => void }) {
  return (
    <html lang="en">
      <body style={{ margin: 0, minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: '#0f1115', color: '#e5e7eb', fontFamily: 'system-ui, sans-serif' }}>
        <title>Cyber Tools Portal</title>
        <div role="alert" style={{ padding: 24, textAlign: 'center' }}>
          <h1 style={{ fontSize: 16 }}>The portal hit an unexpected error</h1>
          <button onClick={() => retry()} style={{ padding: '6px 12px', cursor: 'pointer' }}>
            Try again
          </button>
        </div>
      </body>
    </html>
  );
}
