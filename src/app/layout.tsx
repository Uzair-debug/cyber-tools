import type { Metadata } from 'next';
import localFont from 'next/font/local';
import './globals.css';

// Fonts ship from the npm packages, so builds need no network and visitors' browsers never contact Google.
// Instrument Sans for the interface; JetBrains Mono for indicators, because it keeps 0/O and 1/l/I distinct in hashes and IPs.
const uiSans = localFont({
  src: '../../node_modules/@fontsource-variable/instrument-sans/files/instrument-sans-latin-wght-normal.woff2',
  weight: '400 700',
  variable: '--font-sans',
  display: 'swap',
});
const dataMono = localFont({
  src: '../../node_modules/@fontsource-variable/jetbrains-mono/files/jetbrains-mono-latin-wght-normal.woff2',
  weight: '100 800',
  variable: '--font-mono',
  display: 'swap',
});

// Applies the saved theme before first paint so the light theme doesn't flash dark
const THEME_BOOT = `try{var t=localStorage.getItem('ctp-theme');if(t)document.documentElement.setAttribute('data-theme',t)}catch(e){}`;

export const metadata: Metadata = {
  title: 'Cyber Tools Portal | SecOps & SOC Analysis Toolkit',
  description: 'Security analysis toolkit for Purview audit triage, email headers, DNS recon, IP threat intel, defanging and cryptography.',
  icons: {
    icon: [{ url: '/logo.svg', type: 'image/svg+xml' }],
    shortcut: '/favicon.ico',
    apple: '/apple-touch-icon.png',
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className={`dark ${uiSans.variable} ${dataMono.variable}`} suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: THEME_BOOT }} />
      </head>
      <body className="bg-[var(--bg-app)] text-slate-100 font-sans min-h-screen antialiased selection:bg-violet-500/30 selection:text-slate-50">
        {children}
      </body>
    </html>
  );
}
