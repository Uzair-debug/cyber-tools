import type { Metadata } from 'next';
import { IBM_Plex_Mono, IBM_Plex_Sans } from 'next/font/google';
import './globals.css';

// Self-hosted at build time, so visitors' browsers never contact Google
const plexSans = IBM_Plex_Sans({ subsets: ['latin'], weight: ['400', '500', '600', '700'], variable: '--font-sans', display: 'swap' });
const plexMono = IBM_Plex_Mono({ subsets: ['latin'], weight: ['400', '500', '600'], variable: '--font-mono', display: 'swap' });

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
    <html lang="en" className={`dark ${plexSans.variable} ${plexMono.variable}`} suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: THEME_BOOT }} />
      </head>
      <body className="bg-[var(--bg-app)] text-slate-100 font-sans min-h-screen antialiased selection:bg-violet-500/30 selection:text-violet-100">
        {children}
      </body>
    </html>
  );
}
