import type { Config } from "tailwindcss";

const SHADES = ["50", "100", "200", "300", "400", "500", "600", "700", "800", "900", "950"];

// A Tailwind colour scale read from the theme variables in globals.css (--n-* neutral, --a-* accent)
function themeScale(prefix: "n" | "a") {
  return Object.fromEntries(SHADES.map(s => [s, `rgb(var(--${prefix}-${s}) / <alpha-value>)`]));
}

const neutral = themeScale("n");
const accent = themeScale("a");

// Meaningful colours keep their hue in every theme; the light theme only swaps light and dark shades
const FIXED = ["red", "rose", "orange", "amber", "yellow", "green", "emerald", "lime", "blue", "sky"] as const;
const fixed = Object.fromEntries(FIXED.map(f => [f, Object.fromEntries(SHADES.map(s => [s, `rgb(var(--${f}-${s}) / <alpha-value>)`]))]));

const config: Config = {
  darkMode: ["class"],
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        // Greys follow the theme's neutral scale; decorative hues all become the theme accent.
        // Red, rose, orange, amber, yellow, green, emerald, lime, blue and sky keep their hue
        // because they carry meaning (severity, pass/fail, low risk).
        ...fixed,
        black: "rgb(var(--c-black) / <alpha-value>)",
        slate: neutral,
        gray: neutral,
        zinc: neutral,
        neutral: neutral,
        stone: neutral,
        cyan: accent,
        teal: accent,
        indigo: accent,
        violet: accent,
        purple: accent,
        fuchsia: accent,
        pink: accent,
        border: "hsl(var(--border))",
        input: "hsl(var(--input))",
        ring: "hsl(var(--ring))",
        background: "hsl(var(--background))",
        foreground: "hsl(var(--foreground))",
        primary: {
          DEFAULT: "hsl(var(--primary))",
          foreground: "hsl(var(--primary-foreground))",
        },
        secondary: {
          DEFAULT: "hsl(var(--secondary))",
          foreground: "hsl(var(--secondary-foreground))",
        },
        destructive: {
          DEFAULT: "hsl(var(--destructive))",
          foreground: "hsl(var(--destructive-foreground))",
        },
        muted: {
          DEFAULT: "hsl(var(--muted))",
          foreground: "hsl(var(--muted-foreground))",
        },
        accent: {
          DEFAULT: "hsl(var(--accent))",
          foreground: "hsl(var(--accent-foreground))",
        },
        card: {
          DEFAULT: "hsl(var(--card))",
          foreground: "hsl(var(--card-foreground))",
        },
        soc: {
          bg: "#090d16",
          card: "#0f172a",
          cardHover: "#131e36",
          border: "#1e293b",
          borderGlow: "#334155",
          cyber: "#06b6d4",
          emerald: "#10b981",
          amber: "#f59e0b",
          rose: "#f43f5e",
          purple: "#8b5cf6",
        }
      },
      borderRadius: {
        lg: "var(--radius)",
        md: "calc(var(--radius) - 2px)",
        sm: "calc(var(--radius) - 4px)",
      },
      fontFamily: {
        sans: ['var(--font-sans)', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['var(--font-mono)', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Consolas', 'monospace'],
      },
      animation: {
        'pulse-subtle': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'glow-pulse': 'glow 2s ease-in-out infinite alternate',
      },
      keyframes: {
        glow: {
          '0%': { boxShadow: '0 0 5px rgba(6, 182, 212, 0.2)' },
          '100%': { boxShadow: '0 0 20px rgba(6, 182, 212, 0.6)' },
        }
      }
    },
  },
  plugins: [],
};
export default config;
