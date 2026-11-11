'use client';

import React, { createContext, useContext, useEffect, useState } from 'react';

export type ThemeId = 'graphite' | 'midnight' | 'navy' | 'light';

export interface ThemeOption {
  id: ThemeId;
  name: string;
  subtitle: string;
  icon: string;
  previewColor: string;
}

export const THEMES: ThemeOption[] = [
  {
    id: 'graphite',
    name: 'Graphite',
    subtitle: 'Neutral grey with violet accent',
    icon: '◐',
    previewColor: '#7c3aed',
  },
  {
    id: 'midnight',
    name: 'Midnight',
    subtitle: 'True black with violet accent',
    icon: '●',
    previewColor: '#000000',
  },
  {
    id: 'navy',
    name: 'Navy',
    subtitle: 'Blue-grey with cyan accent',
    icon: '◑',
    previewColor: '#0891b2',
  },
  {
    id: 'light',
    name: 'Light',
    subtitle: 'Light grey with violet accent',
    icon: '○',
    previewColor: '#f4f4f5',
  },
];

const STORAGE_KEY = 'ctp-theme';
// Themes from before the rebrand, mapped to their closest replacement
const LEGACY_KEY = 'crimson-sec-theme';
const LEGACY_THEMES: Record<string, ThemeId> = {
  slate: 'navy',
  cyberpunk: 'navy',
  crimson: 'graphite',
  emerald: 'graphite',
  midnight: 'midnight',
};

function readSavedTheme(): ThemeId {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved && THEMES.some(t => t.id === saved)) return saved as ThemeId;
    const legacy = localStorage.getItem(LEGACY_KEY);
    if (legacy && LEGACY_THEMES[legacy]) return LEGACY_THEMES[legacy];
  } catch {
    // Storage can be blocked; fall back to the default theme
  }
  return 'graphite';
}

interface ThemeContextType {
  theme: ThemeId;
  setTheme: (t: ThemeId) => void;
  activeThemeConfig: ThemeOption;
}

const ThemeContext = createContext<ThemeContextType>({
  theme: 'graphite',
  setTheme: () => {},
  activeThemeConfig: THEMES[0],
});

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [theme, setThemeState] = useState<ThemeId>('graphite');

  const applyTheme = (themeId: ThemeId) => {
    document.documentElement.setAttribute('data-theme', themeId);
  };

  useEffect(() => {
    const initialTheme = readSavedTheme();
    setThemeState(initialTheme);
    applyTheme(initialTheme);
  }, []);

  const setTheme = (newTheme: ThemeId) => {
    setThemeState(newTheme);
    try {
      localStorage.setItem(STORAGE_KEY, newTheme);
      localStorage.removeItem(LEGACY_KEY);
    } catch {
      // Storage can be blocked; the theme still applies for this visit
    }
    applyTheme(newTheme);
  };

  const activeThemeConfig = THEMES.find(t => t.id === theme) || THEMES[0];

  return (
    <ThemeContext.Provider value={{ theme, setTheme, activeThemeConfig }}>
      {children}
    </ThemeContext.Provider>
  );
}

export function useTheme() {
  return useContext(ThemeContext);
}
