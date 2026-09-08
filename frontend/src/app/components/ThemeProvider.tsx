import * as React from "react"
import { ThemeProvider as NextThemesProvider } from "next-themes"
import { type ThemeProviderProps } from "next-themes/dist/types"

/**
 * Enhanced ThemeProvider with:
 * - Support for light, dark, and system themes
 * - Persistent user theme preference in localStorage
 * - Smooth transitions between themes
 * - No flash of unstyled content on startup
 */
export function ThemeProvider({ children, ...props }: ThemeProviderProps) {
  return (
    <NextThemesProvider
      attribute="class"
      defaultTheme="system"
      enableSystem
      enableColorSchemeQuery
      storageKey="spectrashield-theme"
      forcedTheme={props.forcedTheme}
      {...props}
    >
      {children}
    </NextThemesProvider>
  )
}
