/**
 * React hook for accessing theme colors in components
 * 
 * Usage:
 * const colors = useThemeColors()
 * const riskColor = colors.getRiskColor(75)
 * const textColor = colors.getColor('text-primary')
 */

import { useTheme } from 'next-themes'
import { useEffect, useState } from 'react'
import {
  getThemeColor,
  getRiskColor,
  getRiskStatus,
  getChartColors,
  getThemePalette,
  type ColorScale,
} from './colors'

export function useThemeColors() {
  const { theme } = useTheme()
  const [mounted, setMounted] = useState(false)

  useEffect(() => {
    setMounted(true)
  }, [])

  // Default to dark theme if not mounted to avoid hydration mismatch
  const currentTheme = mounted ? (theme === 'system' ? 'dark' : (theme as ColorScale)) : 'dark'

  return {
    /**
     * Get a specific color value
     */
    getColor: (colorName: string) => getThemeColor(colorName, currentTheme),

    /**
     * Get risk color based on score
     */
    getRiskColor: (score: number) => getRiskColor(score, currentTheme),

    /**
     * Get risk status with label and color
     */
    getRiskStatus: (score: number) => getRiskStatus(score, currentTheme),

    /**
     * Get chart color scheme
     */
    getChartColors: () => getChartColors(currentTheme),

    /**
     * Get full color palette
     */
    getPalette: () => getThemePalette(currentTheme),

    /**
     * Current theme
     */
    theme: currentTheme,

    /**
     * Is dark theme
     */
    isDark: currentTheme === 'dark',

    /**
     * Is light theme
     */
    isLight: currentTheme === 'light',
  }
}
