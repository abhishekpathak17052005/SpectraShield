/**
 * SpectraShield Theme Color Palette
 * 
 * Centralized semantic color tokens for use in components.
 * These map directly to CSS variables defined in src/styles/theme.css
 * 
 * Usage:
 * - For CSS classes: use Tailwind classes like bg-accent, text-primary, etc.
 * - For inline styles: use getThemeColor('accent') or themeColors.accent
 * - For charts/canvas: use getThemeHexColor('accent') to get hex values
 */

// Color scale types
export type ColorScale = 'light' | 'dark'
export type SemanticColor = 
  | 'background'
  | 'foreground'
  | 'surface'
  | 'surface-elevated'
  | 'surface-muted'
  | 'surface-hover'
  | 'text-primary'
  | 'text-secondary'
  | 'text-muted'
  | 'text-disabled'
  | 'border'
  | 'border-subtle'
  | 'border-strong'
  | 'primary'
  | 'primary-foreground'
  | 'secondary'
  | 'secondary-foreground'
  | 'accent'
  | 'accent-foreground'
  | 'accent-muted'
  | 'success'
  | 'success-foreground'
  | 'success-muted'
  | 'warning'
  | 'warning-foreground'
  | 'warning-muted'
  | 'destructive'
  | 'destructive-foreground'
  | 'destructive-muted'
  | 'info'
  | 'info-foreground'
  | 'info-muted'
  | 'danger'
  | 'danger-foreground'

/**
 * Light Theme Color Palette
 */
export const lightTheme: Record<string, string> = {
  // Surfaces & Backgrounds
  background: '#F8FAFC',
  surface: '#FFFFFF',
  'surface-elevated': '#F1F5F9',
  'surface-muted': '#E2E8F0',
  'surface-hover': '#F0F4F8',

  // Text / Foreground
  foreground: '#0F172A',
  'text-primary': '#0F172A',
  'text-secondary': '#475569',
  'text-muted': '#94A3B8',
  'text-disabled': '#CBD5E1',

  // Borders
  border: '#E2E8F0',
  'border-subtle': '#F1F5F9',
  'border-strong': '#94A3B8',

  // Primary
  primary: '#0F172A',
  'primary-foreground': '#FFFFFF',
  'primary-hover': '#1E293B',

  // Secondary
  secondary: '#F1F5F9',
  'secondary-foreground': '#0F172A',
  'secondary-hover': '#E2E8F0',

  // Accent (Cyan)
  accent: '#0EA5E9',
  'accent-foreground': '#FFFFFF',
  'accent-hover': '#0284C7',
  'accent-muted': '#E0F2FE',

  // Success (Green)
  success: '#16A34A',
  'success-foreground': '#FFFFFF',
  'success-muted': '#DCFCE7',

  // Warning (Amber)
  warning: '#F59E0B',
  'warning-foreground': '#FFFFFF',
  'warning-muted': '#FEF3C7',

  // Destructive (Red)
  destructive: '#DC2626',
  'destructive-foreground': '#FFFFFF',
  'destructive-muted': '#FEE2E2',

  // Info (Blue)
  info: '#0284C7',
  'info-foreground': '#FFFFFF',
  'info-muted': '#E0F2FE',

  // Danger
  danger: '#DC2626',
  'danger-foreground': '#FFFFFF',

  // Sidebar
  'sidebar-background': '#F8FAFC',
  'sidebar-surface': '#FFFFFF',
  'sidebar-foreground': '#0F172A',
  'sidebar-border': '#E2E8F0',
  'sidebar-hover': '#F1F5F9',
  'sidebar-active': '#E0F2FE',
  'sidebar-active-foreground': '#0284C7',

  // Header
  'header-background': '#FFFFFF',
  'header-border': '#E2E8F0',
  'header-foreground': '#0F172A',

  // Table
  'table-background': '#FFFFFF',
  'table-row-hover': '#F8FAFC',
  'table-row-selected': '#E0F2FE',
  'table-border': '#E2E8F0',

  // Graph
  'graph-background': '#F8FAFC',
  'graph-grid': '#E2E8F0',
  'graph-node': '#0284C7',
  'graph-edge': '#CBD5E1',
  'graph-label': '#0F172A',

  // Input
  'input-background': '#FFFFFF',
  'input-border': '#E2E8F0',
  'input-text': '#0F172A',
  'input-placeholder': '#94A3B8',
}

/**
 * Dark Theme Color Palette
 */
export const darkTheme: Record<string, string> = {
  // Surfaces & Backgrounds
  background: '#060A12',
  surface: '#0B1120',
  'surface-elevated': '#111827',
  'surface-muted': '#172033',
  'surface-hover': '#0F1729',

  // Text / Foreground
  foreground: '#F8FAFC',
  'text-primary': '#F8FAFC',
  'text-secondary': '#CBD5E1',
  'text-muted': '#64748B',
  'text-disabled': '#475569',

  // Borders
  border: '#1E293B',
  'border-subtle': '#0F1729',
  'border-strong': '#475569',

  // Primary
  primary: '#F8FAFC',
  'primary-foreground': '#0B1120',
  'primary-hover': '#E2E8F0',

  // Secondary
  secondary: '#1E293B',
  'secondary-foreground': '#F8FAFC',
  'secondary-hover': '#2E3A4F',

  // Accent (Cyan)
  accent: '#0EA5E9',
  'accent-foreground': '#0B1120',
  'accent-hover': '#38BDF8',
  'accent-muted': '#082F49',

  // Success (Green)
  success: '#10B981',
  'success-foreground': '#FFFFFF',
  'success-muted': '#064E3B',

  // Warning (Amber)
  warning: '#F59E0B',
  'warning-foreground': '#FFFFFF',
  'warning-muted': '#78350F',

  // Destructive (Red)
  destructive: '#EF4444',
  'destructive-foreground': '#FFFFFF',
  'destructive-muted': '#7F1D1D',

  // Info (Cyan)
  info: '#38BDF8',
  'info-foreground': '#FFFFFF',
  'info-muted': '#082F49',

  // Danger
  danger: '#EF4444',
  'danger-foreground': '#FFFFFF',

  // Sidebar
  'sidebar-background': '#060A12',
  'sidebar-surface': '#0B1120',
  'sidebar-foreground': '#F8FAFC',
  'sidebar-border': '#1E293B',
  'sidebar-hover': '#111827',
  'sidebar-active': '#082F49',
  'sidebar-active-foreground': '#38BDF8',

  // Header
  'header-background': '#0B1120',
  'header-border': '#1E293B',
  'header-foreground': '#F8FAFC',

  // Table
  'table-background': '#0B1120',
  'table-row-hover': '#111827',
  'table-row-selected': '#082F49',
  'table-border': '#1E293B',

  // Graph
  'graph-background': '#060A12',
  'graph-grid': '#0F1729',
  'graph-node': '#38BDF8',
  'graph-edge': '#2E3A4F',
  'graph-label': '#E2E8F0',

  // Input
  'input-background': '#0B1120',
  'input-border': '#1E293B',
  'input-text': '#F8FAFC',
  'input-placeholder': '#64748B',
}

/**
 * Get color palette for current theme
 */
export function getThemePalette(theme: ColorScale): Record<string, string> {
  return theme === 'dark' ? darkTheme : lightTheme
}

/**
 * Get a specific color from the current theme
 * Returns hex value directly
 */
export function getThemeColor(colorName: string, theme: ColorScale = 'dark'): string {
  const palette = getThemePalette(theme)
  return palette[colorName] || '#000000'
}

/**
 * Get CSS variable reference (for use in CSS-in-JS)
 */
export function getThemeVar(colorName: string): string {
  return `var(--${colorName})`
}

/**
 * Semantic color groups for easy access
 */
export const semanticColors = {
  status: {
    safe: 'success',
    suspicious: 'warning',
    highRisk: 'destructive',
    info: 'info',
  },
  ui: {
    primary: 'primary',
    secondary: 'secondary',
    accent: 'accent',
    danger: 'destructive',
  },
  text: {
    primary: 'text-primary',
    secondary: 'text-secondary',
    muted: 'text-muted',
    disabled: 'text-disabled',
  },
  surface: {
    default: 'background',
    card: 'surface',
    elevated: 'surface-elevated',
    hover: 'surface-hover',
    muted: 'surface-muted',
  },
  border: {
    default: 'border',
    subtle: 'border-subtle',
    strong: 'border-strong',
  },
}

/**
 * Risk score color mapping
 */
export const riskScoreColors = {
  safe: {
    light: lightTheme.success,
    dark: darkTheme.success,
  },
  suspicious: {
    light: lightTheme.warning,
    dark: darkTheme.warning,
  },
  highRisk: {
    light: lightTheme.destructive,
    dark: darkTheme.destructive,
  },
}

/**
 * Get risk color based on score
 */
export function getRiskColor(score: number, theme: ColorScale = 'dark'): string {
  if (score >= 70) return getThemeColor('destructive', theme)
  if (score >= 30) return getThemeColor('warning', theme)
  return getThemeColor('success', theme)
}

/**
 * Get risk label and color
 */
export function getRiskStatus(score: number, theme: ColorScale = 'dark') {
  if (score >= 70) {
    return { label: 'HIGH RISK', color: getThemeColor('destructive', theme) }
  }
  if (score >= 30) {
    return { label: 'SUSPICIOUS', color: getThemeColor('warning', theme) }
  }
  return { label: 'SAFE', color: getThemeColor('success', theme) }
}

/**
 * Chart color schemes for both themes
 */
export const chartColorSchemes = {
  light: [
    lightTheme.accent,        // Primary accent
    '#8B5CF6',                // Violet
    '#EC4899',                // Pink
    '#F97316',                // Orange
    '#06B6D4',                // Cyan
    '#6366F1',                // Indigo
  ],
  dark: [
    darkTheme.accent,         // Primary accent
    '#A78BFA',                // Light Violet
    '#F472B6',                // Light Pink
    '#FB923C',                // Light Orange
    '#22D3EE',                // Light Cyan
    '#818CF8',                // Light Indigo
  ],
}

/**
 * Get chart colors for theme
 */
export function getChartColors(theme: ColorScale = 'dark'): string[] {
  return theme === 'dark' ? chartColorSchemes.dark : chartColorSchemes.light
}
