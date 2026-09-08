# SpectraShield Theme System Guide

This guide explains how to use the SpectraShield light/dark theme system throughout the application.

## Architecture

The theme system consists of:

1. **CSS Variables** (`src/styles/theme.css`)
   - Semantic color tokens for light and dark themes
   - Organized by category: surfaces, text, borders, inputs, status, etc.
   - No hardcoded hex values in components

2. **TypeScript Utilities** (`src/app/theme/`)
   - `colors.ts`: Color palette definitions and utility functions
   - `useThemeColors.ts`: React hook for accessing theme colors
   - `index.ts`: Central export point

3. **UI Components** (`src/app/components/ui/`)
   - Button, Badge, Input, Select, Textarea, Checkbox, Radio
   - All theme-aware with semantic variants

## Quick Start

### Using CSS Classes (Recommended)

```tsx
import { Button } from '@/app/components/ui/Button'

export function MyComponent() {
  return (
    <Button variant="accent" size="md">
      Click me
    </Button>
  )
}
```

### Using the useThemeColors Hook

```tsx
import { useThemeColors } from '@/app/theme'

export function MyComponent() {
  const colors = useThemeColors()
  
  const riskColor = colors.getRiskColor(75) // Get color for risk score
  const textColor = colors.getColor('text-primary')
  const chartColors = colors.getChartColors()
  
  return (
    <div style={{ color: textColor }}>
      Risk Level: <span style={{ color: riskColor }}>High</span>
    </div>
  )
}
```

### Using Color Tokens Directly

```tsx
import { getThemeColor, getRiskStatus } from '@/app/theme'

const safeColor = getThemeColor('success', 'dark')
const status = getRiskStatus(45, 'light')
```

## Color Tokens Reference

### Surfaces & Backgrounds

- `--background`: Main app background
- `--surface`: Primary surface (cards, containers)
- `--surface-elevated`: Elevated surface (modals, popovers)
- `--surface-muted`: Muted surface (disabled states)
- `--surface-hover`: Hover state background

### Text Colors

- `--text-primary`: Primary text
- `--text-secondary`: Secondary text
- `--text-muted`: Muted text
- `--text-disabled`: Disabled text

### Semantic Colors

- `--accent`: Primary accent (cyan in both themes)
- `--success`: Success state (green)
- `--warning`: Warning state (amber)
- `--destructive`: Destructive state (red)
- `--info`: Info state (blue/cyan)
- `--danger`: Danger state (red)

### Component-Specific Tokens

#### Sidebar
- `--sidebar-background`
- `--sidebar-surface`
- `--sidebar-foreground`
- `--sidebar-border`
- `--sidebar-active`
- `--sidebar-active-foreground`

#### Header
- `--header-background`
- `--header-border`
- `--header-foreground`

#### Table
- `--table-background`
- `--table-row-hover`
- `--table-row-selected`
- `--table-border`

#### Graph
- `--graph-background`
- `--graph-grid`
- `--graph-node`
- `--graph-edge`
- `--graph-label`

#### Input
- `--input-background`
- `--input-border`
- `--input-border-hover`
- `--input-border-focus`
- `--input-text`
- `--input-placeholder`

## Button Variants

```tsx
<Button variant="default">Default</Button>
<Button variant="secondary">Secondary</Button>
<Button variant="accent">Accent</Button>
<Button variant="destructive">Destructive</Button>
<Button variant="success">Success</Button>
<Button variant="warning">Warning</Button>
<Button variant="danger">Danger</Button>
<Button variant="outline">Outline</Button>
<Button variant="ghost">Ghost</Button>
<Button variant="link">Link</Button>
```

## Button Sizes

```tsx
<Button size="xs">Extra Small</Button>
<Button size="sm">Small</Button>
<Button size="md">Medium (default)</Button>
<Button size="lg">Large</Button>
<Button size="xl">Extra Large</Button>
<Button size="icon">Icon</Button>
```

## Badge Variants

```tsx
<Badge variant="default">Default</Badge>
<Badge variant="success">Success</Badge>
<Badge variant="warning">Warning</Badge>
<Badge variant="destructive">Destructive</Badge>
<Badge variant="info">Info</Badge>
<Badge variant="accent">Accent</Badge>
<Badge variant="outline">Outline</Badge>
<Badge variant="ghost">Ghost</Badge>
```

## Risk Badge

```tsx
import { RiskBadge } from '@/app/components/ui/Badge'

<RiskBadge level="safe">Safe</RiskBadge>
<RiskBadge level="suspicious">Suspicious</RiskBadge>
<RiskBadge level="high-risk">High Risk</RiskBadge>
<RiskBadge level="critical">Critical</RiskBadge>
```

## Status Badge

```tsx
import { StatusBadge } from '@/app/components/ui/Badge'

<StatusBadge status="online" animated>Online</StatusBadge>
<StatusBadge status="offline">Offline</StatusBadge>
<StatusBadge status="enriched" animated>Enriched</StatusBadge>
<StatusBadge status="not-enriched">Not Enriched</StatusBadge>
<StatusBadge status="live" animated>Live</StatusBadge>
<StatusBadge status="demo">Demo</StatusBadge>
```

## Form Components

### Input

```tsx
import { Input } from '@/app/components/ui/Input'
import { Search } from 'lucide-react'

<Input 
  placeholder="Search..." 
  icon={<Search className="h-4 w-4" />}
/>
<Input 
  error 
  placeholder="Error state"
/>
<Input 
  success 
  placeholder="Success state"
/>
```

### Select

```tsx
import { Select } from '@/app/components/ui/Select'

<Select>
  <option>Option 1</option>
  <option>Option 2</option>
</Select>
```

### Textarea

```tsx
import { Textarea } from '@/app/components/ui/Textarea'

<Textarea 
  placeholder="Enter text..."
  rows={4}
/>
```

### Checkbox

```tsx
import { Checkbox } from '@/app/components/ui/Checkbox'

<Checkbox 
  label="Accept terms" 
  description="You agree to our terms of service"
/>
```

### Radio

```tsx
import { Radio } from '@/app/components/ui/Radio'

<Radio 
  name="theme" 
  value="dark" 
  label="Dark Mode"
  description="Choose dark theme"
/>
```

## Theme System Usage in Non-UI Components

### Getting Current Theme

```tsx
import { useTheme } from 'next-themes'

export function MyComponent() {
  const { theme } = useTheme()
  // theme: 'light' | 'dark' | 'system'
}
```

### Conditional Styling Based on Theme

```tsx
import { useThemeColors } from '@/app/theme'

export function MyComponent() {
  const colors = useThemeColors()
  
  return (
    <div style={{
      backgroundColor: colors.isDark ? '#060A12' : '#F8FAFC',
      color: colors.getColor('text-primary')
    }}>
      {colors.isDark ? 'Dark Mode' : 'Light Mode'}
    </div>
  )
}
```

### Using Chart Colors

```tsx
import { useThemeColors } from '@/app/theme'

export function MyChart() {
  const colors = useThemeColors()
  const chartColors = colors.getChartColors()
  
  return <BarChart colors={chartColors} />
}
```

## Best Practices

1. **Always use semantic tokens**, not hardcoded colors
   - ✅ `text-primary`, `bg-accent`, `border-border`
   - ❌ `text-white`, `bg-blue-500`, `border-gray-300`

2. **Use component variants** instead of custom styling
   - ✅ `<Button variant="accent" />`
   - ❌ `<button className="bg-cyan-500" />`

3. **For custom colors**, use the `useThemeColors` hook
   - ✅ `const color = colors.getColor('accent')`
   - ❌ `const color = '#0EA5E9'`

4. **Respect accessibility**
   - Ensure sufficient contrast in both themes
   - Don't rely on color alone to convey meaning
   - Use icons or text labels with colors

5. **Test in both themes**
   - Always verify components in light and dark modes
   - Use the theme toggle in sidebar to test

## Migrating Existing Components

To migrate a component to use the theme system:

1. Replace hardcoded colors with theme tokens:
   ```tsx
   // Before
   className="bg-blue-500 text-white border-gray-300"
   
   // After
   className="bg-accent text-accent-foreground border-border"
   ```

2. Update semantic color names:
   ```tsx
   // Before
   className="text-white hover:text-gray-100"
   
   // After
   className="text-foreground hover:text-text-secondary"
   ```

3. Use components from `ui/` instead of custom implementations:
   ```tsx
   // Before
   <button className="px-4 py-2 bg-blue-500 rounded">Click</button>
   
   // After
   import { Button } from '@/components/ui/Button'
   <Button>Click</Button>
   ```

## Debugging

If theme changes don't apply:

1. Check if component uses CSS classes (should work automatically)
2. Verify CSS variables are defined in `theme.css`
3. Use browser DevTools to inspect computed styles
4. Check if component is wrapped in `ThemeProvider`
5. Ensure theme is mounted with `useEffect` in SSR context

## Resources

- Theme CSS: `src/styles/theme.css`
- Color utilities: `src/app/theme/colors.ts`
- useThemeColors hook: `src/app/theme/useThemeColors.ts`
- UI components: `src/app/components/ui/`
- ThemeProvider: `src/app/components/ThemeProvider.tsx`
- ThemeToggle: `src/app/components/ThemeToggle.tsx`
