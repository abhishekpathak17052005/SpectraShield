import * as React from "react"
import { Moon, Sun, Laptop } from "lucide-react"
import { useTheme } from "next-themes"
import { motion } from "motion/react"

/**
 * Enhanced theme toggle with three options:
 * - Light mode
 * - System preference
 * - Dark mode
 * 
 * Displays current selection and updates globally
 */
export function ThemeToggle() {
  const { setTheme, theme } = useTheme()
  const [mounted, setMounted] = React.useState(false)

  React.useEffect(() => {
    setMounted(true)
  }, [])

  if (!mounted) {
    return null
  }

  const options = [
    { value: "light", label: "Light", icon: Sun },
    { value: "system", label: "System", icon: Laptop },
    { value: "dark", label: "Dark", icon: Moon },
  ]

  return (
    <div className="flex items-center p-1 bg-surface-elevated rounded-full border border-border gap-0.5 backdrop-blur-sm">
      {options.map(({ value, label, icon: Icon }) => (
        <motion.button
          key={value}
          onClick={() => setTheme(value)}
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
          className={`p-1.5 rounded-full transition-all ${
            theme === value
              ? "bg-accent text-accent-foreground shadow-sm"
              : "text-text-muted hover:text-text-secondary"
          }`}
          title={`${label} mode`}
          aria-label={`Switch to ${label} mode`}
        >
          <Icon className="h-4 w-4" />
        </motion.button>
      ))}
    </div>
  )
}

