import * as React from "react"
import { cn } from "./utils"

export interface SelectProps
  extends React.SelectHTMLAttributes<HTMLSelectElement> {
  icon?: React.ReactNode
  error?: boolean
  success?: boolean
}

const Select = React.forwardRef<HTMLSelectElement, SelectProps>(
  ({ className, icon, error, success, children, ...props }, ref) => (
    <div className="relative">
      {icon && (
        <div className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted pointer-events-none">
          {icon}
        </div>
      )}
      <select
        className={cn(
          "flex h-9 w-full rounded-lg border px-3 py-2 text-sm bg-input-background text-input-text appearance-none transition-colors",
          "border-input-border hover:border-input-border-hover focus:outline-none focus:border-input-border-focus focus:ring-2 focus:ring-input-border-focus/30",
          "disabled:cursor-not-allowed disabled:opacity-50 disabled:bg-surface-muted disabled:text-text-disabled",
          icon && "pl-9",
          error && "border-destructive focus:border-destructive focus:ring-destructive/30",
          success && "border-success focus:border-success focus:ring-success/30",
          "pr-8",
          className
        )}
        ref={ref}
        {...props}
      >
        {children}
      </select>
      <div className="absolute right-2.5 top-1/2 -translate-y-1/2 pointer-events-none text-text-muted">
        <svg
          className="h-4 w-4"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M19 14l-7 7m0 0l-7-7m7 7V3"
          />
        </svg>
      </div>
    </div>
  )
)
Select.displayName = "Select"

export { Select }
