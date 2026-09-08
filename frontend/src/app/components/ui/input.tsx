import * as React from "react"
import { cn } from "./utils"

export interface InputProps
  extends React.InputHTMLAttributes<HTMLInputElement> {
  icon?: React.ReactNode
  error?: boolean
  success?: boolean
}

const Input = React.forwardRef<HTMLInputElement, InputProps>(
  ({ className, type, icon, error, success, ...props }, ref) => (
    <div className="relative">
      {icon && (
        <div className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted pointer-events-none">
          {icon}
        </div>
      )}
      <input
        type={type}
        className={cn(
          "flex h-9 w-full rounded-lg border px-3 py-2 text-sm bg-input-background text-input-text placeholder-input-placeholder transition-colors",
          "border-input-border hover:border-input-border-hover focus:outline-none focus:border-input-border-focus focus:ring-2 focus:ring-input-border-focus/30",
          "disabled:cursor-not-allowed disabled:opacity-50 disabled:bg-surface-muted disabled:text-text-disabled",
          icon && "pl-9",
          error && "border-destructive focus:border-destructive focus:ring-destructive/30",
          success && "border-success focus:border-success focus:ring-success/30",
          className
        )}
        ref={ref}
        {...props}
      />
    </div>
  )
)
Input.displayName = "Input"

export { Input }
