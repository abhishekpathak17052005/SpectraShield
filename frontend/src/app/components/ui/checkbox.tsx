import * as React from "react"
import { Check } from "lucide-react"
import { cn } from "./utils"

export interface CheckboxProps
  extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: React.ReactNode
  description?: React.ReactNode
  error?: boolean
}

const Checkbox = React.forwardRef<HTMLInputElement, CheckboxProps>(
  ({ className, label, description, error, ...props }, ref) => (
    <label className="flex items-start gap-2.5 cursor-pointer group">
      <div className="relative pt-1 flex-shrink-0">
        <input
          type="checkbox"
          className="sr-only peer"
          ref={ref}
          {...props}
        />
        <div
          className={cn(
            "h-5 w-5 rounded-md border-2 transition-all flex items-center justify-center",
            "border-border bg-input-background",
            "peer-hover:border-accent peer-hover:bg-accent/5",
            "peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-accent/30",
            "peer-checked:bg-accent peer-checked:border-accent peer-checked:hover:bg-accent-hover",
            "peer-disabled:opacity-50 peer-disabled:cursor-not-allowed",
            error && "border-destructive peer-checked:bg-destructive peer-checked:border-destructive",
            className
          )}
        >
          <Check className="h-3.5 w-3.5 text-accent-foreground opacity-0 peer-checked:opacity-100 transition-opacity" />
        </div>
      </div>
      {(label || description) && (
        <div className="flex-1 pt-0.5">
          {label && (
            <div className="text-sm font-medium text-text-primary group-hover:text-text-primary transition-colors">
              {label}
            </div>
          )}
          {description && (
            <div className="text-xs text-text-muted mt-0.5">
              {description}
            </div>
          )}
        </div>
      )}
    </label>
  )
)
Checkbox.displayName = "Checkbox"

export { Checkbox }
