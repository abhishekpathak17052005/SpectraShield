import * as React from "react"
import { cn } from "./utils"

export interface RadioProps
  extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: React.ReactNode
  description?: React.ReactNode
}

const Radio = React.forwardRef<HTMLInputElement, RadioProps>(
  ({ className, label, description, ...props }, ref) => (
    <label className="flex items-start gap-2.5 cursor-pointer group">
      <div className="relative pt-1 flex-shrink-0">
        <input
          type="radio"
          className="sr-only peer"
          ref={ref}
          {...props}
        />
        <div
          className={cn(
            "h-5 w-5 rounded-full border-2 transition-all ring-offset-background",
            "border-border bg-input-background",
            "peer-hover:border-accent peer-hover:bg-accent/5",
            "peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-offset-2 peer-focus:ring-accent/30",
            "peer-checked:border-accent peer-checked:hover:border-accent-hover",
            "peer-disabled:opacity-50 peer-disabled:cursor-not-allowed",
            className
          )}
        >
          <div className="absolute inset-2 rounded-full bg-accent opacity-0 peer-checked:opacity-100 transition-opacity" />
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
Radio.displayName = "Radio"

export { Radio }
