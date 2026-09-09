import * as React from "react"
import { cn } from "./utils"

export interface TextareaProps
  extends React.TextareaHTMLAttributes<HTMLTextAreaElement> {
  error?: boolean
  success?: boolean
  resizable?: boolean
}

const Textarea = React.forwardRef<HTMLTextAreaElement, TextareaProps>(
  ({ className, error, success, resizable = true, ...props }, ref) => (
    <textarea
      className={cn(
        "flex min-h-[80px] w-full rounded-lg border px-3 py-2 text-sm bg-input-background text-input-text placeholder-input-placeholder transition-colors",
        "border-input-border hover:border-input-border-hover focus:outline-none focus:border-input-border-focus focus:ring-2 focus:ring-input-border-focus/30",
        "disabled:cursor-not-allowed disabled:opacity-50 disabled:bg-surface-muted disabled:text-text-disabled",
        error && "border-destructive focus:border-destructive focus:ring-destructive/30",
        success && "border-success focus:border-success focus:ring-success/30",
        !resizable && "resize-none",
        className
      )}
      ref={ref}
      {...props}
    />
  )
)
Textarea.displayName = "Textarea"

export { Textarea }
