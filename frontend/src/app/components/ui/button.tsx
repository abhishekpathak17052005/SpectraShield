import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"
import { cn } from "./utils"

const buttonVariants = cva(
  "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-lg font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50",
  {
    variants: {
      variant: {
        default:
          "bg-primary text-primary-foreground hover:bg-primary-hover active:bg-primary-hover/80 shadow-sm",
        secondary:
          "bg-secondary text-secondary-foreground border border-border hover:bg-secondary-hover active:bg-secondary-hover/80",
        accent:
          "bg-accent text-accent-foreground hover:bg-accent-hover active:bg-accent-hover/80 shadow-sm shadow-accent/30",
        destructive:
          "bg-destructive text-destructive-foreground hover:bg-destructive/90 active:bg-destructive/80 shadow-sm shadow-destructive/30",
        success:
          "bg-success text-success-foreground hover:bg-success/90 active:bg-success/80 shadow-sm shadow-success/30",
        warning:
          "bg-warning text-warning-foreground hover:bg-warning/90 active:bg-warning/80 shadow-sm shadow-warning/30",
        danger:
          "bg-danger text-danger-foreground hover:bg-danger/90 active:bg-danger/80 shadow-sm shadow-danger/30",
        outline:
          "border border-border text-foreground hover:bg-surface-hover active:bg-surface-muted",
        ghost:
          "text-foreground hover:bg-surface-hover active:bg-surface-muted",
        link:
          "text-accent underline-offset-4 hover:underline active:text-accent-hover",
      },
      size: {
        xs: "h-7 px-2 text-xs",
        sm: "h-8 px-3 text-sm",
        md: "h-9 px-4 text-sm",
        lg: "h-10 px-5 text-base",
        xl: "h-11 px-6 text-base",
        icon: "h-9 w-9",
        "icon-sm": "h-7 w-7",
        "icon-lg": "h-10 w-10",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "md",
    },
  }
)

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, ...props }, ref) => (
    <button
      className={cn(buttonVariants({ variant, size, className }))}
      ref={ref}
      {...props}
    />
  )
)
Button.displayName = "Button"

export { Button, buttonVariants }
