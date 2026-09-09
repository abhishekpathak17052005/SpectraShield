import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"
import { cn } from "./utils"

const badgeVariants = cva(
  "inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-semibold border transition-colors",
  {
    variants: {
      variant: {
        default:
          "bg-primary/10 text-primary border-primary/30 dark:bg-primary/15",
        secondary:
          "bg-secondary/50 text-secondary-foreground border-border",
        accent:
          "bg-accent-muted text-accent border-accent/30 dark:bg-accent/15",
        success:
          "bg-success-muted text-success border-success/30 dark:bg-success/15",
        warning:
          "bg-warning-muted text-warning border-warning/30 dark:bg-warning/15",
        destructive:
          "bg-destructive-muted text-destructive border-destructive/30 dark:bg-destructive/15",
        info:
          "bg-info-muted text-info border-info/30 dark:bg-info/15",
        danger:
          "bg-danger-muted text-danger border-danger/30 dark:bg-danger/15",
        outline:
          "bg-transparent text-foreground border-border",
        ghost:
          "bg-surface-muted/50 text-text-secondary border-transparent",
      },
      size: {
        xs: "text-[10px] px-2 py-0.5",
        sm: "text-xs px-2.5 py-1",
        md: "text-sm px-3 py-1.5",
        lg: "text-base px-4 py-2",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "sm",
    },
  }
)

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {
  icon?: React.ReactNode
  dot?: boolean
}

const Badge = React.forwardRef<HTMLDivElement, BadgeProps>(
  ({ className, variant, size, icon, dot, ...props }, ref) => (
    <div
      className={cn(badgeVariants({ variant, size, className }))}
      ref={ref}
      {...props}
    >
      {dot && (
        <div className="h-1.5 w-1.5 rounded-full bg-current flex-shrink-0" />
      )}
      {icon && (
        <div className="flex-shrink-0">
          {icon}
        </div>
      )}
      {props.children}
    </div>
  )
)
Badge.displayName = "Badge"

/**
 * Risk-specific badge for displaying threat levels
 */
export interface RiskBadgeProps
  extends Omit<BadgeProps, 'variant'> {
  level: 'safe' | 'suspicious' | 'high-risk' | 'critical'
  icon?: React.ReactNode
}

const RiskBadge = React.forwardRef<HTMLDivElement, RiskBadgeProps>(
  ({ level, icon, className, ...props }, ref) => {
    const variantMap = {
      'safe': 'success',
      'suspicious': 'warning',
      'high-risk': 'destructive',
      'critical': 'danger',
    } as const

    return (
      <Badge
        ref={ref}
        variant={variantMap[level]}
        size="sm"
        className={className}
        {...props}
      >
        {icon}
        {props.children}
      </Badge>
    )
  }
)
RiskBadge.displayName = "RiskBadge"

/**
 * Status badge for online/offline/enriched states
 */
export interface StatusBadgeProps
  extends Omit<BadgeProps, 'variant'> {
  status: 'online' | 'offline' | 'enriched' | 'not-enriched' | 'demo' | 'live'
  animated?: boolean
}

const StatusBadge = React.forwardRef<HTMLDivElement, StatusBadgeProps>(
  ({ status, animated, className, ...props }, ref) => {
    const variantMap = {
      'online': 'success',
      'offline': 'destructive',
      'enriched': 'accent',
      'not-enriched': 'outline',
      'demo': 'warning',
      'live': 'success',
    } as const

    const shouldAnimate = animated && (status === 'online' || status === 'live' || status === 'enriched')

    return (
      <Badge
        ref={ref}
        variant={variantMap[status]}
        size="sm"
        className={cn(
          "inline-flex items-center gap-1.5",
          shouldAnimate && "animate-pulse",
          className
        )}
        dot={shouldAnimate}
        {...props}
      />
    )
  }
)
StatusBadge.displayName = "StatusBadge"

export { Badge, badgeVariants, RiskBadge, StatusBadge }
