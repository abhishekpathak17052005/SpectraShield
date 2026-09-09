import * as React from "react"
import { cn } from "./utils"

export interface CardProps extends React.HTMLAttributes<HTMLDivElement> {
  elevated?: boolean
  interactive?: boolean
  noBorder?: boolean
}

const Card = React.forwardRef<HTMLDivElement, CardProps>(
  ({ className, elevated = false, interactive = false, noBorder = false, ...props }, ref) => (
    <div
      className={cn(
        "rounded-lg bg-surface border transition-all",
        !noBorder && "border-border",
        elevated && "bg-surface-elevated border-border shadow-lg",
        interactive && "hover:shadow-lg hover:border-border-strong cursor-pointer",
        className
      )}
      ref={ref}
      {...props}
    />
  )
)
Card.displayName = "Card"

export interface CardHeaderProps extends React.HTMLAttributes<HTMLDivElement> {}

const CardHeader = React.forwardRef<HTMLDivElement, CardHeaderProps>(
  ({ className, ...props }, ref) => (
    <div
      className={cn("flex flex-col space-y-1.5 p-6 border-b border-border", className)}
      ref={ref}
      {...props}
    />
  )
)
CardHeader.displayName = "CardHeader"

export interface CardTitleProps extends React.HTMLAttributes<HTMLHeadingElement> {}

const CardTitle = React.forwardRef<HTMLHeadingElement, CardTitleProps>(
  ({ className, ...props }, ref) => (
    <h2
      className={cn("text-lg font-semibold text-foreground leading-none tracking-tight", className)}
      ref={ref}
      {...props}
    />
  )
)
CardTitle.displayName = "CardTitle"

export interface CardDescriptionProps extends React.HTMLAttributes<HTMLParagraphElement> {}

const CardDescription = React.forwardRef<HTMLParagraphElement, CardDescriptionProps>(
  ({ className, ...props }, ref) => (
    <p
      className={cn("text-sm text-text-muted", className)}
      ref={ref}
      {...props}
    />
  )
)
CardDescription.displayName = "CardDescription"

export interface CardContentProps extends React.HTMLAttributes<HTMLDivElement> {}

const CardContent = React.forwardRef<HTMLDivElement, CardContentProps>(
  ({ className, ...props }, ref) => (
    <div className={cn("p-6 pt-0", className)} ref={ref} {...props} />
  )
)
CardContent.displayName = "CardContent"

export interface CardFooterProps extends React.HTMLAttributes<HTMLDivElement> {}

const CardFooter = React.forwardRef<HTMLDivElement, CardFooterProps>(
  ({ className, ...props }, ref) => (
    <div
      className={cn("flex items-center p-6 pt-0", className)}
      ref={ref}
      {...props}
    />
  )
)
CardFooter.displayName = "CardFooter"

export { Card, CardHeader, CardFooter, CardTitle, CardDescription, CardContent }
