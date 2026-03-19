import * as React from "react"
import { cn } from "@/lib/utils"
import { EnhancedCard } from "./enhanced-card"

// Skeleton loading component
interface SkeletonProps extends React.HTMLAttributes<HTMLDivElement> {
  lines?: number
  avatar?: boolean
  button?: boolean
}

const Skeleton = React.forwardRef<HTMLDivElement, SkeletonProps>(
  ({ className, lines = 1, avatar, button, ...props }, ref) => (
    <div ref={ref} className={cn("space-y-3", className)} {...props}>
      {avatar && (
        <div className="h-12 w-12 rounded-full loading-skeleton" />
      )}
      
      {Array.from({ length: lines }).map((_, i) => (
        <div 
          key={i}
          className={cn(
            "h-4 loading-skeleton",
            i === lines - 1 && "w-3/4", // Dernière ligne plus courte
            i === 0 && "w-full"
          )}
        />
      ))}
      
      {button && (
        <div className="h-10 w-24 rounded-md loading-skeleton" />
      )}
    </div>
  )
)
Skeleton.displayName = "Skeleton"

// Loading spinner avec différentes tailles
interface LoadingSpinnerProps {
  size?: "sm" | "md" | "lg" | "xl"
  className?: string
  text?: string
}

const LoadingSpinner: React.FC<LoadingSpinnerProps> = ({ 
  size = "md", 
  className,
  text 
}) => {
  const sizeClasses = {
    sm: "h-4 w-4",
    md: "h-8 w-8", 
    lg: "h-12 w-12",
    xl: "h-16 w-16"
  }

  return (
    <div className={cn("flex flex-col items-center justify-center space-y-2", className)}>
      <svg 
        className={cn("animate-spin text-primary", sizeClasses[size])}
        fill="none" 
        viewBox="0 0 24 24"
      >
        <circle 
          className="opacity-25" 
          cx="12" 
          cy="12" 
          r="10" 
          stroke="currentColor" 
          strokeWidth="4"
        />
        <path 
          className="opacity-75" 
          fill="currentColor" 
          d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
        />
      </svg>
      
      {text && (
        <p className="text-sm text-muted-foreground animate-pulse">{text}</p>
      )}
    </div>
  )
}

// Composant de chargement pour les tables
interface TableLoadingProps {
  rows?: number
  columns?: number
}

const TableLoading: React.FC<TableLoadingProps> = ({ 
  rows = 5, 
  columns = 4 
}) => (
  <div className="space-y-4">
    {/* Header */}
    <div className="grid gap-4" style={{ gridTemplateColumns: `repeat(${columns}, 1fr)` }}>
      {Array.from({ length: columns }).map((_, i) => (
        <div key={i} className="h-6 loading-skeleton" />
      ))}
    </div>
    
    {/* Rows */}
    {Array.from({ length: rows }).map((_, rowIndex) => (
      <div 
        key={rowIndex}
        className="grid gap-4 py-2"
        style={{ gridTemplateColumns: `repeat(${columns}, 1fr)` }}
      >
        {Array.from({ length: columns }).map((_, colIndex) => (
          <div key={colIndex} className="h-8 loading-skeleton" />
        ))}
      </div>
    ))}
  </div>
)

// Page de chargement complète
interface PageLoadingProps {
  title?: string
  description?: string
}

const PageLoading: React.FC<PageLoadingProps> = ({ 
  title = "Chargement...",
  description 
}) => (
  <div className="min-h-screen flex items-center justify-center bg-background">
    <EnhancedCard variant="premium" className="p-8 max-w-md w-full mx-4">
      <div className="text-center space-y-6">
        <LoadingSpinner size="lg" />
        <div className="space-y-2">
          <h2 className="text-xl font-semibold">{title}</h2>
          {description && (
            <p className="text-muted-foreground">{description}</p>
          )}
        </div>
      </div>
    </EnhancedCard>
  </div>
)

// États vides avec appel à l'action
interface EmptyStateProps {
  icon?: React.ReactNode
  title: string
  description?: string
  action?: React.ReactNode
  className?: string
}

const EmptyState: React.FC<EmptyStateProps> = ({
  icon,
  title,
  description,
  action,
  className
}) => (
  <div className={cn("flex flex-col items-center justify-center text-center py-12", className)}>
    {icon && (
      <div className="h-16 w-16 text-muted-foreground mb-4 opacity-50">
        {icon}
      </div>
    )}
    
    <h3 className="text-lg font-semibold text-foreground mb-2">{title}</h3>
    
    {description && (
      <p className="text-muted-foreground mb-6 max-w-md">{description}</p>
    )}
    
    {action && (
      <div>{action}</div>
    )}
  </div>
)

// Hook pour gérer les états de chargement
interface UseLoadingState {
  isLoading: boolean
  error: string | null
  setLoading: (loading: boolean) => void
  setError: (error: string | null) => void
  clearError: () => void
}

const useLoadingState = (initialLoading = false): UseLoadingState => {
  const [isLoading, setIsLoading] = React.useState(initialLoading)
  const [error, setError] = React.useState<string | null>(null)

  const setLoading = React.useCallback((loading: boolean) => {
    setIsLoading(loading)
    if (loading) setError(null) // Clear error when starting to load
  }, [])

  const clearError = React.useCallback(() => {
    setError(null)
  }, [])

  return {
    isLoading,
    error,
    setLoading,
    setError,
    clearError
  }
}

export {
  Skeleton,
  LoadingSpinner,
  TableLoading,
  PageLoading,
  EmptyState,
  useLoadingState
}