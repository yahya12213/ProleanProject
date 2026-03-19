import React from 'react';
import { cn } from '@/lib/utils';

interface ModernLoadingProps {
  className?: string;
  size?: 'sm' | 'md' | 'lg';
  variant?: 'spinner' | 'dots' | 'pulse' | 'skeleton';
}

export const ModernLoading: React.FC<ModernLoadingProps> = ({ 
  className, 
  size = 'md', 
  variant = 'spinner' 
}) => {
  const sizeClasses = {
    sm: 'w-4 h-4',
    md: 'w-6 h-6',
    lg: 'w-8 h-8'
  };

  if (variant === 'spinner') {
    return (
      <div className={cn("animate-spin rounded-full border-2 border-muted border-t-primary", sizeClasses[size], className)}>
      </div>
    );
  }

  if (variant === 'dots') {
    return (
      <div className={cn("flex space-x-1", className)}>
        {[0, 1, 2].map((i) => (
          <div
            key={i}
            className={cn(
              "rounded-full bg-primary animate-bounce",
              size === 'sm' ? 'w-1 h-1' : size === 'md' ? 'w-2 h-2' : 'w-3 h-3'
            )}
            style={{ animationDelay: `${i * 0.1}s` }}
          />
        ))}
      </div>
    );
  }

  if (variant === 'pulse') {
    return (
      <div className={cn("rounded-full bg-primary animate-pulse", sizeClasses[size], className)}>
      </div>
    );
  }

  // Skeleton variant
  return (
    <div className={cn("animate-pulse bg-muted rounded", className)}>
      <div className="h-4 bg-muted-foreground/20 rounded w-3/4 mb-2"></div>
      <div className="h-4 bg-muted-foreground/20 rounded w-1/2 mb-2"></div>
      <div className="h-4 bg-muted-foreground/20 rounded w-5/6"></div>
    </div>
  );
};

interface ShimmerProps {
  className?: string;
  children?: React.ReactNode;
}

export const Shimmer: React.FC<ShimmerProps> = ({ className, children }) => {
  return (
    <div className={cn("relative overflow-hidden", className)}>
      {children}
      <div className="absolute inset-0 -translate-x-full animate-[shimmer_2s_infinite] bg-gradient-to-r from-transparent via-white/60 to-transparent" />
    </div>
  );
};

interface LoadingStateProps {
  isLoading: boolean;
  children: React.ReactNode;
  fallback?: React.ReactNode;
}

export const LoadingState: React.FC<LoadingStateProps> = ({ 
  isLoading, 
  children, 
  fallback 
}) => {
  if (isLoading) {
    return fallback || <ModernLoading variant="spinner" />;
  }
  
  return <>{children}</>;
};