import React from 'react';
import { ChevronRight, Home } from 'lucide-react';
import { useNavigation } from '@/contexts/NavigationContext';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';

interface BreadcrumbsProps {
  className?: string;
}

export const Breadcrumbs: React.FC<BreadcrumbsProps> = ({ className }) => {
  const { navigationState, goToPage } = useNavigation();
  const { breadcrumbs } = navigationState;

  if (breadcrumbs.length <= 1) {
    return null;
  }

  return (
    <nav className={cn("flex items-center space-x-1 text-sm text-muted-foreground", className)}>
      {breadcrumbs.map((breadcrumb, index) => (
        <span key={breadcrumb.path} className="flex items-center">
          {index > 0 && (
            <ChevronRight className="h-4 w-4 text-muted-foreground/50" />
          )}
          <Button
            variant="ghost"
            size="sm"
            className={cn(
              "h-auto p-1 text-sm font-normal hover:text-primary transition-colors",
              index === breadcrumbs.length - 1 
                ? "text-foreground font-medium cursor-default" 
                : "text-muted-foreground hover:text-primary cursor-pointer"
            )}
            onClick={() => index < breadcrumbs.length - 1 && goToPage(breadcrumb.path)}
            disabled={index === breadcrumbs.length - 1}
          >
            {index === 0 && <Home className="h-3 w-3 mr-1" />}
            {breadcrumb.label}
          </Button>
        </span>
      ))}
    </nav>
  );
};