import React from 'react';
import { Button } from '@/components/ui/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { useTheme, ThemeVariant } from '@/contexts/ThemeContext';
import { Palette, Sun, Moon, Building2, Leaf, Sparkles } from 'lucide-react';
import { cn } from '@/lib/utils';

const themeConfig: Record<ThemeVariant, {
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
  gradient: string;
}> = {
  light: {
    label: 'Clair',
    icon: Sun,
    description: 'Thème clair classique',
    gradient: 'from-white to-gray-100'
  },
  dark: {
    label: 'Sombre',
    icon: Moon,
    description: 'Thème sombre moderne',
    gradient: 'from-gray-900 to-gray-800'
  },
  'blue-corporate': {
    label: 'Corporate',
    icon: Building2,
    description: 'Bleu professionnel',
    gradient: 'from-blue-500 to-blue-600'
  },
  'green-nature': {
    label: 'Nature',
    icon: Leaf,
    description: 'Vert naturel',
    gradient: 'from-green-500 to-green-600'
  },
  'purple-creative': {
    label: 'Créatif',
    icon: Sparkles,
    description: 'Violet créatif',
    gradient: 'from-purple-500 to-pink-500'
  }
};

export const ThemeSelector: React.FC<{ className?: string }> = ({ className }) => {
  const { theme, setTheme } = useTheme();
  const currentConfig = themeConfig[theme];
  const CurrentIcon = currentConfig.icon;

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button 
          variant="ghost" 
          size="sm" 
          className={cn(
            "relative overflow-hidden group transition-all duration-300",
            "hover:scale-105 hover:shadow-md",
            className
          )}
        >
          <div className="flex items-center gap-2">
            <CurrentIcon className="h-4 w-4" />
            <span className="hidden sm:inline">{currentConfig.label}</span>
            <Palette className="h-3 w-3 opacity-60" />
          </div>
        </Button>
      </DropdownMenuTrigger>
      
      <DropdownMenuContent 
        align="end" 
        className="w-64 p-2 bg-card/95 backdrop-blur-sm border shadow-xl animate-scale-in"
      >
        <DropdownMenuLabel className="flex items-center gap-2 text-sm font-semibold">
          <Palette className="h-4 w-4" />
          Sélectionner un thème
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        
        <div className="grid gap-2">
          {Object.entries(themeConfig).map(([themeKey, config]) => {
            const Icon = config.icon;
            const isActive = theme === themeKey;
            
            return (
              <DropdownMenuItem
                key={themeKey}
                className={cn(
                  "flex items-center gap-3 p-3 rounded-lg cursor-pointer transition-all duration-200",
                  "hover:bg-muted/50 focus:bg-muted/50",
                  isActive && "bg-primary/10 border border-primary/20"
                )}
                onClick={() => setTheme(themeKey as ThemeVariant)}
              >
                <div className={cn(
                  "w-8 h-8 rounded-full flex items-center justify-center bg-gradient-to-br",
                  config.gradient,
                  "shadow-sm"
                )}>
                  <Icon className="h-4 w-4 text-white" />
                </div>
                
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="font-medium text-sm">{config.label}</span>
                    {isActive && (
                      <div className="w-2 h-2 bg-primary rounded-full animate-pulse" />
                    )}
                  </div>
                  <p className="text-xs text-muted-foreground">{config.description}</p>
                </div>
              </DropdownMenuItem>
            );
          })}
        </div>
        
        <DropdownMenuSeparator />
        <div className="text-xs text-muted-foreground text-center py-1">
          Le thème s'applique à tout le site
        </div>
      </DropdownMenuContent>
    </DropdownMenu>
  );
};