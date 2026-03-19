import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';

export type ThemeVariant = 'light' | 'dark' | 'blue-corporate' | 'green-nature' | 'purple-creative';

interface ThemeContextType {
  theme: ThemeVariant;
  setTheme: (theme: ThemeVariant) => void;
}

const ThemeContext = createContext<ThemeContextType | undefined>(undefined);

const themeVariants: Record<ThemeVariant, Record<string, string>> = {
  'light': {
    '--background': '0 0% 100%',
    '--foreground': '210 15% 10%',
    '--primary': '260 75% 65%',
    '--primary-foreground': '0 0% 100%',
    '--secondary': '142 76% 36%',
    '--secondary-foreground': '0 0% 100%',
    '--accent': '24 95% 53%',
    '--accent-foreground': '0 0% 100%',
    '--muted': '220 14% 96%',
    '--muted-foreground': '215 16% 47%',
    '--card': '0 0% 100%',
    '--card-foreground': '210 15% 10%',
    '--border': '220 13% 91%',
    '--input': '220 13% 91%',
    '--ring': '260 75% 65%',
    '--gradient-hero': 'linear-gradient(135deg, hsl(260 75% 65% / 0.4) 0%, hsl(260 75% 55% / 0.3) 50%, hsl(142 76% 36% / 0.35) 100%)',
    '--gradient-primary': 'linear-gradient(135deg, hsl(260 75% 65%), hsl(250 75% 70%))',
    '--gradient-accent': 'linear-gradient(135deg, hsl(24 95% 53%), hsl(20 95% 58%))',
  },
  'dark': {
    '--background': '222 84% 5%',
    '--foreground': '210 40% 98%',
    '--primary': '260 75% 65%',
    '--primary-foreground': '222 47% 11%',
    '--secondary': '142 76% 36%',
    '--secondary-foreground': '0 0% 100%',
    '--accent': '24 95% 53%',
    '--accent-foreground': '0 0% 100%',
    '--muted': '217 33% 18%',
    '--muted-foreground': '215 20% 65%',
    '--card': '222 84% 5%',
    '--card-foreground': '210 40% 98%',
    '--border': '217 33% 18%',
    '--input': '217 33% 18%',
    '--ring': '260 75% 65%',
    '--gradient-hero': 'linear-gradient(135deg, hsl(260 75% 65% / 0.4) 0%, hsl(260 75% 55% / 0.3) 50%, hsl(142 76% 36% / 0.35) 100%)',
    '--gradient-primary': 'linear-gradient(135deg, hsl(260 75% 65%), hsl(250 75% 70%))',
    '--gradient-accent': 'linear-gradient(135deg, hsl(24 95% 53%), hsl(20 95% 58%))',
  },
  'blue-corporate': {
    '--background': '0 0% 100%',
    '--foreground': '210 15% 10%',
    '--primary': '211 100% 50%',
    '--primary-foreground': '0 0% 100%',
    '--secondary': '204 94% 94%',
    '--secondary-foreground': '211 100% 50%',
    '--accent': '208 100% 47%',
    '--accent-foreground': '0 0% 100%',
    '--muted': '214 32% 91%',
    '--muted-foreground': '210 11% 15%',
    '--card': '0 0% 100%',
    '--card-foreground': '210 15% 10%',
    '--border': '214 32% 91%',
    '--input': '214 32% 91%',
    '--ring': '211 100% 50%',
    '--gradient-hero': 'linear-gradient(135deg, hsl(211 100% 50% / 0.4) 0%, hsl(208 100% 47% / 0.3) 50%, hsl(204 94% 94% / 0.35) 100%)',
    '--gradient-primary': 'linear-gradient(135deg, hsl(211 100% 50%), hsl(208 100% 47%))',
    '--gradient-accent': 'linear-gradient(135deg, hsl(208 100% 47%), hsl(200 100% 50%))',
  },
  'green-nature': {
    '--background': '0 0% 100%',
    '--foreground': '210 15% 10%',
    '--primary': '142 71% 45%',
    '--primary-foreground': '0 0% 100%',
    '--secondary': '120 60% 50%',
    '--secondary-foreground': '0 0% 100%',
    '--accent': '84 81% 44%',
    '--accent-foreground': '0 0% 100%',
    '--muted': '138 76% 97%',
    '--muted-foreground': '142 11% 15%',
    '--card': '0 0% 100%',
    '--card-foreground': '210 15% 10%',
    '--border': '138 76% 97%',
    '--input': '138 76% 97%',
    '--ring': '142 71% 45%',
    '--gradient-hero': 'linear-gradient(135deg, hsl(142 71% 45% / 0.4) 0%, hsl(120 60% 50% / 0.3) 50%, hsl(84 81% 44% / 0.35) 100%)',
    '--gradient-primary': 'linear-gradient(135deg, hsl(142 71% 45%), hsl(120 60% 50%))',
    '--gradient-accent': 'linear-gradient(135deg, hsl(84 81% 44%), hsl(102 81% 47%))',
  },
  'purple-creative': {
    '--background': '0 0% 100%',
    '--foreground': '210 15% 10%',
    '--primary': '271 81% 56%',
    '--primary-foreground': '0 0% 100%',
    '--secondary': '296 85% 52%',
    '--secondary-foreground': '0 0% 100%',
    '--accent': '318 85% 52%',
    '--accent-foreground': '0 0% 100%',
    '--muted': '270 20% 98%',
    '--muted-foreground': '271 15% 25%',
    '--card': '0 0% 100%',
    '--card-foreground': '210 15% 10%',
    '--border': '270 20% 98%',
    '--input': '270 20% 98%',
    '--ring': '271 81% 56%',
    '--gradient-hero': 'linear-gradient(135deg, hsl(271 81% 56% / 0.4) 0%, hsl(296 85% 52% / 0.3) 50%, hsl(318 85% 52% / 0.35) 100%)',
    '--gradient-primary': 'linear-gradient(135deg, hsl(271 81% 56%), hsl(296 85% 52%))',
    '--gradient-accent': 'linear-gradient(135deg, hsl(318 85% 52%), hsl(340 85% 55%))',
  }
};

export const ThemeProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [theme, setTheme] = useState<ThemeVariant>(() => {
    if (typeof window !== 'undefined') {
      return (localStorage.getItem('prolean-theme') as ThemeVariant) || 'light';
    }
    return 'light';
  });

  useEffect(() => {
    const root = document.documentElement;
    const themeVars = themeVariants[theme];
    
    // Apply theme variables
    Object.entries(themeVars).forEach(([property, value]) => {
      root.style.setProperty(property, value);
    });
    
    // Apply dark class for specific themes
    if (theme === 'dark') {
      root.classList.add('dark');
    } else {
      root.classList.remove('dark');
    }
    
    // Store theme preference
    localStorage.setItem('prolean-theme', theme);
  }, [theme]);

  return (
    <ThemeContext.Provider value={{ theme, setTheme }}>
      {children}
    </ThemeContext.Provider>
  );
};

export const useTheme = () => {
  const context = useContext(ThemeContext);
  if (context === undefined) {
    throw new Error('useTheme must be used within a ThemeProvider');
  }
  return context;
};