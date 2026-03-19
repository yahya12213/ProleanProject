import { Button } from "@/components/ui/button";
import { useNavigate, useLocation } from "react-router-dom";
import { Home, Building2, User, Settings, CheckCircle, LogOut } from "lucide-react";
import { ThemeSelector } from "@/components/ui/theme-selector";
import { MobileDrawer, MobileDrawerSection } from "@/components/ui/mobile-drawer";
import { useToast } from "@/hooks/use-toast";
import { useState, useEffect } from "react";

const MainNavigation = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { toast } = useToast();
  const [session, setSession] = useState<Session | null>(null);
  const [userEmail, setUserEmail] = useState<string>('');

  useEffect(() => {
    setUserEmail(session?.user?.email || '');

    // Écouter les changements d'authentification via l'API Express
    const fetchSession = async () => {
      const response = await fetch('/api/auth/session');
      const data = await response.json();
      setSession(data.session);
      setUserEmail(data.session?.user?.email || '');
    };

    fetchSession();

    return () => {
      // Pas de désabonnement nécessaire pour une API Express
    };
  }, [session]);

  const isActive = (path: string) => location.pathname === path;

  const handleLogout = async () => {
    try {
      // TODO: Remplacer par appel à l'API Express locale
      if (error) throw error;
      
      toast({
        title: "Déconnexion réussie",
        description: "Vous avez été déconnecté avec succès",
      });
      
      navigate('/auth');
    } catch (error) {
      console.error('Erreur lors de la déconnexion:', error);
      toast({
        title: "Erreur",
        description: "Impossible de se déconnecter",
        variant: "destructive",
      });
    }
  };

  const navigationItems = [
    { path: '/dashboard', label: 'Tableau de bord', icon: Home },
    { path: '/hub-gestion', label: 'Hub de Gestion', icon: Building2 },
    { path: '/mon-espace', label: 'Mon Espace', icon: User },
    { path: '/validation-demandes', label: 'Validation des demandes', icon: CheckCircle },
    { path: '/administration', label: 'Administration', icon: Settings },
  ];

  return (
    <div className="flex items-center gap-2">
      {/* Desktop Navigation - Always visible */}
      <div className="hidden sm:flex items-center gap-2">
        {navigationItems.map(({ path, label, icon: Icon }) => (
          <Button 
            key={path}
            variant={isActive(path) ? "default" : "ghost"}
            size="sm" 
            className="text-foreground hover:text-primary hover:scale-105 transition-all duration-300"
            onClick={() => navigate(path)}
          >
            <Icon className="h-4 w-4 mr-2" />
            {label}
          </Button>
        ))}
        
        {/* Theme Selector and User Info */}
        <div className="flex flex-col items-center gap-1 ml-2 border-l pl-2">
          <div className="flex items-center gap-2">
            <ThemeSelector className="scale-90" />
            <Button 
              variant="ghost"
              size="sm" 
              className="text-foreground hover:text-destructive hover:scale-105 transition-all duration-300"
              onClick={handleLogout}
              title="Se déconnecter"
            >
              <LogOut className="h-4 w-4" />
            </Button>
          </div>
          {userEmail && (
            <div className="text-xs text-muted-foreground text-center max-w-[120px] truncate">
              {userEmail}
            </div>
          )}
        </div>
      </div>

      {/* Mobile Navigation */}
      <div className="sm:hidden flex items-center gap-2">
        <MobileDrawer title="Navigation">
          <MobileDrawerSection title="Pages principales">
            {navigationItems.map(({ path, label, icon: Icon }) => (
              <Button 
                key={path}
                variant={isActive(path) ? "default" : "ghost"}
                size="sm" 
                className="w-full justify-start"
                onClick={() => navigate(path)}
              >
                <Icon className="h-4 w-4 mr-2" />
                {label}
              </Button>
            ))}
          </MobileDrawerSection>
          
          <MobileDrawerSection title="Paramètres">
            {userEmail && (
              <div className="text-sm text-muted-foreground mb-2 p-2 bg-muted/50 rounded">
                Connecté: {userEmail}
              </div>
            )}
            <ThemeSelector />
            <Button 
              variant="ghost"
              size="sm" 
              className="w-full justify-start text-destructive hover:text-destructive"
              onClick={handleLogout}
            >
              <LogOut className="h-4 w-4 mr-2" />
              Se déconnecter
            </Button>
          </MobileDrawerSection>
        </MobileDrawer>
      </div>
    </div>
  );
};

export default MainNavigation;