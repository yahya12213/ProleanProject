import React from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useNavigate } from "react-router-dom";
import { LogOut, Users, BookOpen, UserPlus, DollarSign, TrendingUp, TrendingDown, Plus, FileText, BarChart3 } from "lucide-react";
import { toast } from "@/hooks/use-toast";
import MainNavigation from "@/components/MainNavigation";
import { useNavigation } from "@/contexts/NavigationContext";
import { Breadcrumbs } from "@/components/Breadcrumbs";

const Dashboard = () => {
  const navigate = useNavigate();
  const { setBreadcrumbs } = useNavigation();

  React.useEffect(() => {
    setBreadcrumbs([
      { label: 'Tableau de bord', path: '/dashboard' }
    ]);
  }, [setBreadcrumbs]);

  const handleLogout = async () => {
  // TODO: Remplacer par appel à l'API Express locale
    navigate('/');
    toast({
      title: "Déconnexion réussie",
      description: "Vous avez été déconnecté avec succès.",
    });
  };

  return (
    <div className="min-h-screen bg-background">
      <div className="border-b">
        <div className="flex h-16 items-center px-4">
          <div className="flex items-center gap-2">
            <h1 className="text-lg font-semibold">PROLEAN Dashboard</h1>
          </div>
          <div className="ml-auto flex items-center gap-4">
            <MainNavigation />
          </div>
        </div>
      </div>

      <div className="p-6">
        <Breadcrumbs />
      </div>

      <main className="flex-1 p-3 sm:p-6">
        <div className="mb-6 sm:mb-8">
          <h2 className="text-2xl sm:text-3xl font-bold mb-2">
            Bienvenue sur votre tableau de bord
          </h2>
          <p className="text-sm sm:text-base text-muted-foreground">
            Gérez votre plateforme de formations et suivez vos statistiques
          </p>
        </div>

        <div className="responsive-grid mb-8">
          <div className="stat-card">
            <div className="stat-header">
              <span className="stat-label">Utilisateurs totaux</span>
              <Users className="stat-icon" />
            </div>
            <div className="stat-value">1,234</div>
            <div className="stat-change positive">
              <TrendingUp className="h-3 w-3 mr-1" />
              +20.1% par rapport au mois dernier
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-header">
              <span className="stat-label">Formations actives</span>
              <BookOpen className="stat-icon" />
            </div>
            <div className="stat-value">12</div>
            <div className="stat-change neutral">
              +2 nouvelles cette semaine
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-header">
              <span className="stat-label">Inscriptions ce mois</span>
              <UserPlus className="stat-icon" />
            </div>
            <div className="stat-value">89</div>
            <div className="stat-change positive">
              <TrendingUp className="h-3 w-3 mr-1" />
              +12% par rapport au mois dernier
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-header">
              <span className="stat-label">Revenus totaux</span>
              <DollarSign className="stat-icon" />
            </div>
            <div className="stat-value">€45,231</div>
            <div className="stat-change positive">
              <TrendingUp className="h-3 w-3 mr-1" />
              +25.1% par rapport au mois dernier
            </div>
          </div>
        </div>

        <div className="responsive-grid grid-cols-1 xl:grid-cols-2">
          <Card className="card-enhanced animate-fade-in">
            <CardHeader>
              <CardTitle className="text-lg sm:text-xl">Actions rapides</CardTitle>
              <CardDescription className="text-sm">
                Gérez votre plateforme efficacement
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <button className="btn-enhanced btn-primary w-full justify-start">
                <Plus className="h-4 w-4 mr-2" />
                Créer une nouvelle formation
              </button>
              <button className="btn-enhanced btn-secondary w-full justify-start">
                <Users className="h-4 w-4 mr-2" />
                Gérer les utilisateurs
              </button>
              <button className="btn-enhanced btn-secondary w-full justify-start">
                <FileText className="h-4 w-4 mr-2" />
                Voir les rapports détaillés
              </button>
            </CardContent>
          </Card>

          <Card className="card-enhanced animate-fade-in">
            <CardHeader>
              <CardTitle>Activité récente</CardTitle>
              <CardDescription>
                Dernières actions sur la plateforme
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-6">
                <div className="activity-item animate-slide-in">
                  <div className="activity-indicator status-success"></div>
                  <div className="activity-content">
                    <p className="activity-title">Nouvelle inscription</p>
                    <p className="activity-time">Il y a 2 minutes</p>
                  </div>
                </div>
                <div className="activity-item animate-slide-in">
                  <div className="activity-indicator status-warning"></div>
                  <div className="activity-content">
                    <p className="activity-title">Formation "Marketing Digital" mise à jour</p>
                    <p className="activity-time">Il y a 1 heure</p>
                  </div>
                </div>
                <div className="activity-item animate-slide-in">
                  <div className="activity-indicator status-info"></div>
                  <div className="activity-content">
                    <p className="activity-title">5 nouveaux certificats émis</p>
                    <p className="activity-time">Il y a 3 heures</p>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </main>
    </div>
  );
};

export default Dashboard;