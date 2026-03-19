import { useState, useEffect } from "react";
import { useLocation } from "react-router-dom";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useNavigation } from "@/contexts/NavigationContext";
import { Breadcrumbs } from "@/components/Breadcrumbs";
import { 
  Users, 
  Shield, 
  MapPin, 
  Clock, 
  CheckCircle, 
  BookOpen, 
  FileText,
  Settings
} from "lucide-react";
import UserManagement from "@/components/admin/UserManagement";
import RoleManagement from "@/components/admin/RoleManagement";
import SegmentManagement from "@/components/admin/SegmentManagement";

import ScheduleManagement from "@/components/admin/ScheduleManagement";
import GestionRH from "@/components/admin/GestionRH";
import { RefactoredDemandeValidation } from "@/components/admin/RefactoredDemandeValidation";
import InterviewTemplates from "@/components/admin/InterviewTemplates";
import { TrainingManagement } from "@/components/admin/TrainingManagement";
import MainNavigation from "@/components/MainNavigation";
import { ThemeSelector } from "@/components/ui/theme-selector";

const Administration = () => {
  const [activeTab, setActiveTab] = useState("users");
  const location = useLocation();
  const { setBreadcrumbs } = useNavigation();

  useEffect(() => {
    // Check if we should set a specific tab from navigation state
    if (location.state?.activeTab) {
      setActiveTab(location.state.activeTab);
    }
    
    setBreadcrumbs([
      { label: 'Administration', path: '/administration' }
    ]);
  }, [location.state, setBreadcrumbs]);

  const adminModules = [
    {
      id: "users",
      title: "Gestion des Utilisateurs",
      description: "Gérer les comptes utilisateurs de la plateforme",
      icon: Users,
      color: "text-blue-600"
    },
    {
      id: "roles",
      title: "Gestion des Rôles et Permissions",
      description: "Définir les niveaux d'accès et permissions",
      icon: Shield,
      color: "text-purple-600"
    },
    {
      id: "segments",
      title: "Gestion des Segments",
      description: "Configurer les marques et villes",
      icon: MapPin,
      color: "text-green-600"
    },
    {
      id: "validation",
      title: "Gestion RH",
      description: "Configurer les circuits d'approbation",
      icon: CheckCircle,
      color: "text-cyan-600"
    },
    {
      id: "formations",
      title: "Gestion des Formations",
      description: "Gérer l'offre de formation",
      icon: BookOpen,
      color: "text-red-600"
    },
    {
      id: "interviews",
      title: "Fiches d'Entretien",
      description: "Standardiser les processus de recrutement",
      icon: FileText,
      color: "text-yellow-600"
    }
  ];

  return (
    <div className="min-h-screen bg-neutral">
      {/* Header */}
      <header className="border-b bg-white shadow-soft">
        <div className="container mx-auto px-6 py-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-6">
                <h1 className="text-2xl font-heading font-bold text-gradient flex items-center gap-2">
                  <Settings className="h-6 w-6" />
                  Administration
                </h1>
              </div>
              <div className="flex items-center gap-4">
                <MainNavigation />
              </div>
            </div>
        </div>
      </header>

      <div className="p-6">
        <Breadcrumbs />
      </div>

      <div className="container mx-auto px-3 sm:px-6 py-4 sm:py-8">
        {/* Welcome Section */}
        <div className="mb-6 sm:mb-8">
          <h2 className="text-2xl sm:text-3xl font-heading font-bold text-foreground mb-2">
            Centre d'administration PROLEAN
          </h2>
          <p className="text-sm sm:text-base text-muted-foreground">
            Configurez et gérez tous les aspects de votre plateforme de formation
          </p>
        </div>

        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
          {/* Navigation Tabs - Responsive Grid */}
          <div className="w-full overflow-x-auto">
            <TabsList className="grid w-full grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 xl:grid-cols-8 h-auto p-1 gap-1 min-w-max">
              {adminModules.map((module) => {
                const IconComponent = module.icon;
                return (
                  <TabsTrigger
                    key={module.id}
                    value={module.id}
                    className="flex flex-col items-center justify-center gap-1 sm:gap-2 py-2 sm:py-3 px-1 sm:px-2 text-xs sm:text-xs min-h-[70px] sm:min-h-[90px] text-center min-w-[80px] sm:min-w-[100px]"
                  >
                    <IconComponent className={`h-4 w-4 sm:h-5 sm:w-5 ${module.color} flex-shrink-0`} />
                    <span className="text-center leading-tight font-medium break-words hyphens-auto max-w-full overflow-hidden text-xs">
                      {module.title}
                    </span>
                  </TabsTrigger>
                );
              })}
            </TabsList>
          </div>

          {/* Content Areas */}
          {adminModules.map((module) => {
            const IconComponent = module.icon;
            return (
              <TabsContent key={module.id} value={module.id}>
                {module.id === "users" ? (
                  <UserManagement />
                ) : module.id === "roles" ? (
                  <RoleManagement />
                ) : module.id === "segments" ? (
                  <SegmentManagement />
                ) : module.id === "validation" ? (
                  <GestionRH />
                ) : module.id === "formations" ? (
                  <TrainingManagement />
                ) : module.id === "interviews" ? (
                  <InterviewTemplates />
                ) : (
                  <Card>
                    <CardHeader>
                      <CardTitle className="flex items-center gap-2">
                        <IconComponent className={`h-5 w-5 ${module.color}`} />
                        {module.title}
                      </CardTitle>
                      <CardDescription>{module.description}</CardDescription>
                    </CardHeader>
                    <CardContent>
                      <div className="text-center py-12">
                        <IconComponent className={`h-16 w-16 mx-auto mb-4 ${module.color} opacity-50`} />
                        <h3 className="text-lg font-semibold mb-2">Module {module.title}</h3>
                        <p className="text-muted-foreground mb-4">
                          Ce module sera développé prochainement.
                        </p>
                        <Button variant="outline" size="sm">
                          Commencer la configuration
                        </Button>
                      </div>
                    </CardContent>
                  </Card>
                )}
              </TabsContent>
            );
          })}
        </Tabs>
      </div>
    </div>
  );
};

export default Administration;