import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Building2 } from "lucide-react";
import MainNavigation from "@/components/MainNavigation";
import { ThemeSelector } from "@/components/ui/theme-selector";
import { useNavigation } from "@/contexts/NavigationContext";
import { Breadcrumbs } from "@/components/Breadcrumbs";
import { PilotageCommercial } from "@/components/hub/PilotageCommercial";
import { GestionProjet } from "@/components/hub/GestionProjet";
import { CrmProspects } from "@/components/hub/CrmProspects";
import { GestionRecrutement } from "@/components/hub/GestionRecrutement";
import { PortailEmployeRh } from "@/components/hub/PortailEmployeRh";
import { CommunicationInterne } from "@/components/hub/CommunicationInterne";
import { 
  TrendingUp, 
  FolderKanban, 
  Users, 
  UserCheck, 
  Calendar, 
  MessageCircle 
} from "lucide-react";

export default function HubGestion() {
  const [activeTab, setActiveTab] = useState("pilotage");
  const { setBreadcrumbs } = useNavigation();

  useEffect(() => {
    setBreadcrumbs([
      { label: 'Hub de Gestion', path: '/hub-gestion' }
    ]);
  }, [setBreadcrumbs]);

  const modules = [
    {
      id: "pilotage",
      label: "Pilotage Commercial",
      icon: TrendingUp,
      description: "Tableau de bord et performance des ventes"
    },
    {
      id: "projet",
      label: "Gestion de Projet",
      icon: FolderKanban,
      description: "Plans d'action et suivi des tâches"
    },
    {
      id: "crm",
      label: "CRM Prospects",
      icon: Users,
      description: "Gestion de la relation prospect"
    },
    {
      id: "recrutement",
      label: "ATS Recrutement",
      icon: UserCheck,
      description: "Gestion du pipeline de recrutement"
    },
    {
      id: "rh",
      label: "Portail Employé RH",
      icon: Calendar,
      description: "Services RH en libre-service"
    },
    {
      id: "communication",
      label: "Communication",
      icon: MessageCircle,
      description: "Communication interne et collaboration"
    }
  ];

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b bg-white shadow-soft">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-6">
              <h1 className="text-2xl font-heading font-bold text-gradient flex items-center gap-2">
                <Building2 className="h-6 w-6" />
                Hub de Gestion
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
          <h2 className="text-xl sm:text-2xl md:text-3xl font-heading font-bold text-foreground mb-2">
            Interface personnalisée pour les collaborateurs PRF et commerciaux
          </h2>
          <p className="text-sm sm:text-base text-muted-foreground">
            Accédez à tous vos outils de gestion quotidienne
          </p>
        </div>
        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
          {/* Responsive Navigation - Scrollable on mobile */}
          <div className="w-full overflow-x-auto">
            <TabsList className="grid w-full grid-cols-2 sm:grid-cols-3 md:grid-cols-6 h-auto p-2 bg-muted/30 min-w-max">
              {modules.map((module) => (
                <TabsTrigger 
                  key={module.id} 
                  value={module.id}
                  className="flex flex-col items-center gap-2 sm:gap-3 h-16 sm:h-20 md:h-24 px-2 sm:px-4 py-2 sm:py-3 data-[state=active]:bg-primary/10 data-[state=active]:text-primary data-[state=active]:border-primary/20 data-[state=active]:shadow-sm hover:bg-muted/50 transition-all duration-200 min-w-[100px] sm:min-w-[120px]"
                >
                  <module.icon className="h-4 w-4 sm:h-5 sm:w-5 md:h-6 md:w-6 text-current" />
                  <span className="text-xs font-medium text-center leading-tight">{module.label}</span>
                </TabsTrigger>
              ))}
            </TabsList>
          </div>

          <TabsContent value="pilotage" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <TrendingUp className="h-5 w-5" />
                  Pilotage Commercial
                </CardTitle>
                <CardDescription>
                  Tableau de bord de performance et gestion des déclarations commerciales
                </CardDescription>
              </CardHeader>
              <CardContent>
                <PilotageCommercial />
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="projet" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <FolderKanban className="h-5 w-5" />
                  Gestion de Projet
                </CardTitle>
                <CardDescription>
                  Organisation et suivi des tâches transverses et plans d'action
                </CardDescription>
              </CardHeader>
              <CardContent>
                <GestionProjet />
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="crm" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Users className="h-5 w-5" />
                  CRM - Gestion Prospects
                </CardTitle>
                <CardDescription>
                  Gestion du pipeline de vente et relation prospect
                </CardDescription>
              </CardHeader>
              <CardContent>
                <CrmProspects />
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="recrutement" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <UserCheck className="h-5 w-5" />
                  ATS - Gestion Recrutement
                </CardTitle>
                <CardDescription>
                  Gestion du pipeline de recrutement et suivi des candidatures
                </CardDescription>
              </CardHeader>
              <CardContent>
                <GestionRecrutement />
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="rh" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Calendar className="h-5 w-5" />
                  Portail Employé RH
                </CardTitle>
                <CardDescription>
                  Services RH en libre-service : pointage, congés, demandes
                </CardDescription>
              </CardHeader>
              <CardContent>
                <PortailEmployeRh />
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="communication" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <MessageCircle className="h-5 w-5" />
                  Communication Interne
                </CardTitle>
                <CardDescription>
                  Interface de chat et collaboration entre collaborateurs
                </CardDescription>
              </CardHeader>
              <CardContent>
                <CommunicationInterne />
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}