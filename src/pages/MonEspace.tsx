import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useNavigation } from "@/contexts/NavigationContext";
import { Breadcrumbs } from "@/components/Breadcrumbs";
import { 
  BookOpen, 
  User, 
  Award, 
  Calendar, 
  MessageSquare, 
  HelpCircle, 
  BarChart3, 
  FileText,
  Bell
} from "lucide-react";
import { PersonalDashboard } from '@/components/dashboard/PersonalDashboard';
import { MyFormations } from '@/components/dashboard/MyFormations';
import { MyProfile } from '@/components/dashboard/MyProfile';
import { MyCertificates } from '@/components/dashboard/MyCertificates';
import MainNavigation from "@/components/MainNavigation";

const MonEspace = () => {
  const [activeTab, setActiveTab] = useState("dashboard");
  const { setBreadcrumbs } = useNavigation();

  useEffect(() => {
    setBreadcrumbs([
      { label: 'Mon Espace', path: '/mon-espace' }
    ]);
  }, [setBreadcrumbs]);

  const espaceModules = [
    {
      id: "dashboard",
      title: "Dashboard",
      description: "Vue d'ensemble de votre progression et statistiques",
      icon: BarChart3,
      color: "text-blue-600"
    },
    {
      id: "formations",
      title: "Mes formations",
      description: "Accédez à vos formations en cours et consultez votre progression",
      icon: BookOpen,
      color: "text-green-600"
    },
    {
      id: "profil",
      title: "Mon profil",
      description: "Gérez vos informations personnelles et vos préférences",
      icon: User,
      color: "text-purple-600"
    },
    {
      id: "certificats",
      title: "Mes certificats",
      description: "Consultez et téléchargez vos certificats obtenus",
      icon: Award,
      color: "text-yellow-600"
    },
    {
      id: "notes",
      title: "Mes notes",
      description: "Prenez et organisez vos notes de cours",
      icon: FileText,
      color: "text-indigo-600"
    },
    {
      id: "planning",
      title: "Planning",
      description: "Consultez votre planning de formations et sessions",
      icon: Calendar,
      color: "text-cyan-600"
    },
    {
      id: "messagerie",
      title: "Messagerie",
      description: "Communiquez avec vos formateurs et autres apprenants",
      icon: MessageSquare,
      color: "text-orange-600"
    },
    {
      id: "support",
      title: "Support",
      description: "Trouvez de l'aide et consultez les FAQ",
      icon: HelpCircle,
      color: "text-red-600"
    }
  ];

  const renderTabContent = () => {
    switch (activeTab) {
      case 'dashboard':
        return <PersonalDashboard />;
      case 'formations':
        return <MyFormations />;
      case 'profil':
        return <MyProfile />;
      case 'certificats':
        return <MyCertificates />;
      case 'notes':
        return <MyNotesPlaceholder />;
      case 'planning':
        return <MyPlanningPlaceholder />;
      case 'messagerie':
        return <MyMessagingPlaceholder />;
      case 'support':
        return <MySupportPlaceholder />;
      default:
        return <PersonalDashboard />;
    }
  };

  return (
    <div className="min-h-screen bg-neutral">
      {/* Header */}
      <header className="border-b bg-white shadow-soft">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-6">
              <h1 className="text-2xl font-heading font-bold text-gradient flex items-center gap-2">
                <User className="h-6 w-6" />
                Mon Espace
              </h1>
            </div>
            <MainNavigation />
          </div>
        </div>
      </header>

      <div className="p-6">
        <Breadcrumbs />
      </div>

      <div className="container mx-auto px-6 py-8">
        {/* Welcome Section */}
        <div className="mb-8">
          <h2 className="text-3xl font-heading font-bold text-foreground mb-2">
            Bienvenue dans votre espace de travail
          </h2>
          <p className="text-muted-foreground">
            Accédez à tous vos outils de travail personnalisés selon votre rôle
          </p>
        </div>

        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
          {/* Navigation Tabs */}
          <TabsList className="grid w-full grid-cols-4 lg:grid-cols-8 h-auto p-1">
            {espaceModules.map((module) => {
              const IconComponent = module.icon;
              return (
                <TabsTrigger
                  key={module.id}
                  value={module.id}
                  className="flex flex-col items-center gap-1 py-3 px-2 text-xs"
                >
                  <IconComponent className={`h-4 w-4 ${module.color}`} />
                  <span className="hidden sm:inline">{module.title.split(' ')[0]}</span>
                </TabsTrigger>
              );
            })}
          </TabsList>

          {/* Content */}
          <div className="tab-content">
            {renderTabContent()}
          </div>
        </Tabs>
      </div>
    </div>
  );
};

// Composants placeholder pour les modules non encore implémentés
const MyNotesPlaceholder = () => (
  <Card>
    <CardHeader>
      <CardTitle className="flex items-center gap-2">
        <FileText className="h-5 w-5" />
        Mes notes
      </CardTitle>
    </CardHeader>
    <CardContent>
      <div className="text-center py-8">
        <FileText className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
        <h3 className="text-lg font-medium mb-2">Module en développement</h3>
        <p className="text-muted-foreground">Le module de prise de notes sera bientôt disponible.</p>
      </div>
    </CardContent>
  </Card>
);

const MyPlanningPlaceholder = () => (
  <Card>
    <CardHeader>
      <CardTitle className="flex items-center gap-2">
        <Calendar className="h-5 w-5" />
        Mon planning
      </CardTitle>
    </CardHeader>
    <CardContent>
      <div className="text-center py-8">
        <Calendar className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
        <h3 className="text-lg font-medium mb-2">Module en développement</h3>
        <p className="text-muted-foreground">Le module de planning sera bientôt disponible.</p>
      </div>
    </CardContent>
  </Card>
);

const MyMessagingPlaceholder = () => (
  <Card>
    <CardHeader>
      <CardTitle className="flex items-center gap-2">
        <MessageSquare className="h-5 w-5" />
        Messagerie
      </CardTitle>
    </CardHeader>
    <CardContent>
      <div className="text-center py-8">
        <MessageSquare className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
        <h3 className="text-lg font-medium mb-2">Module en développement</h3>
        <p className="text-muted-foreground">Le module de messagerie sera bientôt disponible.</p>
      </div>
    </CardContent>
  </Card>
);

const MySupportPlaceholder = () => (
  <Card>
    <CardHeader>
      <CardTitle className="flex items-center gap-2">
        <HelpCircle className="h-5 w-5" />
        Support
      </CardTitle>
    </CardHeader>
    <CardContent>
      <div className="text-center py-8">
        <HelpCircle className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
        <h3 className="text-lg font-medium mb-2">Module en développement</h3>
        <p className="text-muted-foreground">Le module de support sera bientôt disponible.</p>
      </div>
    </CardContent>
  </Card>
);

export default MonEspace;