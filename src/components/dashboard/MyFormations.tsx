import React, { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';
import { Input } from '@/components/ui/input';
import { BookOpen, Play, Clock, CheckCircle, Search, Filter } from 'lucide-react';

export const MyFormations = () => {
  const [searchTerm, setSearchTerm] = useState('');

  const formations = [
    {
      id: 1,
      titre: "Project Management Professional",
      description: "Formation complète en gestion de projet selon les standards PMI",
      progression: 85,
      statut: "en_cours",
      tempsTotal: "40h",
      tempsEcoule: "34h",
      modules: 8,
      modulesTermines: 7,
      prochainModule: "Module 8: Clôture de projet",
      dateInscription: "2024-01-15",
      dateLimite: "2024-03-15",
      certificat: true,
      image: "/api/placeholder/300/200"
    },
    {
      id: 2,
      titre: "Data Analysis & Visualization",
      description: "Analyse de données avec Python, R et Tableau",
      progression: 60,
      statut: "en_cours",
      tempsTotal: "35h",
      tempsEcoule: "21h",
      modules: 6,
      modulesTermines: 4,
      prochainModule: "Module 5: Machine Learning",
      dateInscription: "2024-02-01",
      dateLimite: "2024-04-01",
      certificat: true,
      image: "/api/placeholder/300/200"
    },
    {
      id: 3,
      titre: "Digital Marketing Strategy",
      description: "Stratégies marketing digital et réseaux sociaux",
      progression: 100,
      statut: "termine",
      tempsTotal: "25h",
      tempsEcoule: "25h",
      modules: 5,
      modulesTermines: 5,
      dateInscription: "2023-12-01",
      dateTerminaison: "2024-01-20",
      certificat: true,
      certificatObtenu: true,
      image: "/api/placeholder/300/200"
    },
    {
      id: 4,
      titre: "Lean Management",
      description: "Principes et outils du Lean Management",
      progression: 30,
      statut: "en_cours",
      tempsTotal: "20h",
      tempsEcoule: "6h",
      modules: 4,
      modulesTermines: 1,
      prochainModule: "Module 2: Value Stream Mapping",
      dateInscription: "2024-02-15",
      dateLimite: "2024-04-15",
      certificat: true,
      image: "/api/placeholder/300/200"
    },
    {
      id: 5,
      titre: "Leadership & Communication",
      description: "Développement des compétences de leadership",
      progression: 100,
      statut: "termine",
      tempsTotal: "30h",
      tempsEcoule: "30h",
      modules: 6,
      modulesTermines: 6,
      dateInscription: "2023-11-01",
      dateTerminaison: "2023-12-30",
      certificat: true,
      certificatObtenu: true,
      image: "/api/placeholder/300/200"
    }
  ];

  const getStatutBadge = (statut: string) => {
    switch (statut) {
      case 'en_cours':
        return <Badge variant="default">En cours</Badge>;
      case 'termine':
        return <Badge variant="secondary">Terminé</Badge>;
      case 'nouveau':
        return <Badge variant="outline">Nouveau</Badge>;
      default:
        return <Badge variant="outline">{statut}</Badge>;
    }
  };

  const filteredFormations = formations.filter(formation =>
    formation.titre.toLowerCase().includes(searchTerm.toLowerCase()) ||
    formation.description.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const formationsEnCours = filteredFormations.filter(f => f.statut === 'en_cours');
  const formationsTerminees = filteredFormations.filter(f => f.statut === 'termine');

  const FormationCard = ({ formation }: { formation: any }) => (
    <Card className="hover:shadow-md transition-shadow">
      <CardHeader>
        <div className="flex justify-between items-start">
          <div className="flex-1">
            <CardTitle className="text-lg mb-2">{formation.titre}</CardTitle>
            <p className="text-sm text-muted-foreground mb-3">{formation.description}</p>
            {getStatutBadge(formation.statut)}
          </div>
          <div className="text-right">
            <div className="text-2xl font-bold text-primary">{formation.progression}%</div>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <Progress value={formation.progression} className="h-2" />
        
        <div className="grid grid-cols-2 gap-4 text-sm">
          <div className="flex items-center gap-2">
            <Clock className="h-4 w-4 text-muted-foreground" />
            <span>{formation.tempsEcoule} / {formation.tempsTotal}</span>
          </div>
          <div className="flex items-center gap-2">
            <BookOpen className="h-4 w-4 text-muted-foreground" />
            <span>{formation.modulesTermines} / {formation.modules} modules</span>
          </div>
        </div>

        {formation.statut === 'en_cours' && (
          <div className="bg-muted p-3 rounded-lg">
            <p className="text-sm font-medium mb-1">Prochaine étape:</p>
            <p className="text-sm text-muted-foreground">{formation.prochainModule}</p>
          </div>
        )}

        {formation.certificatObtenu && (
          <div className="flex items-center gap-2 text-green-600">
            <CheckCircle className="h-4 w-4" />
            <span className="text-sm font-medium">Certificat obtenu</span>
          </div>
        )}

        <div className="flex gap-2">
          {formation.statut === 'en_cours' && (
            <Button className="flex-1">
              <Play className="h-4 w-4 mr-2" />
              Continuer
            </Button>
          )}
          {formation.statut === 'termine' && formation.certificatObtenu && (
            <Button variant="outline" className="flex-1">
              Voir le certificat
            </Button>
          )}
          <Button variant="outline" size="sm">
            Détails
          </Button>
        </div>
      </CardContent>
    </Card>
  );

  return (
    <div className="space-y-6">
      {/* Barre de recherche et filtres */}
      <div className="flex flex-col sm:flex-row gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Rechercher une formation..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="pl-10"
          />
        </div>
        <Button variant="outline">
          <Filter className="h-4 w-4 mr-2" />
          Filtrer
        </Button>
      </div>

      {/* Onglets */}
      <Tabs defaultValue="en_cours" className="w-full">
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="en_cours">
            En cours ({formationsEnCours.length})
          </TabsTrigger>
          <TabsTrigger value="terminees">
            Terminées ({formationsTerminees.length})
          </TabsTrigger>
          <TabsTrigger value="toutes">
            Toutes ({filteredFormations.length})
          </TabsTrigger>
        </TabsList>

        <TabsContent value="en_cours" className="mt-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {formationsEnCours.map((formation) => (
              <FormationCard key={formation.id} formation={formation} />
            ))}
          </div>
          {formationsEnCours.length === 0 && (
            <div className="text-center py-8">
              <BookOpen className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
              <p className="text-muted-foreground">Aucune formation en cours</p>
            </div>
          )}
        </TabsContent>

        <TabsContent value="terminees" className="mt-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {formationsTerminees.map((formation) => (
              <FormationCard key={formation.id} formation={formation} />
            ))}
          </div>
          {formationsTerminees.length === 0 && (
            <div className="text-center py-8">
              <CheckCircle className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
              <p className="text-muted-foreground">Aucune formation terminée</p>
            </div>
          )}
        </TabsContent>

        <TabsContent value="toutes" className="mt-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {filteredFormations.map((formation) => (
              <FormationCard key={formation.id} formation={formation} />
            ))}
          </div>
          {filteredFormations.length === 0 && (
            <div className="text-center py-8">
              <Search className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
              <p className="text-muted-foreground">Aucune formation trouvée</p>
            </div>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
};