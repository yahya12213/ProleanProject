import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { Badge } from '@/components/ui/badge';
import { BookOpen, Trophy, Calendar, MessageSquare, Clock, Target } from 'lucide-react';

export const PersonalDashboard = () => {
  const stats = {
    formationsEnCours: 3,
    formationsTerminees: 7,
    certificatsObtenus: 5,
    tempsEtude: 47,
    prochaineCertification: "Lean Management",
    progressionGlobale: 68
  };

  const formationsRecentes = [
    { id: 1, titre: "Project Management", progression: 85, prochainModule: "Module 4: Risk Management" },
    { id: 2, titre: "Data Analysis", progression: 60, prochainModule: "Module 3: Advanced Statistics" },
    { id: 3, titre: "Digital Marketing", progression: 30, prochainModule: "Module 2: SEO Fundamentals" }
  ];

  const notifications = [
    { id: 1, type: "formation", message: "Nouveau module disponible en Project Management", date: "Il y a 2 heures" },
    { id: 2, type: "certificat", message: "Félicitations ! Certificat Data Analysis disponible", date: "Il y a 1 jour" },
    { id: 3, type: "rappel", message: "N'oubliez pas votre session prévue demain à 14h", date: "Il y a 2 jours" }
  ];

  return (
    <div className="space-y-6">
      {/* Vue d'ensemble */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card className="dashboard-card">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Formations en cours</CardTitle>
            <BookOpen className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-primary">{stats.formationsEnCours}</div>
            <p className="text-xs text-muted-foreground">+2 ce mois-ci</p>
          </CardContent>
        </Card>

        <Card className="dashboard-card">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Certificats obtenus</CardTitle>
            <Trophy className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-primary">{stats.certificatsObtenus}</div>
            <p className="text-xs text-muted-foreground">+1 cette semaine</p>
          </CardContent>
        </Card>

        <Card className="dashboard-card">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Temps d'étude</CardTitle>
            <Clock className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-primary">{stats.tempsEtude}h</div>
            <p className="text-xs text-muted-foreground">Ce mois-ci</p>
          </CardContent>
        </Card>

        <Card className="dashboard-card">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Progression globale</CardTitle>
            <Target className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-primary">{stats.progressionGlobale}%</div>
            <Progress value={stats.progressionGlobale} className="mt-2" />
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Formations en cours */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <BookOpen className="h-5 w-5" />
              Mes formations en cours
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {formationsRecentes.map((formation) => (
              <div key={formation.id} className="space-y-2">
                <div className="flex justify-between items-center">
                  <h4 className="font-medium">{formation.titre}</h4>
                  <Badge variant="secondary">{formation.progression}%</Badge>
                </div>
                <Progress value={formation.progression} className="h-2" />
                <p className="text-sm text-muted-foreground">
                  Prochaine étape: {formation.prochainModule}
                </p>
              </div>
            ))}
          </CardContent>
        </Card>

        {/* Notifications récentes */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <MessageSquare className="h-5 w-5" />
              Notifications récentes
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {notifications.map((notification) => (
              <div key={notification.id} className="border-l-4 border-primary pl-4 py-2">
                <p className="text-sm font-medium">{notification.message}</p>
                <p className="text-xs text-muted-foreground">{notification.date}</p>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      {/* Prochaine certification */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Calendar className="h-5 w-5" />
            Prochaine certification
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-lg font-semibold">{stats.prochaineCertification}</h3>
              <p className="text-muted-foreground">Examen prévu le 15 Mars 2024</p>
            </div>
            <Badge variant="outline">En préparation</Badge>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};