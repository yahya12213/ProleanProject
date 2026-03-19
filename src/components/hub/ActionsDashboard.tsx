import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { TrendingUp, AlertTriangle, Clock, CheckCircle, Target, Users } from "lucide-react";

interface ActionStats {
  total: number;
  completed: number;
  inProgress: number;
  todo: number;
  overdue: number;
  dueSoon: number;
  progressPercent: number;
  topPilots: Array<{ name: string; count: number }>;
}

interface ActionsDashboardProps {
  stats: ActionStats;
}

export function ActionsDashboard({ stats }: ActionsDashboardProps) {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 grid-spacing mb-6 animate-fade-in">
      {/* Progression Globale */}
      <Card className="stat-card">
        <div className="flex items-center gap-4 p-6">
          <div className="stat-icon">
            <TrendingUp className="h-6 w-6 text-primary" />
          </div>
          <div className="flex-1">
            <p className="stat-label">Progression Globale</p>
            <p className="stat-value">{stats.progressPercent}%</p>
            <Progress value={stats.progressPercent} className="w-full mt-3 h-2" />
            <p className="text-xs text-muted-foreground mt-2">
              {stats.completed} sur {stats.total} actions terminées
            </p>
          </div>
        </div>
      </Card>

      {/* Actions en Retard */}
      <Card className="stat-card">
        <div className="flex items-center gap-4 p-6">
          <div className="stat-icon bg-destructive/10 border-destructive/20">
            <AlertTriangle className="h-6 w-6 text-destructive" />
          </div>
          <div className="flex-1">
            <p className="stat-label">Actions en Retard</p>
            <p className="text-3xl font-bold tracking-tight text-destructive">{stats.overdue}</p>
            <p className="text-xs text-muted-foreground mt-1">
              Actions dépassant la date d'échéance
            </p>
          </div>
        </div>
      </Card>

      {/* Actions Dues Bientôt */}
      <Card className="stat-card">
        <div className="flex items-center gap-4 p-6">
          <div className="stat-icon bg-amber-50 border-amber-200 dark:bg-amber-950/30 dark:border-amber-800/30">
            <Clock className="h-6 w-6 text-amber-600 dark:text-amber-400" />
          </div>
          <div className="flex-1">
            <p className="stat-label">Dues dans 3 jours</p>
            <p className="text-3xl font-bold tracking-tight text-amber-600 dark:text-amber-400">{stats.dueSoon}</p>
            <p className="text-xs text-muted-foreground mt-1">
              Actions à traiter prioritairement
            </p>
          </div>
        </div>
      </Card>

      {/* Répartition par Statut */}
      <Card className="stat-card">
        <div className="p-6 space-y-4">
          <div className="flex items-center gap-3">
            <div className="stat-icon">
              <Target className="h-5 w-5 text-primary" />
            </div>
            <h3 className="font-semibold text-lg">Répartition</h3>
          </div>
          <div className="space-y-3">
            <div className="flex items-center justify-between p-3 rounded-lg bg-emerald-50 dark:bg-emerald-950/20 border border-emerald-200 dark:border-emerald-800/30">
              <div className="flex items-center gap-2">
                <CheckCircle className="h-4 w-4 text-emerald-600 dark:text-emerald-400" />
                <span className="text-sm font-medium text-emerald-700 dark:text-emerald-300">Terminé</span>
              </div>
              <span className="font-bold text-lg text-emerald-600 dark:text-emerald-400">{stats.completed}</span>
            </div>
            <div className="flex items-center justify-between p-3 rounded-lg bg-amber-50 dark:bg-amber-950/20 border border-amber-200 dark:border-amber-800/30">
              <span className="text-sm font-medium text-amber-700 dark:text-amber-300">En cours</span>
              <span className="font-bold text-lg text-amber-600 dark:text-amber-400">{stats.inProgress}</span>
            </div>
            <div className="flex items-center justify-between p-3 rounded-lg bg-muted/50 border border-border">
              <span className="text-sm font-medium text-muted-foreground">À faire</span>
              <span className="font-bold text-lg text-foreground">{stats.todo}</span>
            </div>
          </div>
        </div>
      </Card>

      {/* Top Pilotes - Prend 2 colonnes en mode large */}
      {stats.topPilots.length > 0 && (
        <Card className="stat-card lg:col-span-2">
          <div className="p-6 space-y-4">
            <div className="flex items-center gap-3">
              <div className="stat-icon">
                <Users className="h-5 w-5 text-primary" />
              </div>
              <h3 className="font-semibold text-lg">Top Pilotes (Actions à terminer)</h3>
            </div>
            <div className="space-y-3">
              {stats.topPilots.map((pilot, index) => (
                <div key={pilot.name} className="flex items-center justify-between p-3 rounded-lg bg-card/50 border border-border/50 hover:bg-primary/5 hover:border-primary/20 transition-all duration-200">
                  <div className="flex items-center gap-4">
                    <div className={`w-10 h-10 rounded-full flex items-center justify-center text-sm font-bold text-white ${
                      index === 0 ? 'bg-gradient-to-br from-amber-400 to-amber-600' : 
                      index === 1 ? 'bg-gradient-to-br from-gray-400 to-gray-600' : 'bg-gradient-to-br from-amber-500 to-amber-700'
                    }`}>
                      {index + 1}
                    </div>
                    <span className="font-semibold text-foreground">{pilot.name}</span>
                  </div>
                  <div className="text-right">
                    <span className="font-bold text-primary">{pilot.count}</span>
                    <span className="text-xs text-muted-foreground ml-1">action{pilot.count > 1 ? 's' : ''}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </Card>
      )}
    </div>
  );
}