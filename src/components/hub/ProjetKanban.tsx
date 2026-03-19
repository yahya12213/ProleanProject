import { useState, useEffect, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Calendar } from "@/components/ui/calendar";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Checkbox } from "@/components/ui/checkbox";
import { Plus, CalendarIcon, Settings, User } from "lucide-react";
import { format } from "date-fns";
import { fr } from "date-fns/locale";
import { cn } from "@/lib/utils";
import { useToast } from "@/hooks/use-toast";
import {
  Project,
  Action,
  calculateProjectProgress,
  getProgressColor,
  fetchProjects,
  fetchActions,
  createProject,
  fetchProfiles,
  formatDate,
  linkActionToProject,
  unlinkActionFromProject
} from "@/lib/project-utils";
import api from '@/services/api';

interface ProjectWithProgress extends Project {
  total_actions: number;
  completed_actions: number;
  progress_percentage: number;
}

export function ProjetKanban() {
  const [projects, setProjects] = useState<ProjectWithProgress[]>([]);
  const [allActions, setAllActions] = useState<Action[]>([]);
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false);
  const [isActionsDialogOpen, setIsActionsDialogOpen] = useState(false);
  const [selectedProject, setSelectedProject] = useState<ProjectWithProgress | null>(null);
  const [projectActions, setProjectActions] = useState<string[]>([]);
  const [selectedDate, setSelectedDate] = useState<Date>();
  const [isLoading, setIsLoading] = useState(true);
  const { toast } = useToast();

  // Form data pour nouveau projet
  const [newProject, setNewProject] = useState({
    nom: "",
    description: "",
    chef_projet_id: "",
    date_debut: "",
    date_fin_prevue: "",
    budget: "",
    priorite: "normale" as const
  });

  const loadData = useCallback(async () => {
    setIsLoading(true);
    try {
      const [projectsData, actionsData, profilesData] = await Promise.all([
        fetchProjects(),
        fetchActions(),
        fetchProfiles()
      ]);

      // Calculer la progression pour chaque projet
      const projectsWithProgress = await Promise.all(
        projectsData.map(async (project) => {
          // Remplacement par appel API Express
          const linkedActions = await api.getProjectActions(project.id);
          const totalActions = linkedActions.length;
          const completedActions = linkedActions.filter((la) => la.statut === "termine").length;
          const progressPercentage = calculateProjectProgress(totalActions, completedActions);

          return {
            ...project,
            total_actions: totalActions,
            completed_actions: completedActions,
            progress_percentage: progressPercentage
          };
        })
      );

      setProjects(projectsWithProgress);
      setAllActions(actionsData);
      setProfiles(profilesData);
    } catch (error) {
      toast({
        title: "Erreur",
        description: "Impossible de charger les données",
        variant: "destructive"
      });
    } finally {
      setIsLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleCreateProject = async () => {
    if (!newProject.nom || !newProject.chef_projet_id || !newProject.date_debut || !newProject.date_fin_prevue) {
      toast({
        title: "Erreur",
        description: "Veuillez remplir tous les champs obligatoires",
        variant: "destructive"
      });
      return;
    }

    try {
      const projectData = {
        id: '', // Temporary placeholder, replace with actual ID logic
        ...newProject,
        budget: newProject.budget ? parseFloat(newProject.budget) : null,
        progression_percent: 0,
        statut: "planifie" as const
      };

      await createProject(projectData);
      await loadData();
      
      setIsCreateDialogOpen(false);
      setNewProject({
        nom: "",
        description: "",
        chef_projet_id: "",
        date_debut: "",
        date_fin_prevue: "",
        budget: "",
        priorite: "normale"
      });
      
      toast({
        title: "Succès",
        description: "Projet créé avec succès"
      });
    } catch (error) {
      toast({
        title: "Erreur",
        description: "Impossible de créer le projet",
        variant: "destructive"
      });
    }
  };

  const handleOpenActionsDialog = async (project: ProjectWithProgress) => {
    setSelectedProject(project);
    
    // Récupérer les actions déjà liées à ce projet
    const linkedActions = await api.getProjectActions(project.id);
    setProjectActions(linkedActions?.map(la => la.action_id) || []);
    setIsActionsDialogOpen(true);
  };

  const handleToggleAction = async (actionId: string, isChecked: boolean) => {
    if (!selectedProject) return;

    try {
      if (isChecked) {
        await linkActionToProject(selectedProject.id, actionId);
        setProjectActions([...projectActions, actionId]);
      } else {
        await unlinkActionFromProject(selectedProject.id, actionId);
        setProjectActions(projectActions.filter(id => id !== actionId));
      }
    } catch (error) {
      toast({
        title: "Erreur",
        description: "Impossible de modifier les liaisons",
        variant: "destructive"
      });
    }
  };

  const handleSaveActions = async () => {
    await loadData(); // Recharger les données pour mettre à jour les progressions
    setIsActionsDialogOpen(false);
    toast({
      title: "Succès",
      description: "Actions mises à jour avec succès"
    });
  };

  if (isLoading) {
    return (
      <Card>
        <CardContent className="p-8">
          <div className="text-center">Chargement...</div>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold text-foreground">Gestion de Projet (Kanban)</h2>
        <Dialog open={isCreateDialogOpen} onOpenChange={setIsCreateDialogOpen}>
          <DialogTrigger asChild>
            <Button className="bg-blue-600 hover:bg-blue-700 text-white">
              <Plus className="h-4 w-4 mr-2" />
              Créer un projet
            </Button>
          </DialogTrigger>
          <DialogContent className="sm:max-w-lg">
            <DialogHeader>
              <DialogTitle>Créer un nouveau projet</DialogTitle>
              <DialogDescription>
                Créez une nouvelle carte projet
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4">
              <div>
                <Label htmlFor="nom">Nom du projet *</Label>
                <Input
                  id="nom"
                  value={newProject.nom}
                  onChange={(e) => setNewProject({ ...newProject, nom: e.target.value })}
                  placeholder="Nom du projet"
                />
              </div>
              
              <div>
                <Label htmlFor="description">Description</Label>
                <Textarea
                  id="description"
                  value={newProject.description}
                  onChange={(e) => setNewProject({ ...newProject, description: e.target.value })}
                  placeholder="Description du projet"
                />
              </div>
              
              <div>
                <Label>Chef de projet *</Label>
                <Select value={newProject.chef_projet_id} onValueChange={(value) => setNewProject({ ...newProject, chef_projet_id: value })}>
                  <SelectTrigger>
                    <SelectValue placeholder="Sélectionner le chef de projet" />
                  </SelectTrigger>
                  <SelectContent>
                    {profiles.map((profile) => (
                      <SelectItem key={profile.id} value={profile.id}>
                        {profile.prenom} {profile.nom}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label htmlFor="date_debut">Date de début *</Label>
                  <Input
                    id="date_debut"
                    type="date"
                    value={newProject.date_debut}
                    onChange={(e) => setNewProject({ ...newProject, date_debut: e.target.value })}
                  />
                </div>
                <div>
                  <Label htmlFor="date_fin_prevue">Date de fin prévue *</Label>
                  <Input
                    id="date_fin_prevue"
                    type="date"
                    value={newProject.date_fin_prevue}
                    onChange={(e) => setNewProject({ ...newProject, date_fin_prevue: e.target.value })}
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label htmlFor="budget">Budget</Label>
                  <Input
                    id="budget"
                    type="number"
                    value={newProject.budget}
                    onChange={(e) => setNewProject({ ...newProject, budget: e.target.value })}
                    placeholder="Budget en DH"
                  />
                </div>
                <div>
                  <Label>Priorité</Label>
                  <Select
                    value={newProject.priorite}
                    onValueChange={(value: 'basse' | 'normale' | 'haute') => setNewProject({ ...newProject, priorite: value })}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="normale">Normale</SelectItem>
                      <SelectItem value="haute">Haute</SelectItem>
                      <SelectItem value="urgente">Urgente</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setIsCreateDialogOpen(false)}>
                Annuler
              </Button>
              <Button onClick={handleCreateProject}>
                Créer le projet
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {/* Grille de cartes Kanban */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
        {projects.map((project) => (
          <Card key={project.id} className="hover:shadow-lg transition-shadow">
            <CardHeader className="pb-3">
              <div className="flex items-start justify-between">
                <CardTitle className="text-lg font-semibold line-clamp-2">
                  {project.nom}
                </CardTitle>
                <Badge variant={
                  project.priorite === "urgente" ? "destructive" :
                  project.priorite === "haute" ? "default" : "secondary"
                }>
                  {project.priorite}
                </Badge>
              </div>
              {project.description && (
                <p className="text-sm text-muted-foreground line-clamp-2">
                  {project.description}
                </p>
              )}
            </CardHeader>
            <CardContent className="space-y-4">
              {/* Barre de progression */}
              <div className="space-y-2">
                <div className="flex items-center justify-between text-sm">
                  <span className="text-muted-foreground">Avancement</span>
                  <span className="font-medium">{project.progress_percentage}%</span>
                </div>
                <Progress 
                  value={project.progress_percentage} 
                  className="h-2"
                />
              </div>

              {/* Résumé des actions */}
              <div className="text-sm text-muted-foreground">
                {project.completed_actions} / {project.total_actions} actions terminées
              </div>

              {/* Informations du projet */}
              <div className="space-y-2 text-sm">
                <div className="flex items-center gap-2">
                  <User className="h-4 w-4 text-muted-foreground" />
                  <span>{project.chef_projet_name}</span>
                </div>
                <div className="flex items-center gap-2">
                  <CalendarIcon className="h-4 w-4 text-muted-foreground" />
                  <span>{formatDate(project.date_debut)} - {formatDate(project.date_fin_prevue)}</span>
                </div>
                {project.budget && (
                  <div className="text-muted-foreground">
                    Budget: {project.budget.toLocaleString()} DH
                  </div>
                )}
              </div>

              {/* Actions */}
              <Button 
                variant="outline" 
                className="w-full"
                onClick={() => handleOpenActionsDialog(project)}
              >
                <Settings className="h-4 w-4 mr-2" />
                Gérer les actions
              </Button>
            </CardContent>
          </Card>
        ))}
      </div>

      {projects.length === 0 && (
        <Card>
          <CardContent className="text-center py-8 text-muted-foreground">
            Aucun projet créé
          </CardContent>
        </Card>
      )}

      {/* Dialog pour gérer les actions */}
      <Dialog open={isActionsDialogOpen} onOpenChange={setIsActionsDialogOpen}>
        <DialogContent className="sm:max-w-2xl max-h-[80vh] flex flex-col">
          <DialogHeader>
            <DialogTitle>Gérer les actions - {selectedProject?.nom}</DialogTitle>
            <DialogDescription>
              Sélectionnez les actions à associer à ce projet
            </DialogDescription>
          </DialogHeader>
          <div className="flex-1 overflow-y-auto space-y-2">
            {allActions.map((action) => (
              <div key={action.id} className="flex items-start space-x-3 p-3 border rounded-lg">
                <Checkbox
                  checked={projectActions.includes(action.id)}
                  onCheckedChange={(checked) => handleToggleAction(action.id, checked as boolean)}
                />
                <div className="flex-1 min-w-0">
                  <div className="font-medium">{action.titre}</div>
                  {action.description && (
                    <div className="text-sm text-muted-foreground mt-1">{action.description}</div>
                  )}
                  <div className="text-xs text-muted-foreground mt-1">
                    Responsable: {action.assigned_to_name} • 
                    Statut: {action.statut === "todo" ? "À faire" : action.statut === "en_cours" ? "En cours" : "Terminé"}
                  </div>
                </div>
              </div>
            ))}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setIsActionsDialogOpen(false)}>
              Annuler
            </Button>
            <Button onClick={handleSaveActions}>
              Sauvegarder
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}