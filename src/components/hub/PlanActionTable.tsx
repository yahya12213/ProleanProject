import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Calendar } from "@/components/ui/calendar";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger } from "@/components/ui/alert-dialog";
import { Plus, CalendarIcon, Search, Edit, Trash2, Lock } from "lucide-react";
import { format } from "date-fns";
import { fr } from "date-fns/locale";
import { cn } from "@/lib/utils";
import { useToast } from "@/hooks/use-toast";
import {
  Action,
  ACTION_STATUS_OPTIONS,
  getActionStatusColor,
  getRowColor,
  fetchActions,
  updateActionStatus,
  createAction,
  fetchProfiles,
  formatDate,
  calculateActionStats,
  deleteAction,
  canUserEditAction
} from "@/lib/project-utils";
import { ActionsDashboard } from "./ActionsDashboard";
import { EditActionModal } from "./EditActionModal";

export function PlanActionTable() {
  const [actions, setActions] = useState<Action[]>([]);
  const [profiles, setProfiles] = useState<any[]>([]);
  const [filteredProfiles, setFilteredProfiles] = useState<any[]>([]);
  const [isAddDialogOpen, setIsAddDialogOpen] = useState(false);
  const [isEditModalOpen, setIsEditModalOpen] = useState(false);
  const [selectedAction, setSelectedAction] = useState<Action | null>(null);
  const [selectedDate, setSelectedDate] = useState<Date>();
  const [isLoading, setIsLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");
  const [showDropdown, setShowDropdown] = useState(false);
  const [currentUserProfileId, setCurrentUserProfileId] = useState<string>("");
  const { toast } = useToast();

  // Form data pour nouvelle action
  const [newAction, setNewAction] = useState({
    titre: "",
    description: "",
    assigned_to_profile_id: "",
    assigned_by_profile_id: "",
    due_date: "",
    commentaire: ""
  });

  useEffect(() => {
    loadData();
  }, []);

  useEffect(() => {
    if (searchQuery === "") {
      setFilteredProfiles(profiles);
    } else {
      const filtered = profiles.filter(profile => 
        `${profile.prenom} ${profile.nom}`.toLowerCase().includes(searchQuery.toLowerCase())
      );
      setFilteredProfiles(filtered);
    }
  }, [searchQuery, profiles]);

  const loadData = async () => {
    setIsLoading(true);
    try {
      const [actionsData, profilesData] = await Promise.all([
        fetchActions(),
        fetchProfiles()
      ]);
      setActions(actionsData || []);
      setProfiles(profilesData || []);
      setFilteredProfiles(profilesData || []);
      
      // Définir l'utilisateur actuel (premier profil pour la démo)
      if (profilesData && profilesData.length > 0) {
        setCurrentUserProfileId(profilesData[0].id);
      }
    } catch (error) {
      toast({
        title: "Erreur",
        description: "Impossible de charger les données",
        variant: "destructive"
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleStatusChange = async (actionId: string, newStatus: string) => {
    try {
      await updateActionStatus(actionId, newStatus as any);
      setActions(actions.map(action => 
        action.id === actionId ? { ...action, statut: newStatus as any } : action
      ));
      toast({
        title: "Succès",
        description: "Statut mis à jour avec succès"
      });
    } catch (error) {
      toast({
        title: "Erreur",
        description: "Impossible de mettre à jour le statut",
        variant: "destructive"
      });
    }
  };

  const handleCreateAction = async () => {
    if (!newAction.titre || !newAction.assigned_to_profile_id) {
      toast({
        title: "Erreur",
        description: "Veuillez remplir les champs obligatoires",
        variant: "destructive"
      });
      return;
    }

    try {
      const actionData = {
        ...newAction,
        assigned_by_profile_id: profiles[0]?.id || newAction.assigned_to_profile_id,
        assigned_at: new Date().toISOString(),
        statut: "todo" as const,
        due_date: selectedDate ? selectedDate.toISOString().split('T')[0] : undefined
      };

      await createAction(actionData);
      await loadData();
      
      setIsAddDialogOpen(false);
      setNewAction({
        titre: "",
        description: "",
        assigned_to_profile_id: "",
        assigned_by_profile_id: "",
        due_date: "",
        commentaire: ""
      });
      setSelectedDate(undefined);
      setSearchQuery("");
      
      toast({
        title: "Succès",
        description: "Action créée avec succès"
      });
    } catch (error) {
      toast({
        title: "Erreur",
        description: "Impossible de créer l'action",
        variant: "destructive"
      });
    }
  };

  const handleEditAction = (action: Action) => {
    setSelectedAction(action);
    setIsEditModalOpen(true);
  };

  const handleDeleteAction = async (actionId: string) => {
    try {
      await deleteAction(actionId);
      await loadData();
      toast({
        title: "Succès",
        description: "Action supprimée avec succès"
      });
    } catch (error) {
      toast({
        title: "Erreur",
        description: "Impossible de supprimer l'action",
        variant: "destructive"
      });
    }
  };

  const getSelectedProfileName = () => {
    const selected = profiles.find(p => p.id === newAction.assigned_to_profile_id);
    return selected ? `${selected.prenom} ${selected.nom}` : "";
  };

  // Calculer les statistiques
  const actionStats = calculateActionStats(actions);

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
        <h2 className="text-2xl font-bold text-foreground">Plan d'Action</h2>
        <Dialog open={isAddDialogOpen} onOpenChange={setIsAddDialogOpen}>
          <DialogTrigger asChild>
            <Button className="bg-blue-600 hover:bg-blue-700 text-white">
              <Plus className="h-4 w-4 mr-2" />
              Ajouter une action
            </Button>
          </DialogTrigger>
          <DialogContent className="sm:max-w-lg">
            <DialogHeader>
              <DialogTitle>Créer une nouvelle action</DialogTitle>
              <DialogDescription>
                Ajoutez une nouvelle action au plan d'action
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4">
              <div>
                <Label htmlFor="titre">Description de l'action *</Label>
                <Input
                  id="titre"
                  value={newAction.titre}
                  onChange={(e) => setNewAction({ ...newAction, titre: e.target.value })}
                  placeholder="Description de l'action"
                />
              </div>
              
              <div>
                <Label htmlFor="description">Description détaillée</Label>
                <Textarea
                  id="description"
                  value={newAction.description}
                  onChange={(e) => setNewAction({ ...newAction, description: e.target.value })}
                  placeholder="Description détaillée"
                />
              </div>
              
              <div>
                <Label>Pilote (Responsable) *</Label>
                <div className="relative">
                  <div className="flex">
                    <Input
                      placeholder="Rechercher et sélectionner un utilisateur..."
                      value={getSelectedProfileName() || searchQuery}
                      onChange={(e) => {
                        setSearchQuery(e.target.value);
                        setShowDropdown(true);
                        if (!e.target.value) {
                          setNewAction({ ...newAction, assigned_to_profile_id: "" });
                        }
                      }}
                      onFocus={() => setShowDropdown(true)}
                      className="pr-10"
                    />
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      className="absolute right-0 top-0 h-full px-3"
                      onClick={() => setShowDropdown(!showDropdown)}
                    >
                      <Search className="h-4 w-4" />
                    </Button>
                  </div>
                  
                  {showDropdown && (
                    <div className="absolute z-50 w-full mt-1 bg-background border border-border rounded-md shadow-lg max-h-60 overflow-auto">
                      {filteredProfiles.length > 0 ? (
                        filteredProfiles.map((profile) => (
                          <div
                            key={profile.id}
                            className="px-3 py-2 hover:bg-muted cursor-pointer text-sm"
                            onClick={() => {
                              setNewAction({ ...newAction, assigned_to_profile_id: profile.id });
                              setSearchQuery("");
                              setShowDropdown(false);
                            }}
                          >
                            {profile.prenom} {profile.nom}
                          </div>
                        ))
                      ) : (
                        <div className="px-3 py-2 text-sm text-muted-foreground">
                          Aucun utilisateur trouvé
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>
              
              <div>
                <Label>Délai</Label>
                <Popover>
                  <PopoverTrigger asChild>
                    <Button
                      variant="outline"
                      className={cn(
                        "w-full justify-start text-left font-normal",
                        !selectedDate && "text-muted-foreground"
                      )}
                    >
                      <CalendarIcon className="mr-2 h-4 w-4" />
                      {selectedDate ? format(selectedDate, "dd/MM/yyyy", { locale: fr }) : "Sélectionner une date"}
                    </Button>
                  </PopoverTrigger>
                  <PopoverContent className="w-auto p-0">
                    <Calendar
                      mode="single"
                      selected={selectedDate}
                      onSelect={setSelectedDate}
                      initialFocus
                    />
                  </PopoverContent>
                </Popover>
              </div>

              <div>
                <Label htmlFor="commentaire">Commentaire</Label>
                <Textarea
                  id="commentaire"
                  value={newAction.commentaire}
                  onChange={(e) => setNewAction({ ...newAction, commentaire: e.target.value })}
                  placeholder="Commentaire"
                />
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setIsAddDialogOpen(false)}>
                Annuler
              </Button>
              <Button onClick={handleCreateAction}>
                Créer l'action
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {/* Tableau de bord des statistiques */}
      <ActionsDashboard stats={actionStats} />

      {/* Table */}
      <Card>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-muted/50 border-b">
                <tr>
                  <th className="text-left p-3 font-semibold text-muted-foreground">DESCRIPTION DE L'ACTION</th>
                  <th className="text-left p-3 font-semibold text-muted-foreground">PILOTE</th>
                  <th className="text-left p-3 font-semibold text-muted-foreground">AFFECTÉ PAR</th>
                  <th className="text-left p-3 font-semibold text-muted-foreground">DATE D'AFFECTATION</th>
                  <th className="text-left p-3 font-semibold text-muted-foreground">DÉLAI</th>
                  <th className="text-left p-3 font-semibold text-muted-foreground">ÉTAT D'AVANCEMENT</th>
                  <th className="text-left p-3 font-semibold text-muted-foreground">COMMENTAIRE</th>
                  <th className="text-left p-3 font-semibold text-muted-foreground">ACTIONS</th>
                </tr>
              </thead>
              <tbody>
                {actions.map((action) => {
                  const canEdit = canUserEditAction(action, currentUserProfileId);
                  const rowColorClass = getRowColor(action);
                  
                  return (
                    <tr 
                      key={action.id} 
                      className={cn(rowColorClass, "cursor-pointer")}
                      onClick={() => canEdit && handleEditAction(action)}
                    >
                      <td className="p-3">
                        <div>
                          <div className="font-medium">{action.titre}</div>
                          {action.description && (
                            <div className="text-sm text-muted-foreground mt-1">{action.description}</div>
                          )}
                        </div>
                      </td>
                      <td className="p-3">{action.assigned_to_name}</td>
                      <td className="p-3">{action.assigned_by_name}</td>
                      <td className="p-3">{formatDate(action.assigned_at)}</td>
                      <td className="p-3">
                        {action.due_date ? (
                          <div className="flex items-center gap-2">
                            {formatDate(action.due_date)}
                            {action.due_date && new Date(action.due_date) < new Date() && (
                              <span className="text-xs bg-destructive/10 text-destructive px-2 py-1 rounded">
                                En retard
                              </span>
                            )}
                          </div>
                        ) : "-"}
                      </td>
                      <td className="p-3">
                        <Select 
                          value={action.statut} 
                          onValueChange={(value) => handleStatusChange(action.id, value)}
                          disabled={!canEdit}
                        >
                          <SelectTrigger className={cn("w-32", getActionStatusColor(action.statut))}>
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            {ACTION_STATUS_OPTIONS.map((option) => (
                              <SelectItem key={option.value} value={option.value}>
                                {option.label}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      </td>
                      <td className="p-3 max-w-xs">
                        <div className="text-sm text-muted-foreground truncate">
                          {action.commentaire || "-"}
                        </div>
                      </td>
                      <td className="p-3">
                        <div className="flex items-center gap-2">
                          {canEdit ? (
                            <>
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  handleEditAction(action);
                                }}
                                className="h-8 w-8 p-0 hover:bg-primary/10"
                              >
                                <Edit className="h-4 w-4" />
                              </Button>
                              <AlertDialog>
                                <AlertDialogTrigger asChild>
                                  <Button
                                    variant="ghost"
                                    size="sm"
                                    onClick={(e) => e.stopPropagation()}
                                    className="h-8 w-8 p-0 hover:bg-destructive/10 text-destructive"
                                  >
                                    <Trash2 className="h-4 w-4" />
                                  </Button>
                                </AlertDialogTrigger>
                                <AlertDialogContent>
                                  <AlertDialogHeader>
                                    <AlertDialogTitle>Confirmer la suppression</AlertDialogTitle>
                                    <AlertDialogDescription>
                                      Êtes-vous sûr de vouloir supprimer cette action ? Cette action est irréversible.
                                    </AlertDialogDescription>
                                  </AlertDialogHeader>
                                  <AlertDialogFooter>
                                    <AlertDialogCancel>Annuler</AlertDialogCancel>
                                    <AlertDialogAction
                                      onClick={() => handleDeleteAction(action.id)}
                                      className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                                    >
                                      Supprimer
                                    </AlertDialogAction>
                                  </AlertDialogFooter>
                                </AlertDialogContent>
                              </AlertDialog>
                            </>
                          ) : (
                            <div className="flex items-center gap-2 text-muted-foreground">
                              <Lock className="h-4 w-4" />
                              <span className="text-xs">Accès restreint</span>
                            </div>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          {actions.length === 0 && (
            <div className="text-center py-8 text-muted-foreground">
              Aucune action dans le plan d'action
            </div>
          )}
        </CardContent>
      </Card>

      {/* Modal d'édition */}
      <EditActionModal
        action={selectedAction}
        isOpen={isEditModalOpen}
        onClose={() => {
          setIsEditModalOpen(false);
          setSelectedAction(null);
        }}
        onActionUpdated={loadData}
      />
    </div>
  );
}