import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger } from "@/components/ui/alert-dialog";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks/use-toast";
import { CheckCircle, Plus, Edit, Trash2, ArrowRight, UserCheck, Clock, AlertCircle } from "lucide-react";

interface ValidationStep {
  ordre: number;
  validateur_type: 'user' | 'role';
  validateur_id: string;
  validateur_nom: string;
  condition?: string;
}

interface BoucleValidation {
  id: string;
  nom: string;
  description?: string;
  declencheur: string;
  segment_id?: string;
  etapes: ValidationStep[];
  actif: boolean;
  created_at: string;
}

interface User {
  id: string;
  nom: string;
  prenom: string;
  email: string;
}

interface Role {
  id: string;
  nom: string;
}

interface Segment {
  id: string;
  nom: string;
  couleur: string;
}

const ValidationWorkflow = () => {
  const [workflows, setWorkflows] = useState<BoucleValidation[]>([]);
  const [users, setUsers] = useState<User[]>([]);
  const [roles, setRoles] = useState<Role[]>([]);
  const [segments, setSegments] = useState<Segment[]>([]);
  const [loading, setLoading] = useState(true);
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [editingWorkflow, setEditingWorkflow] = useState<BoucleValidation | null>(null);
  const { toast } = useToast();

  // Form state
  const [formData, setFormData] = useState({
    nom: "",
    description: "",
    declencheur: "",
    segment_id: "all",
    etapes: [] as ValidationStep[]
  });

  const declencheurs = [
    { value: "demande_conge", label: "Demande de congé" },
    { value: "demande_administrative", label: "Demande administrative" },
    { value: "correction_pointage", label: "Correction de pointage" },
    { value: "note_frais", label: "Note de frais" },
    { value: "demande_formation", label: "Demande de formation" },
    { value: "recrutement", label: "Processus de recrutement" }
  ];

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      
      // Mock users data
      const mockUsers: User[] = [
        { id: "1", nom: "Dupont", prenom: "Jean", email: "jean.dupont@prolean.com" },
        { id: "2", nom: "Martin", prenom: "Marie", email: "marie.martin@prolean.com" },
        { id: "3", nom: "Durand", prenom: "Pierre", email: "pierre.durand@prolean.com" },
        { id: "4", nom: "Moreau", prenom: "Thomas", email: "thomas.moreau@prolean.com" }
      ];

      // Mock roles data
      const mockRoles: Role[] = [
        { id: "1", nom: "Manager" },
        { id: "2", nom: "RH" },
        { id: "3", nom: "Directeur" },
        { id: "4", nom: "Admin" }
      ];

      // Mock segments data
      const mockSegments: Segment[] = [
        { id: "1", nom: "PROLEAN Groupe", couleur: "#3B82F6" },
        { id: "2", nom: "PROLEAN Formation", couleur: "#10B981" },
        { id: "3", nom: "PROLEAN Consulting", couleur: "#F59E0B" }
      ];

      // Mock workflows data
      const mockWorkflows: BoucleValidation[] = [
        {
          id: "1",
          nom: "Validation Congés - Standard",
          description: "Circuit de validation pour les demandes de congé standard",
          declencheur: "demande_conge",
          segment_id: "1",
          actif: true,
          etapes: [
            {
              ordre: 1,
              validateur_type: 'role',
              validateur_id: "1",
              validateur_nom: "Manager",
              condition: "Chef hiérarchique direct"
            },
            {
              ordre: 2,
              validateur_type: 'role',
              validateur_id: "2",
              validateur_nom: "RH",
              condition: "Validation finale RH"
            }
          ],
          created_at: new Date().toISOString()
        },
        {
          id: "2",
          nom: "Validation Notes de Frais",
          description: "Circuit pour les notes de frais",
          declencheur: "note_frais",
          actif: true,
          etapes: [
            {
              ordre: 1,
              validateur_type: 'role',
              validateur_id: "1",
              validateur_nom: "Manager"
            },
            {
              ordre: 2,
              validateur_type: 'user',
              validateur_id: "1",
              validateur_nom: "Jean Dupont",
              condition: "Directeur comptable"
            }
          ],
          created_at: new Date().toISOString()
        },
        {
          id: "3",
          nom: "Recrutement - Commercial",
          description: "Circuit de validation pour le recrutement de commerciaux",
          declencheur: "recrutement",
          segment_id: "2",
          actif: true,
          etapes: [
            {
              ordre: 1,
              validateur_type: 'role',
              validateur_id: "2",
              validateur_nom: "RH",
              condition: "Pré-sélection RH"
            },
            {
              ordre: 2,
              validateur_type: 'role',
              validateur_id: "1",
              validateur_nom: "Manager",
              condition: "Entretien manager"
            },
            {
              ordre: 3,
              validateur_type: 'role',
              validateur_id: "3",
              validateur_nom: "Directeur",
              condition: "Validation finale"
            }
          ],
          created_at: new Date().toISOString()
        }
      ];

      setUsers(mockUsers);
      setRoles(mockRoles);
      setSegments(mockSegments);
      setWorkflows(mockWorkflows);

    } catch (error) {
      console.error('Error loading data:', error);
      toast({
        title: "Erreur",
        description: "Impossible de charger les données",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    try {
      if (formData.etapes.length === 0) {
        toast({
          title: "Erreur",
          description: "Vous devez définir au moins une étape de validation",
          variant: "destructive"
        });
        return;
      }

      if (editingWorkflow) {
        // Update workflow
        setWorkflows(workflows.map(workflow => 
          workflow.id === editingWorkflow.id 
            ? {
                ...workflow,
                nom: formData.nom,
                description: formData.description,
                declencheur: formData.declencheur,
                segment_id: formData.segment_id || undefined,
                etapes: formData.etapes
              }
            : workflow
        ));

        toast({
          title: "Succès",
          description: "Boucle de validation modifiée avec succès"
        });
      } else {
        // Create new workflow
        const newWorkflow: BoucleValidation = {
          id: Date.now().toString(),
          nom: formData.nom,
          description: formData.description,
          declencheur: formData.declencheur,
          segment_id: formData.segment_id || undefined,
          etapes: formData.etapes,
          actif: true,
          created_at: new Date().toISOString()
        };

        setWorkflows([...workflows, newWorkflow]);
        
        toast({
          title: "Succès",
          description: "Boucle de validation créée avec succès"
        });
      }

      setIsDialogOpen(false);
      resetForm();

    } catch (error) {
      console.error('Error saving workflow:', error);
      toast({
        title: "Erreur",
        description: "Impossible de sauvegarder la boucle de validation",
        variant: "destructive"
      });
    }
  };

  const handleDelete = async (workflowId: string) => {
    try {
      setWorkflows(workflows.filter(workflow => workflow.id !== workflowId));

      toast({
        title: "Succès",
        description: "Boucle de validation supprimée avec succès"
      });
      
    } catch (error) {
      console.error('Error deleting workflow:', error);
      toast({
        title: "Erreur",
        description: "Impossible de supprimer la boucle de validation",
        variant: "destructive"
      });
    }
  };

  const toggleWorkflowStatus = async (workflowId: string) => {
    try {
      setWorkflows(workflows.map(workflow =>
        workflow.id === workflowId
          ? { ...workflow, actif: !workflow.actif }
          : workflow
      ));

      toast({
        title: "Succès",
        description: "Statut de la boucle mis à jour"
      });
    } catch (error) {
      console.error('Error updating workflow status:', error);
      toast({
        title: "Erreur",
        description: "Impossible de modifier le statut",
        variant: "destructive"
      });
    }
  };

  const resetForm = () => {
    setFormData({
      nom: "",
      description: "",
      declencheur: "",
      segment_id: "all",
      etapes: []
    });
    setEditingWorkflow(null);
  };

  const openEditDialog = (workflow: BoucleValidation) => {
    setEditingWorkflow(workflow);
    setFormData({
      nom: workflow.nom,
      description: workflow.description || "",
      declencheur: workflow.declencheur,
      segment_id: workflow.segment_id || "all",
      etapes: workflow.etapes
    });
    setIsDialogOpen(true);
  };

  const addEtape = () => {
    const newEtape: ValidationStep = {
      ordre: formData.etapes.length + 1,
      validateur_type: 'role',
      validateur_id: "",
      validateur_nom: "",
      condition: ""
    };
    setFormData({
      ...formData,
      etapes: [...formData.etapes, newEtape]
    });
  };

  const updateEtape = (index: number, field: keyof ValidationStep, value: any) => {
    const updatedEtapes = formData.etapes.map((etape, i) => {
      if (i === index) {
        const updated = { ...etape, [field]: value };
        
        // Update validateur_nom when validateur_id changes
        if (field === 'validateur_id' || field === 'validateur_type') {
          if (updated.validateur_type === 'user') {
            const user = users.find(u => u.id === updated.validateur_id);
            updated.validateur_nom = user ? `${user.prenom} ${user.nom}` : "";
          } else {
            const role = roles.find(r => r.id === updated.validateur_id);
            updated.validateur_nom = role ? role.nom : "";
          }
        }
        
        return updated;
      }
      return etape;
    });
    
    setFormData({ ...formData, etapes: updatedEtapes });
  };

  const removeEtape = (index: number) => {
    const updatedEtapes = formData.etapes
      .filter((_, i) => i !== index)
      .map((etape, i) => ({ ...etape, ordre: i + 1 }));
    
    setFormData({ ...formData, etapes: updatedEtapes });
  };

  const moveEtape = (index: number, direction: 'up' | 'down') => {
    const newIndex = direction === 'up' ? index - 1 : index + 1;
    if (newIndex < 0 || newIndex >= formData.etapes.length) return;

    const updatedEtapes = [...formData.etapes];
    [updatedEtapes[index], updatedEtapes[newIndex]] = [updatedEtapes[newIndex], updatedEtapes[index]];
    
    // Update ordre
    updatedEtapes.forEach((etape, i) => {
      etape.ordre = i + 1;
    });
    
    setFormData({ ...formData, etapes: updatedEtapes });
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="text-center">
          <CheckCircle className="h-12 w-12 mx-auto mb-4 text-muted-foreground animate-pulse" />
          <p className="text-muted-foreground">Chargement des boucles de validation...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h3 className="text-lg font-semibold">Boucles de Validation RH</h3>
          <p className="text-sm text-muted-foreground">
            Configurez les circuits d'approbation automatiques pour les demandes RH
          </p>
        </div>
        
        <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
          <DialogTrigger asChild>
            <Button onClick={resetForm} className="gap-2">
              <Plus className="h-4 w-4" />
              Créer une boucle
            </Button>
          </DialogTrigger>
          
          <DialogContent className="max-w-4xl max-h-[80vh] overflow-y-auto">
            <form onSubmit={handleSubmit}>
              <DialogHeader>
                <DialogTitle>
                  {editingWorkflow ? "Modifier la boucle de validation" : "Nouvelle boucle de validation"}
                </DialogTitle>
                <DialogDescription>
                  {editingWorkflow ? "Modifiez le circuit d'approbation" : "Créez un nouveau circuit d'approbation automatique"}
                </DialogDescription>
              </DialogHeader>

              <div className="grid gap-6 py-4">
                {/* Basic Info */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <Label htmlFor="nom">Nom de la boucle *</Label>
                    <Input
                      id="nom"
                      value={formData.nom}
                      onChange={(e) => setFormData({...formData, nom: e.target.value})}
                      required
                    />
                  </div>
                  <div>
                    <Label htmlFor="declencheur">Déclencheur *</Label>
                    <Select value={formData.declencheur} onValueChange={(value) => setFormData({...formData, declencheur: value})}>
                      <SelectTrigger>
                        <SelectValue placeholder="Sélectionner un déclencheur" />
                      </SelectTrigger>
                      <SelectContent>
                        {declencheurs.map((declencheur) => (
                          <SelectItem key={declencheur.value} value={declencheur.value}>
                            {declencheur.label}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <Label htmlFor="description">Description</Label>
                    <Textarea
                      id="description"
                      value={formData.description}
                      onChange={(e) => setFormData({...formData, description: e.target.value})}
                      rows={3}
                    />
                  </div>
                  <div>
                    <Label htmlFor="segment">Segment (optionnel)</Label>
                    <Select value={formData.segment_id} onValueChange={(value) => setFormData({...formData, segment_id: value})}>
                      <SelectTrigger>
                        <SelectValue placeholder="Tous les segments" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="all">Tous les segments</SelectItem>
                        {segments.map((segment) => (
                          <SelectItem key={segment.id} value={segment.id}>
                            {segment.nom}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </div>

                {/* Validation Steps */}
                <Card>
                  <CardHeader>
                    <div className="flex items-center justify-between">
                      <CardTitle className="text-base">Étapes de validation</CardTitle>
                      <Button type="button" onClick={addEtape} size="sm" className="gap-2">
                        <Plus className="h-4 w-4" />
                        Ajouter une étape
                      </Button>
                    </div>
                    <CardDescription>
                      Définissez les étapes d'approbation dans l'ordre
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    {formData.etapes.length === 0 ? (
                      <div className="text-center py-8 text-muted-foreground">
                        <AlertCircle className="h-8 w-8 mx-auto mb-2" />
                        <p>Aucune étape définie. Ajoutez une première étape.</p>
                      </div>
                    ) : (
                      <div className="space-y-4">
                        {formData.etapes.map((etape, index) => (
                          <div key={index} className="flex items-center gap-4 p-4 border rounded-lg">
                            <div className="flex items-center gap-2">
                              <div className="w-8 h-8 bg-primary text-primary-foreground rounded-full flex items-center justify-center text-sm font-medium">
                                {etape.ordre}
                              </div>
                              {index < formData.etapes.length - 1 && (
                                <ArrowRight className="h-4 w-4 text-muted-foreground" />
                              )}
                            </div>

                            <div className="grid grid-cols-1 md:grid-cols-4 gap-3 flex-1">
                              <div>
                                <Label className="text-xs">Type</Label>
                                <Select 
                                  value={etape.validateur_type} 
                                  onValueChange={(value) => updateEtape(index, 'validateur_type', value)}
                                >
                                  <SelectTrigger className="h-8">
                                    <SelectValue />
                                  </SelectTrigger>
                                  <SelectContent>
                                    <SelectItem value="role">Rôle</SelectItem>
                                    <SelectItem value="user">Utilisateur</SelectItem>
                                  </SelectContent>
                                </Select>
                              </div>

                              <div>
                                <Label className="text-xs">Validateur</Label>
                                <Select 
                                  value={etape.validateur_id} 
                                  onValueChange={(value) => updateEtape(index, 'validateur_id', value)}
                                >
                                  <SelectTrigger className="h-8">
                                    <SelectValue placeholder="Sélectionner" />
                                  </SelectTrigger>
                                  <SelectContent>
                                    {etape.validateur_type === 'role' 
                                      ? roles.map((role) => (
                                          <SelectItem key={role.id} value={role.id}>
                                            {role.nom}
                                          </SelectItem>
                                        ))
                                      : users.map((user) => (
                                          <SelectItem key={user.id} value={user.id}>
                                            {user.prenom} {user.nom}
                                          </SelectItem>
                                        ))
                                    }
                                  </SelectContent>
                                </Select>
                              </div>

                              <div>
                                <Label className="text-xs">Condition</Label>
                                <Input
                                  value={etape.condition || ""}
                                  onChange={(e) => updateEtape(index, 'condition', e.target.value)}
                                  placeholder="Description..."
                                  className="h-8"
                                />
                              </div>

                              <div className="flex gap-1">
                                <Button
                                  type="button"
                                  variant="outline"
                                  size="sm"
                                  onClick={() => moveEtape(index, 'up')}
                                  disabled={index === 0}
                                  className="h-8 w-8 p-0"
                                >
                                  ↑
                                </Button>
                                <Button
                                  type="button"
                                  variant="outline"
                                  size="sm"
                                  onClick={() => moveEtape(index, 'down')}
                                  disabled={index === formData.etapes.length - 1}
                                  className="h-8 w-8 p-0"
                                >
                                  ↓
                                </Button>
                                <Button
                                  type="button"
                                  variant="outline"
                                  size="sm"
                                  onClick={() => removeEtape(index)}
                                  className="h-8 w-8 p-0 text-destructive"
                                >
                                  ×
                                </Button>
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </CardContent>
                </Card>
              </div>

              <DialogFooter>
                <Button type="button" variant="outline" onClick={() => setIsDialogOpen(false)}>
                  Annuler
                </Button>
                <Button type="submit">
                  {editingWorkflow ? "Modifier" : "Créer"}
                </Button>
              </DialogFooter>
            </form>
          </DialogContent>
        </Dialog>
      </div>

      {/* Workflows Table */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <CheckCircle className="h-5 w-5" />
            Boucles de validation ({workflows.length})
          </CardTitle>
          <CardDescription>
            Liste de tous les circuits d'approbation configurés
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Boucle</TableHead>
                <TableHead>Déclencheur</TableHead>
                <TableHead>Segment</TableHead>
                <TableHead>Étapes</TableHead>
                <TableHead>Statut</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {workflows.map((workflow) => (
                <TableRow key={workflow.id}>
                  <TableCell>
                    <div className="flex items-center gap-3">
                      <div className="p-2 bg-primary/10 rounded-lg">
                        <CheckCircle className="h-4 w-4 text-primary" />
                      </div>
                      <div>
                        <div className="font-medium">{workflow.nom}</div>
                        {workflow.description && (
                          <div className="text-sm text-muted-foreground">{workflow.description}</div>
                        )}
                      </div>
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge variant="secondary">
                      {declencheurs.find(d => d.value === workflow.declencheur)?.label || workflow.declencheur}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    {workflow.segment_id ? (
                      <div className="flex items-center gap-2">
                        <div 
                          className="w-3 h-3 rounded-full" 
                          style={{ backgroundColor: segments.find(s => s.id === workflow.segment_id)?.couleur }}
                        />
                        {segments.find(s => s.id === workflow.segment_id)?.nom}
                      </div>
                    ) : (
                      <span className="text-muted-foreground italic">Tous</span>
                    )}
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-1">
                      {workflow.etapes.slice(0, 3).map((etape, index) => (
                        <div key={index} className="flex items-center gap-1">
                          <Badge variant="outline" className="text-xs">
                            {etape.validateur_nom}
                          </Badge>
                          {index < Math.min(workflow.etapes.length - 1, 2) && (
                            <ArrowRight className="h-3 w-3 text-muted-foreground" />
                          )}
                        </div>
                      ))}
                      {workflow.etapes.length > 3 && (
                        <Badge variant="outline" className="text-xs">
                          +{workflow.etapes.length - 3}
                        </Badge>
                      )}
                    </div>
                  </TableCell>
                  <TableCell>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => toggleWorkflowStatus(workflow.id)}
                      className={workflow.actif ? "text-green-600" : "text-red-600"}
                    >
                      {workflow.actif ? (
                        <>
                          <CheckCircle className="h-4 w-4 mr-1" />
                          Actif
                        </>
                      ) : (
                        <>
                          <Clock className="h-4 w-4 mr-1" />
                          Inactif
                        </>
                      )}
                    </Button>
                  </TableCell>
                  <TableCell className="text-right">
                    <div className="flex gap-2 justify-end">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => openEditDialog(workflow)}
                      >
                        <Edit className="h-4 w-4" />
                      </Button>
                      
                      <AlertDialog>
                        <AlertDialogTrigger asChild>
                          <Button variant="outline" size="sm">
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </AlertDialogTrigger>
                        <AlertDialogContent>
                          <AlertDialogHeader>
                            <AlertDialogTitle>Confirmer la suppression</AlertDialogTitle>
                            <AlertDialogDescription>
                              Êtes-vous sûr de vouloir supprimer la boucle "{workflow.nom}" ? 
                              Cette action est irréversible et affectera tous les processus en cours.
                            </AlertDialogDescription>
                          </AlertDialogHeader>
                          <AlertDialogFooter>
                            <AlertDialogCancel>Annuler</AlertDialogCancel>
                            <AlertDialogAction 
                              onClick={() => handleDelete(workflow.id)}
                              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                            >
                              Supprimer
                            </AlertDialogAction>
                          </AlertDialogFooter>
                        </AlertDialogContent>
                      </AlertDialog>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
              {workflows.length === 0 && (
                <TableRow>
                  <TableCell colSpan={6} className="text-center py-8">
                    <CheckCircle className="h-8 w-8 mx-auto mb-2 text-muted-foreground" />
                    <p className="text-muted-foreground">Aucune boucle de validation configurée</p>
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
};

export default ValidationWorkflow;