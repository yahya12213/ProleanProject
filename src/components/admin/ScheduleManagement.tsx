import React, { useState, useEffect, useCallback } from 'react';
import { Clock, Plus, Edit, Trash2, Power, PowerOff, Calendar, UserCheck } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger } from "@/components/ui/alert-dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import axios from 'axios';
import { useToast } from "@/hooks/use-toast";
import HolidayManagement from './HolidayManagement';
import ValidatedLeavesCalendar from './ValidatedLeavesCalendar';
import OvertimeDeclarationManagement from './OvertimeDeclarationManagement';

interface Pause {
  id: string;
  heureDebut: string;
  heureFin: string;
  remuneree: boolean;
  nom: string;
}

interface HoraireJour {
  actif: boolean;
  heureDebut: string;
  heureFin: string;
  pauses: Pause[];
}

interface HorairesSemaine {
  lundi: HoraireJour;
  mardi: HoraireJour;
  mercredi: HoraireJour;
  jeudi: HoraireJour;
  vendredi: HoraireJour;
  samedi: HoraireJour;
  dimanche: HoraireJour;
}

interface HoraireModele {
  id: string;
  nom: string;
  description: string;
  is_active: boolean;
  horaires_semaine: HorairesSemaine;
  jours_feries: string[];
  created_at: string;
  updated_at: string;
}

const ScheduleManagement = () => {
  const [horaires, setHoraires] = useState<HoraireModele[]>([]);
  const [loading, setLoading] = useState(true);
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [editingHoraire, setEditingHoraire] = useState<HoraireModele | null>(null);
  const { toast } = useToast();
  
  // État du formulaire
  const [formData, setFormData] = useState({
    nom: '',
    description: '',
      horaires_semaine: {
        lundi: { actif: true, heureDebut: '09:00', heureFin: '18:00', pauses: [] },
        mardi: { actif: true, heureDebut: '09:00', heureFin: '18:00', pauses: [] },
        mercredi: { actif: true, heureDebut: '09:00', heureFin: '18:00', pauses: [] },
        jeudi: { actif: true, heureDebut: '09:00', heureFin: '18:00', pauses: [] },
        vendredi: { actif: true, heureDebut: '09:00', heureFin: '18:00', pauses: [] },
        samedi: { actif: false, heureDebut: '09:00', heureFin: '18:00', pauses: [] },
        dimanche: { actif: false, heureDebut: '09:00', heureFin: '18:00', pauses: [] }
      },
    jours_feries: ['']
  });

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const response = await axios.get('/api/horaires_modeles');
      const transformedData: HoraireModele[] = response.data.map(item => ({
        ...item,
        horaires_semaine: item.horaires_semaine as HorairesSemaine,
      }));
      setHoraires(transformedData);
    } catch (error) {
      console.error('Erreur lors du chargement des horaires:', error);
      toast({
        title: "Erreur",
        description: "Impossible de charger les modèles d'horaires",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleSubmit = async () => {
    try {
      const horaireData = {
        nom: formData.nom,
        description: formData.description,
        horaires_semaine: formData.horaires_semaine,
        jours_feries: formData.jours_feries.filter(jour => jour.trim() !== ''),
      };

      if (editingHoraire) {
        await axios.put(`/api/horaires_modeles/${editingHoraire.id}`, horaireData);
        toast({
          title: "Modèle modifié",
          description: "Le modèle d'horaire a été modifié avec succès",
        });
      } else {
        await axios.post('/api/horaires_modeles', horaireData);
        toast({
          title: "Modèle créé",
          description: "Le nouveau modèle d'horaire a été créé avec succès",
        });
      }

      loadData();
      resetForm();
      setIsDialogOpen(false);
    } catch (error) {
      console.error('Erreur lors de la sauvegarde:', error);
      toast({
        title: "Erreur",
        description: "Impossible de sauvegarder le modèle d'horaire",
        variant: "destructive",
      });
    }
  };

  const handleDelete = async (id: string) => {
    try {
      const horaire = horaires.find(h => h.id === id);
      if (horaire?.is_active) {
        toast({
          title: "Suppression impossible",
          description: "Impossible de supprimer le modèle actif. Activez d'abord un autre modèle.",
          variant: "destructive",
        });
        return;
      }

      await axios.delete(`/api/horaires_modeles/${id}`);
      toast({
        title: "Modèle supprimé",
        description: "Le modèle d'horaire a été supprimé avec succès",
      });

      loadData();
    } catch (error) {
      console.error('Erreur lors de la suppression:', error);
      toast({
        title: "Erreur",
        description: "Impossible de supprimer le modèle d'horaire",
        variant: "destructive",
      });
    }
  };

  const resetForm = () => {
    setFormData({
      nom: '',
      description: '',
      horaires_semaine: {
        lundi: { actif: true, heureDebut: '09:00', heureFin: '18:00', pauses: [] },
        mardi: { actif: true, heureDebut: '09:00', heureFin: '18:00', pauses: [] },
        mercredi: { actif: true, heureDebut: '09:00', heureFin: '18:00', pauses: [] },
        jeudi: { actif: true, heureDebut: '09:00', heureFin: '18:00', pauses: [] },
        vendredi: { actif: true, heureDebut: '09:00', heureFin: '18:00', pauses: [] },
        samedi: { actif: false, heureDebut: '09:00', heureFin: '18:00', pauses: [] },
        dimanche: { actif: false, heureDebut: '09:00', heureFin: '18:00', pauses: [] }
      },
      jours_feries: ['']
    });
    setEditingHoraire(null);
  };

  const openEditDialog = (horaire: HoraireModele) => {
    setEditingHoraire(horaire);
    setFormData({
      nom: horaire.nom,
      description: horaire.description,
      horaires_semaine: {
        lundi: horaire.horaires_semaine.lundi || { actif: true, heureDebut: '09:00', heureFin: '18:00', pauses: [] },
        mardi: horaire.horaires_semaine.mardi || { actif: true, heureDebut: '09:00', heureFin: '18:00', pauses: [] },
        mercredi: horaire.horaires_semaine.mercredi || { actif: true, heureDebut: '09:00', heureFin: '18:00', pauses: [] },
        jeudi: horaire.horaires_semaine.jeudi || { actif: true, heureDebut: '09:00', heureFin: '18:00', pauses: [] },
        vendredi: horaire.horaires_semaine.vendredi || { actif: true, heureDebut: '09:00', heureFin: '18:00', pauses: [] },
        samedi: horaire.horaires_semaine.samedi || { actif: false, heureDebut: '09:00', heureFin: '18:00', pauses: [] },
        dimanche: horaire.horaires_semaine.dimanche || { actif: false, heureDebut: '09:00', heureFin: '18:00', pauses: [] }
      },
      jours_feries: horaire.jours_feries.length > 0 ? horaire.jours_feries : ['']
    });
    setIsDialogOpen(true);
  };

  const updateJourHoraire = (jour: string, field: string, value: string | boolean) => {
    setFormData(prev => ({
      ...prev,
      horaires_semaine: {
        ...prev.horaires_semaine,
        [jour]: {
          ...prev.horaires_semaine[jour],
          [field]: value
        }
      }
    }));
  };

  // Ajouter une pause à un jour
  const addPause = (jour: string) => {
    const newPause: Pause = {
      id: Date.now().toString(),
      nom: 'Nouvelle pause',
      heureDebut: '12:00',
      heureFin: '13:00',
      remuneree: false
    };
    
    setFormData(prev => ({
      ...prev,
      horaires_semaine: {
        ...prev.horaires_semaine,
        [jour]: {
          ...prev.horaires_semaine[jour],
          pauses: [...prev.horaires_semaine[jour].pauses, newPause]
        }
      }
    }));
  };

  // Supprimer une pause
  const removePause = (jour: string, pauseId: string) => {
    setFormData(prev => ({
      ...prev,
      horaires_semaine: {
        ...prev.horaires_semaine,
        [jour]: {
          ...prev.horaires_semaine[jour],
          pauses: prev.horaires_semaine[jour].pauses.filter(p => p.id !== pauseId)
        }
      }
    }));
  };

  // Mettre à jour une pause
  const updatePause = (jour: string, pauseId: string, field: keyof Pause, value: string | boolean) => {
    setFormData(prev => ({
      ...prev,
      horaires_semaine: {
        ...prev.horaires_semaine,
        [jour]: {
          ...prev.horaires_semaine[jour],
          pauses: prev.horaires_semaine[jour].pauses.map(pause =>
            pause.id === pauseId ? { ...pause, [field]: value } : pause
          )
        }
      }
    }));
  };

  const calculateWeeklyHours = (horaires_semaine: Record<string, HoraireJour>) => {
    let totalMinutes = 0;

    Object.values(horaires_semaine).forEach((jour) => {
      if (jour.actif) {
        const debut = new Date(`2024-01-01T${jour.heureDebut}:00`);
        const fin = new Date(`2024-01-01T${jour.heureFin}:00`);
        let minutesBrutes = (fin.getTime() - debut.getTime()) / (1000 * 60);

        if (jour.pauses) {
          jour.pauses.forEach((pause) => {
            if (!pause.remuneree) {
              const pauseDebut = new Date(`2024-01-01T${pause.heureDebut}:00`);
              const pauseFin = new Date(`2024-01-01T${pause.heureFin}:00`);
              const pauseMinutes = (pauseFin.getTime() - pauseDebut.getTime()) / (1000 * 60);
              minutesBrutes -= pauseMinutes;
            }
          });
        }

        totalMinutes += minutesBrutes;
      }
    });

    return (totalMinutes / 60).toFixed(1);
  };

  const handleActivate = async (id: string) => {
    try {
      await axios.post('/api/activate_horaire_modele', { model_id: id });
      toast({
        title: "Modèle activé",
        description: "Le modèle d'horaire a été activé avec succès",
      });
      loadData();
    } catch (error) {
      console.error('Erreur lors de l\'activation:', error);
      toast({
        title: "Erreur",
        description: "Impossible d'activer le modèle d'horaire",
        variant: "destructive",
      });
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="text-center">
          <Clock className="h-12 w-12 mx-auto mb-4 text-muted-foreground animate-pulse" />
          <p className="text-muted-foreground">Chargement des modèles d'horaires...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <Tabs defaultValue="horaires" className="w-full">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="horaires" className="flex items-center gap-2">
            <Clock className="h-4 w-4" />
            Modèles d'horaires
          </TabsTrigger>
          <TabsTrigger value="jours-feries" className="flex items-center gap-2">
            <Calendar className="h-4 w-4" />
            Jours fériés
          </TabsTrigger>
          <TabsTrigger value="conges-valides" className="flex items-center gap-2">
            <UserCheck className="h-4 w-4" />
            Congés validés
          </TabsTrigger>
          <TabsTrigger value="heures-sup" className="flex items-center gap-2">
            <Clock className="h-4 w-4" />
            Déclaration heures sup
          </TabsTrigger>
        </TabsList>

        <TabsContent value="horaires">
          <div className="space-y-6">
            {/* En-tête */}
            <div className="flex justify-between items-center">
              <div>
                <h3 className="text-lg font-semibold">Gestion des Modèles d'Horaires</h3>
                <p className="text-sm text-muted-foreground">
                  Créez et gérez les modèles d'horaires de travail pour le système de pointage
                </p>
              </div>
              
              <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
          <DialogTrigger asChild>
            <Button onClick={resetForm} className="gap-2">
              <Plus className="h-4 w-4" />
              Créer un modèle
            </Button>
          </DialogTrigger>
          
          <DialogContent className="max-w-4xl max-h-[80vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle>
                {editingHoraire ? "Modifier le modèle d'horaire" : "Nouveau modèle d'horaire"}
              </DialogTitle>
              <DialogDescription>
                {editingHoraire ? "Modifiez les paramètres du modèle d'horaire" : "Créez un nouveau modèle d'horaires de travail"}
              </DialogDescription>
            </DialogHeader>

            <div className="space-y-6 py-4">
              {/* Informations de base */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label htmlFor="nom">Nom du modèle *</Label>
                  <Input
                    id="nom"
                    value={formData.nom}
                    onChange={(e) => setFormData(prev => ({...prev, nom: e.target.value}))}
                    placeholder="Ex: Temps plein - 39h"
                    required
                  />
                </div>
                <div>
                  <Label htmlFor="description">Description</Label>
                  <Input
                    id="description"
                    value={formData.description}
                    onChange={(e) => setFormData(prev => ({...prev, description: e.target.value}))}
                    placeholder="Description du modèle d'horaire"
                  />
                </div>
              </div>

              {/* Horaires de la semaine */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Horaires par jour</CardTitle>
                  <CardDescription>
                    Total hebdomadaire calculé : {calculateWeeklyHours(formData.horaires_semaine)}h
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {Object.entries(formData.horaires_semaine).map(([jour, horaire]) => (
                      <div key={jour} className="flex items-center gap-4 p-3 border rounded-lg">
                        <div className="flex items-center space-x-2 min-w-[120px]">
                          <Checkbox
                            id={`${jour}-actif`}
                            checked={horaire.actif}
                            onCheckedChange={(checked) => updateJourHoraire(jour, 'actif', !!checked)}
                          />
                          <Label htmlFor={`${jour}-actif`} className="font-medium capitalize">
                            {jour}
                          </Label>
                        </div>
                        
                        <div className="flex items-center gap-2 flex-1">
                          <Label className="text-sm">De</Label>
                          <Input
                            type="time"
                            value={horaire.heureDebut}
                            onChange={(e) => updateJourHoraire(jour, 'heureDebut', e.target.value)}
                            disabled={!horaire.actif}
                            className="w-32"
                          />
                          
                          <Label className="text-sm">à</Label>
                          <Input
                            type="time"
                            value={horaire.heureFin}
                            onChange={(e) => updateJourHoraire(jour, 'heureFin', e.target.value)}
                            disabled={!horaire.actif}
                            className="w-32"
                          />
                          
                         {horaire.actif && (
                             <div className="text-sm text-muted-foreground ml-4">
                               {(() => {
                                 const debut = new Date(`2024-01-01T${horaire.heureDebut}:00`);
                                 const fin = new Date(`2024-01-01T${horaire.heureFin}:00`);
                                 const diffMinutes = (fin.getTime() - debut.getTime()) / (1000 * 60);
                                 let minutesNettes = diffMinutes;
                                 
                                 // Déduire les pauses non rémunérées
                                 horaire.pauses.forEach(pause => {
                                   if (!pause.remuneree) {
                                     const pauseDebut = new Date(`2024-01-01T${pause.heureDebut}:00`);
                                     const pauseFin = new Date(`2024-01-01T${pause.heureFin}:00`);
                                     const pauseMinutes = (pauseFin.getTime() - pauseDebut.getTime()) / (1000 * 60);
                                     minutesNettes -= pauseMinutes;
                                   }
                                 });
                                 
                                 const heuresBrutes = (diffMinutes / 60).toFixed(1);
                                 const heuresNettes = (minutesNettes / 60).toFixed(1);
                                 
                                 return heuresBrutes !== heuresNettes 
                                   ? `${heuresBrutes}h brutes / ${heuresNettes}h nettes`
                                   : `${heuresBrutes}h`;
                               })()}
                             </div>
                           )}
                         </div>
                         
                         {/* Section des pauses pour ce jour */}
                         {horaire.actif && (
                           <div className="mt-3 pl-6 border-l-2 border-muted space-y-2">
                             <div className="flex items-center justify-between">
                               <Label className="text-sm font-medium">Pauses</Label>
                               <Button
                                 type="button"
                                 variant="outline"
                                 size="sm"
                                 onClick={() => addPause(jour)}
                                 className="h-7 px-2 text-xs"
                               >
                                 <Plus className="h-3 w-3 mr-1" />
                                 Ajouter
                               </Button>
                             </div>
                             
                             {horaire.pauses.map((pause) => (
                               <div key={pause.id} className="flex items-center gap-2 p-2 bg-muted/30 rounded text-xs">
                                 <Input
                                   value={pause.nom}
                                   onChange={(e) => updatePause(jour, pause.id, 'nom', e.target.value)}
                                   placeholder="Nom de la pause"
                                   className="h-7 text-xs flex-1"
                                 />
                                 <Input
                                   type="time"
                                   value={pause.heureDebut}
                                   onChange={(e) => updatePause(jour, pause.id, 'heureDebut', e.target.value)}
                                   className="h-7 text-xs w-20"
                                 />
                                 <span className="text-muted-foreground">-</span>
                                 <Input
                                   type="time"
                                   value={pause.heureFin}
                                   onChange={(e) => updatePause(jour, pause.id, 'heureFin', e.target.value)}
                                   className="h-7 text-xs w-20"
                                 />
                                 <div className="flex items-center space-x-1">
                                   <Checkbox
                                     id={`${jour}-${pause.id}-remuneree`}
                                     checked={pause.remuneree}
                                     onCheckedChange={(checked) => updatePause(jour, pause.id, 'remuneree', !!checked)}
                                   />
                                   <Label htmlFor={`${jour}-${pause.id}-remuneree`} className="text-xs whitespace-nowrap">
                                     Rémunérée
                                   </Label>
                                 </div>
                                 <Button
                                   type="button"
                                   variant="outline"
                                   size="sm"
                                   onClick={() => removePause(jour, pause.id)}
                                   className="h-7 w-7 p-0"
                                 >
                                   <Trash2 className="h-3 w-3" />
                                 </Button>
                               </div>
                             ))}
                             
                             {horaire.pauses.length === 0 && (
                               <p className="text-xs text-muted-foreground italic">Aucune pause configurée</p>
                             )}
                           </div>
                         )}
                       </div>
                    ))}
                  </div>
                </CardContent>
              </Card>

              {/* Jours fériés */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Jours fériés</CardTitle>
                  <CardDescription>
                    Ajoutez les jours fériés (format: YYYY-MM-DD)
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {formData.jours_feries.map((jourFerie, index) => (
                      <div key={index} className="flex gap-2">
                        <Input
                          type="date"
                          value={jourFerie}
                          onChange={(e) => {
                            const newJoursFeries = [...formData.jours_feries];
                            newJoursFeries[index] = e.target.value;
                            setFormData(prev => ({...prev, jours_feries: newJoursFeries}));
                          }}
                          className="flex-1"
                        />
                        <Button
                          type="button"
                          variant="outline"
                          size="sm"
                          onClick={() => {
                            const newJoursFeries = formData.jours_feries.filter((_, i) => i !== index);
                            setFormData(prev => ({...prev, jours_feries: newJoursFeries}));
                          }}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    ))}
                    
                    <Button
                      type="button"
                      variant="outline"
                      onClick={() => {
                        setFormData(prev => ({...prev, jours_feries: [...prev.jours_feries, '']}));
                      }}
                    >
                      <Plus className="h-4 w-4 mr-2" />
                      Ajouter un jour férié
                    </Button>
                  </div>
                </CardContent>
              </Card>

              {/* Actions */}
              <div className="flex justify-end gap-2">
                <Button variant="outline" onClick={() => setIsDialogOpen(false)}>
                  Annuler
                </Button>
                <Button onClick={handleSubmit} disabled={!formData.nom.trim()}>
                  {editingHoraire ? 'Modifier' : 'Créer'}
                </Button>
              </div>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      {/* Tableau des modèles */}
      <Card>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Statut</TableHead>
              <TableHead>Nom du modèle</TableHead>
              <TableHead>Description</TableHead>
              <TableHead>Total heures/semaine</TableHead>
              <TableHead>Jours actifs</TableHead>
              <TableHead>Jours fériés</TableHead>
              <TableHead>Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {horaires.map((horaire) => (
              <TableRow key={horaire.id}>
                <TableCell>
                  {horaire.is_active ? (
                    <Badge className="bg-green-100 text-green-800 border-green-200">
                      <Power className="h-3 w-3 mr-1" />
                      Actif
                    </Badge>
                  ) : (
                    <Badge variant="outline" className="text-muted-foreground">
                      <PowerOff className="h-3 w-3 mr-1" />
                      Inactif
                    </Badge>
                  )}
                </TableCell>
                <TableCell className="font-medium">{horaire.nom}</TableCell>
                <TableCell>{horaire.description}</TableCell>
                <TableCell>{calculateWeeklyHours(horaire.horaires_semaine)}h</TableCell>
                <TableCell>
                  <div className="flex flex-wrap gap-1">
                    {Object.entries(horaire.horaires_semaine)
                      .filter(([_, config]) => config.actif)
                      .map(([jour]) => (
                        <Badge key={jour} variant="secondary" className="text-xs">
                          {jour.charAt(0).toUpperCase() + jour.slice(1, 3)}
                        </Badge>
                      ))}
                  </div>
                </TableCell>
                <TableCell>
                  <Badge variant="outline">{horaire.jours_feries.length} jour(s)</Badge>
                </TableCell>
                <TableCell>
                  <div className="flex gap-2">
                    {!horaire.is_active && (
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => handleActivate(horaire.id)}
                        className="text-green-600 border-green-200 hover:bg-green-50"
                      >
                        <Power className="h-4 w-4" />
                      </Button>
                    )}
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => openEditDialog(horaire)}
                    >
                      <Edit className="h-4 w-4" />
                    </Button>
                    <AlertDialog>
                      <AlertDialogTrigger asChild>
                        <Button 
                          variant="outline" 
                          size="sm"
                          disabled={horaire.is_active}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </AlertDialogTrigger>
                      <AlertDialogContent>
                        <AlertDialogHeader>
                          <AlertDialogTitle>Supprimer le modèle d'horaire</AlertDialogTitle>
                          <AlertDialogDescription>
                            Êtes-vous sûr de vouloir supprimer le modèle "{horaire.nom}" ? 
                            Cette action est irréversible.
                          </AlertDialogDescription>
                        </AlertDialogHeader>
                         <AlertDialogFooter>
                           <AlertDialogCancel>Annuler</AlertDialogCancel>
                           <AlertDialogAction
                             onClick={() => handleDelete(horaire.id)}
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
           </TableBody>
         </Table>
       </Card>
          </div>
        </TabsContent>

        <TabsContent value="jours-feries">
          <HolidayManagement />
        </TabsContent>

        <TabsContent value="conges-valides">
          <ValidatedLeavesCalendar />
        </TabsContent>

        <TabsContent value="heures-sup">
          <OvertimeDeclarationManagement />
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default ScheduleManagement;