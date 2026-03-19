import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useToast } from "@/hooks/use-toast";
import axios from 'axios';
import { format } from "date-fns";
import { fr } from "date-fns/locale";
import { 
  CheckCircle, 
  XCircle, 
  Clock, 
  Eye, 
  Filter,
  User,
  Calendar,
  FileText
} from "lucide-react";

interface DemandeRh {
  id: string;
  demandeur_id: string;
  type_demande: string;
  titre: string;
  description: string | null;
  date_debut?: string | null;
  date_fin?: string | null;
  statut: "en_attente" | "approuve" | "refuse" | "en_cours";
  created_at: string;
  pointage_id?: string | null;
  donnees_originales?: any | null;
  donnees_corrigees?: any | null;
  profiles?: {
    nom: string;
    prenom: string;
    email: string;
  } | null;
}

export function DemandeValidation() {
  const [demandes, setDemandes] = useState<DemandeRh[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState("en_attente");
  const [selectedDemande, setSelectedDemande] = useState<DemandeRh | null>(null);
  const [validationDialog, setValidationDialog] = useState(false);
  const [commentaire, setCommentaire] = useState("");
  const [actionType, setActionType] = useState<"approuver" | "refuser">("approuver");
  const { toast } = useToast();

  useEffect(() => {
    loadDemandes();
  }, [filter]);

  const loadDemandes = async () => {
    try {
      setLoading(true);
      
      // Fetch demandes from API Express
      const response = await axios.get('/api/demandes', {
        params: { filter },
      });
      const demandesData = response.data;

      if (!demandesData || demandesData.length === 0) {
        setDemandes([]);
        return;
      }

      // Fetch profiles from API Express
      const profileIds = [...new Set(demandesData.map(d => d.demandeur_id))];
      const profilesResponse = await axios.post('/api/profiles', { ids: profileIds });
      const profilesData = profilesResponse.data;

      // Combine demandes and profiles
      const combinedData = demandesData.map(demande => {
        const profile = profilesData.find(p => p.id === demande.demandeur_id);
        return { ...demande, profiles: profile };
      });

      setDemandes(combinedData);
    } catch (error) {
      console.error('Error loading demandes:', error);
      toast({
        title: 'Erreur',
        description: 'Impossible de charger les demandes.',
        status: 'error',
      });
    } finally {
      setLoading(false);
    }
  };

  const handleValidation = async () => {
    if (!selectedDemande) return;

    try {
      console.log('Début validation demande:', selectedDemande.id, 'Type:', selectedDemande.type_demande, 'Action:', actionType);
      
      // Si c'est une correction de pointage approuvée, mettre à jour le pointage
      if (selectedDemande.type_demande === 'correction_pointage' && actionType === "approuver" && selectedDemande.pointage_id && selectedDemande.donnees_corrigees) {
        console.log('Correction de pointage détectée, mise à jour du pointage:', selectedDemande.pointage_id);
        const corrections = selectedDemande.donnees_corrigees;
        
        // Valider le type_pointage avant la mise à jour
        const validTypes = ['entree', 'sortie', 'pause_debut', 'pause_fin'];
        if (corrections.type_pointage && !validTypes.includes(corrections.type_pointage)) {
          console.error('Type de pointage invalide:', corrections.type_pointage);
          toast({
            title: "Erreur",
            description: "Type de pointage invalide.",
            variant: "destructive",
          });
          return;
        }

        const updateData: any = {
          timestamp_pointage: corrections.timestamp_pointage,
          localisation: corrections.localisation || null,
          notes: corrections.notes || null
        };

        // Ajouter type_pointage seulement s'il est défini et valide
        if (corrections.type_pointage && validTypes.includes(corrections.type_pointage)) {
          updateData.type_pointage = corrections.type_pointage;
        }
        
        // Mettre à jour le pointage original avec la fonction RPC qui gère le cast ENUM
        const { error: pointageError } = await supabase.rpc('update_pointage_with_enum', {
          pointage_id: selectedDemande.pointage_id,
          new_type: corrections.type_pointage,
          new_timestamp: corrections.timestamp_pointage,
          new_localisation: corrections.localisation || null,
          new_notes: corrections.notes || null
        });

        if (pointageError) {
          console.error('Erreur lors de la mise à jour du pointage:', pointageError);
          throw pointageError;
        }
        
        console.log('Pointage mis à jour avec succès');
      }

      // Mettre à jour le statut de la demande
      const { error } = await supabase
        .from('demandes_rh')
        .update({
          statut: actionType === "approuver" ? "approuve" : "refuse",
          motif_refus: actionType === "refuser" ? commentaire : null,
          date_approbation: new Date().toISOString(),
          updated_at: new Date().toISOString()
        })
        .eq('id', selectedDemande.id);

      if (error) {
        console.error('Erreur lors de la mise à jour de la demande:', error);
        throw error;
      }

      console.log('Demande validée avec succès');

      toast({
        title: "Succès",
        description: `Demande ${actionType === "approuver" ? "approuvée" : "refusée"} avec succès${
          selectedDemande.type_demande === 'correction_pointage' && actionType === "approuver" 
            ? " - Le pointage a été mis à jour automatiquement" 
            : ""
        }`
      });

      setValidationDialog(false);
      setSelectedDemande(null);
      setCommentaire("");
      loadDemandes();
    } catch (error) {
      console.error('Error validating demande:', error);
      toast({
        title: "Erreur",
        description: `Impossible de valider la demande: ${error.message || 'Erreur inconnue'}`,
        variant: "destructive"
      });
    }
  };

  const getTypeLabel = (type: string) => {
    switch (type) {
      case "conges": return "Congé";
      case "formation": return "Formation";
      case "materiel": return "Matériel";
      case "correction_pointage": return "Correction Pointage";
      case "avance": return "Avance";
      case "autre": return "Autre";
      default: return type;
    }
  };

  const getStatusColor = (statut: string) => {
    switch (statut) {
      case "approuve": return "bg-green-100 text-green-800";
      case "refuse": return "bg-red-100 text-red-800";
      case "en_attente": return "bg-yellow-100 text-yellow-800";
      default: return "bg-gray-100 text-gray-800";
    }
  };

  const getStatusLabel = (statut: string) => {
    switch (statut) {
      case "approuve": return "Approuvé";
      case "refuse": return "Refusé";
      case "en_attente": return "En attente";
      default: return statut;
    }
  };

  const getPointageTypeDisplay = (type: any): string => {
    // Conversion sécurisée pour éviter les erreurs de type ENUM
    if (!type) return '⚪ Non défini';
    
    // Assurer que nous travaillons avec une chaîne de caractères
    const typeStr = typeof type === 'object' ? String(type) : String(type).toLowerCase();
    
    switch (typeStr) {
      case 'entree': return '🟢 Entrée';
      case 'sortie': return '🔴 Sortie';
      case 'pause_debut': return '🔵 Début pause';
      case 'pause_fin': return '🔵 Fin pause';
      default: return `⚪ ${typeStr}`;
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="text-center">
          <Clock className="h-12 w-12 mx-auto mb-4 text-muted-foreground animate-pulse" />
          <p className="text-muted-foreground">Chargement des demandes...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header avec stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <Clock className="h-8 w-8 text-yellow-600" />
              <div>
                <p className="text-sm text-muted-foreground">En attente</p>
                <p className="text-2xl font-bold">
                  {demandes.filter(d => d.statut === "en_attente").length}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <CheckCircle className="h-8 w-8 text-green-600" />
              <div>
                <p className="text-sm text-muted-foreground">Approuvées</p>
                <p className="text-2xl font-bold">
                  {demandes.filter(d => d.statut === "approuve").length}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <XCircle className="h-8 w-8 text-red-600" />
              <div>
                <p className="text-sm text-muted-foreground">Refusées</p>
                <p className="text-2xl font-bold">
                  {demandes.filter(d => d.statut === "refuse").length}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <FileText className="h-8 w-8 text-blue-600" />
              <div>
                <p className="text-sm text-muted-foreground">Total</p>
                <p className="text-2xl font-bold">{demandes.length}</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Filtres */}
      <Card>
        <CardHeader>
          <div className="flex justify-between items-center">
            <div>
              <CardTitle>Validation des Demandes RH</CardTitle>
              <CardDescription>
                Gérez les demandes en attente de validation
              </CardDescription>
            </div>
            <div className="flex items-center gap-2">
              <Filter className="h-4 w-4" />
              <Select value={filter} onValueChange={setFilter}>
                <SelectTrigger className="w-48">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="en_attente">En attente</SelectItem>
                  <SelectItem value="approuve">Approuvées</SelectItem>
                  <SelectItem value="refuse">Refusées</SelectItem>
                  <SelectItem value="toutes">Toutes</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Demandeur</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Titre/Sujet</TableHead>
                <TableHead>Date création</TableHead>
                <TableHead>Détails Correction</TableHead>
                <TableHead>Statut</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {demandes.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center py-8 text-muted-foreground">
                    Aucune demande trouvée
                  </TableCell>
                </TableRow>
              ) : (
                demandes.map((demande) => (
                  <TableRow key={demande.id}>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <User className="h-4 w-4 text-muted-foreground" />
                        <div>
                          <p className="font-medium">
                            {demande.profiles?.prenom} {demande.profiles?.nom}
                          </p>
                          <p className="text-sm text-muted-foreground">
                            {demande.profiles?.email}
                          </p>
                        </div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline">
                        {getTypeLabel(demande.type_demande)}
                      </Badge>
                    </TableCell>
                    <TableCell className="font-medium max-w-xs">
                      <div className="space-y-1">
                        <p className="text-sm font-medium">{demande.titre}</p>
                        {demande.description && (
                          <p className="text-xs text-muted-foreground line-clamp-2">
                            {demande.description}
                          </p>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      {format(new Date(demande.created_at), "dd MMM yyyy", { locale: fr })}
                    </TableCell>
                    <TableCell>
                      {demande.type_demande === 'correction_pointage' && demande.donnees_originales && demande.donnees_corrigees ? (
                        <div className="space-y-1 text-xs">
                          <div className="bg-red-50 text-red-800 px-2 py-1 rounded border border-red-200">
                            <span className="font-medium">Original:</span> {getPointageTypeDisplay(demande.donnees_originales?.type_pointage)} 
                            {demande.donnees_originales?.timestamp_pointage && ` à ${format(new Date(demande.donnees_originales.timestamp_pointage), "HH:mm")}`}
                          </div>
                          <div className="bg-green-50 text-green-800 px-2 py-1 rounded border border-green-200">
                            <span className="font-medium">Demandé:</span> {getPointageTypeDisplay(demande.donnees_corrigees?.type_pointage)} 
                            {demande.donnees_corrigees?.timestamp_pointage && ` à ${format(new Date(demande.donnees_corrigees.timestamp_pointage), "HH:mm")}`}
                          </div>
                        </div>
                      ) : demande.type_demande === 'conges' && (demande.date_debut || demande.date_fin) ? (
                        <div className="space-y-1 text-xs">
                          {demande.date_debut && (
                            <div className="bg-blue-50 text-blue-800 px-2 py-1 rounded border border-blue-200">
                              <span className="font-medium">🟢 Début:</span> {format(new Date(demande.date_debut), "dd/MM/yyyy", { locale: fr })}
                            </div>
                          )}
                          {demande.date_fin && (
                            <div className="bg-orange-50 text-orange-800 px-2 py-1 rounded border border-orange-200">
                              <span className="font-medium">🔴 Fin:</span> {format(new Date(demande.date_fin), "dd/MM/yyyy", { locale: fr })}
                            </div>
                          )}
                        </div>
                      ) : (
                        <span className="text-muted-foreground">-</span>
                      )}
                    </TableCell>
                    <TableCell>
                      <Badge className={getStatusColor(demande.statut)}>
                        {getStatusLabel(demande.statut)}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <div className="flex gap-2">
                        <Dialog>
                          <DialogTrigger asChild>
                            <Button variant="outline" size="sm">
                              <Eye className="h-4 w-4 mr-1" />
                              Voir
                            </Button>
                          </DialogTrigger>
                          <DialogContent>
                            <DialogHeader>
                              <DialogTitle>{demande.titre}</DialogTitle>
                              <DialogDescription>
                                Demande de {getTypeLabel(demande.type_demande)} - {demande.profiles?.prenom} {demande.profiles?.nom}
                              </DialogDescription>
                            </DialogHeader>
                            <div className="space-y-4">
                              <div>
                                <h4 className="font-medium mb-2">Description</h4>
                                <p className="text-sm text-muted-foreground">
                                  {demande.description || "Aucune description"}
                                </p>
                              </div>
                              
                              {demande.type_demande === 'conges' && (demande.date_debut || demande.date_fin) ? (
                                <div>
                                  <h4 className="font-medium mb-3">Période demandée</h4>
                                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                    {demande.date_debut && (
                                      <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                                        <div className="flex items-center gap-2 mb-2">
                                          <div className="w-3 h-3 bg-blue-500 rounded-full"></div>
                                          <span className="font-medium text-blue-800">Date d'entrée en congé</span>
                                        </div>
                                        <p className="text-lg font-semibold text-blue-900">
                                          {format(new Date(demande.date_debut), "dd MMMM yyyy", { locale: fr })}
                                        </p>
                                      </div>
                                    )}
                                    
                                    {demande.date_fin && (
                                      <div className="bg-orange-50 border border-orange-200 rounded-lg p-4">
                                        <div className="flex items-center gap-2 mb-2">
                                          <div className="w-3 h-3 bg-orange-500 rounded-full"></div>
                                          <span className="font-medium text-orange-800">Date de retour</span>
                                        </div>
                                        <p className="text-lg font-semibold text-orange-900">
                                          {format(new Date(demande.date_fin), "dd MMMM yyyy", { locale: fr })}
                                        </p>
                                      </div>
                                    )}
                                  </div>
                                </div>
                              ) : demande.date_debut && (
                                <div>
                                  <h4 className="font-medium mb-2">Période demandée</h4>
                                  <p className="text-sm">
                                    Du {format(new Date(demande.date_debut), "dd MMMM yyyy", { locale: fr })}
                                    {demande.date_fin && ` au ${format(new Date(demande.date_fin), "dd MMMM yyyy", { locale: fr })}`}
                                  </p>
                                </div>
                              )}
                            </div>
                          </DialogContent>
                        </Dialog>

                        {demande.statut === "en_attente" && (
                          <>
                            <Button
                              size="sm"
                              className="bg-green-600 hover:bg-green-700"
                              onClick={() => {
                                setSelectedDemande(demande);
                                setActionType("approuver");
                                setValidationDialog(true);
                              }}
                            >
                              <CheckCircle className="h-4 w-4 mr-1" />
                              Approuver
                            </Button>
                            <Button
                              size="sm"
                              variant="destructive"
                              onClick={() => {
                                setSelectedDemande(demande);
                                setActionType("refuser");
                                setValidationDialog(true);
                              }}
                            >
                              <XCircle className="h-4 w-4 mr-1" />
                              Refuser
                            </Button>
                          </>
                        )}
                      </div>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Dialog de validation */}
      <Dialog open={validationDialog} onOpenChange={setValidationDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {actionType === "approuver" ? "Approuver" : "Refuser"} la demande
            </DialogTitle>
            <DialogDescription>
              {actionType === "approuver" 
                ? "Vous allez approuver cette demande."
                : "Vous allez refuser cette demande. Veuillez indiquer le motif."
              }
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            {selectedDemande && (
              <div className="p-4 bg-muted rounded-lg">
                <h4 className="font-medium">{selectedDemande.titre}</h4>
                <p className="text-sm text-muted-foreground">
                  {selectedDemande.profiles?.prenom} {selectedDemande.profiles?.nom}
                </p>
              </div>
            )}
            <div>
              <label className="text-sm font-medium">
                {actionType === "approuver" ? "Commentaire (optionnel)" : "Motif du refus"}
              </label>
              <Textarea
                value={commentaire}
                onChange={(e) => setCommentaire(e.target.value)}
                placeholder={actionType === "approuver" 
                  ? "Commentaire sur l'approbation..." 
                  : "Expliquez le motif du refus..."
                }
                rows={3}
                required={actionType === "refuser"}
              />
            </div>
          </div>
          <DialogFooter>
            <Button 
              variant="outline" 
              onClick={() => {
                setValidationDialog(false);
                setCommentaire("");
                setSelectedDemande(null);
              }}
            >
              Annuler
            </Button>
            <Button
              onClick={handleValidation}
              className={actionType === "approuver" ? "bg-green-600 hover:bg-green-700" : ""}
              variant={actionType === "refuser" ? "destructive" : "default"}
              disabled={actionType === "refuser" && !commentaire.trim()}
            >
              {actionType === "approuver" ? "Approuver" : "Refuser"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}