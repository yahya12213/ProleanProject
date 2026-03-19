import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useToast } from "@/hooks/use-toast";
// Supabase supprimé, toute la logique doit passer par l'API Express locale
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
  FileText,
  MapPin,
  StickyNote
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
  donnees_originales?: any;
  donnees_corrigees?: any;
  profiles?: {
    nom: string;
    prenom: string;
    email: string;
  } | null;
}

export function EnhancedDemandeValidation() {
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
      
  // TODO: Remplacer par appel API Express ou mock
      
      if (filter !== "toutes") {
        query = query.eq('statut', filter as "en_attente" | "approuve" | "refuse" | "en_cours");
      }

      const { data: demandesData, error: demandesError } = await query;
      if (demandesError) throw demandesError;

      if (!demandesData || demandesData.length === 0) {
        setDemandes([]);
        return;
      }

      const profileIds = [...new Set(demandesData.map(d => d.demandeur_id))];
  // TODO: Remplacer par appel API Express ou mock
        .from('profiles')
        .select('id, nom, prenom, email')
        .in('id', profileIds);

      if (profilesError) {
        console.warn('Erreur lors du chargement des profils:', profilesError);
      }

      const demandesWithProfiles = demandesData.map(demande => ({
        ...demande,
        profiles: profilesData?.find(p => p.id === demande.demandeur_id) || null
      }));

      setDemandes(demandesWithProfiles);
    } catch (error) {
      console.error('Error loading demandes:', error);
      toast({
        title: "Erreur",
        description: "Impossible de charger les demandes",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const handleValidation = async () => {
    if (!selectedDemande) return;

    try {
      // Si c'est une correction de pointage approuvée, mettre à jour le pointage
      if (selectedDemande.type_demande === 'correction_pointage' && actionType === "approuver" && selectedDemande.pointage_id && selectedDemande.donnees_corrigees) {
        const corrections = selectedDemande.donnees_corrigees;
        
        // Mettre à jour le pointage original
  // TODO: Remplacer par appel API Express ou mock
          .from('pointages')
          .update({
            type_pointage: corrections.type_pointage,
            timestamp_pointage: corrections.timestamp_pointage,
            localisation: corrections.localisation || null,
            notes: corrections.notes || null,
            updated_at: new Date().toISOString()
          })
          .eq('id', selectedDemande.pointage_id);

        if (pointageError) {
          console.error('Erreur lors de la mise à jour du pointage:', pointageError);
          throw pointageError;
        }
      }

      // Mettre à jour le statut de la demande
  // TODO: Remplacer par appel API Express ou mock
        .from('demandes_rh')
        .update({
          statut: actionType === "approuver" ? "approuve" : "refuse",
          motif_refus: actionType === "refuser" ? commentaire : null,
          date_approbation: new Date().toISOString(),
          updated_at: new Date().toISOString()
        })
        .eq('id', selectedDemande.id);

      if (error) throw error;

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
        description: "Impossible de valider la demande",
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

  const getTypePointageLabel = (type: string) => {
    switch (type) {
      case "entree": return "Entrée";
      case "sortie": return "Sortie";
      case "pause_debut": return "Début pause";
      case "pause_fin": return "Fin pause";
      default: return type;
    }
  };

  const renderCorrectionDetails = (demande: DemandeRh) => {
    if (demande.type_demande !== 'correction_pointage' || !demande.donnees_originales || !demande.donnees_corrigees) {
      return "Aucun détail disponible";
    }

    const original = demande.donnees_originales;
    const corrigee = demande.donnees_corrigees;
    const changes = [];

    if (original.type_pointage !== corrigee.type_pointage) {
      changes.push(`Type: ${getTypePointageLabel(original.type_pointage)} → ${getTypePointageLabel(corrigee.type_pointage)}`);
    }

    if (original.timestamp_pointage !== corrigee.timestamp_pointage) {
      const originalTime = format(new Date(original.timestamp_pointage), "dd/MM/yyyy HH:mm", { locale: fr });
      const corrigeeTime = format(new Date(corrigee.timestamp_pointage), "dd/MM/yyyy HH:mm", { locale: fr });
      changes.push(`Heure: ${originalTime} → ${corrigeeTime}`);
    }

    if (original.localisation !== corrigee.localisation) {
      changes.push(`Lieu: ${original.localisation || 'Non défini'} → ${corrigee.localisation || 'Non défini'}`);
    }

    if (original.notes !== corrigee.notes) {
      changes.push(`Notes: ${original.notes || 'Aucune'} → ${corrigee.notes || 'Aucune'}`);
    }

    return changes.length > 0 ? changes.join('; ') : 'Aucune modification détectée';
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
              <CardTitle>Validation des Demandes RH - Interface Améliorée</CardTitle>
              <CardDescription>
                Gérez les demandes avec détails avancés pour les corrections de pointage
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
                <TableHead>Titre</TableHead>
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
                    <TableCell className="font-medium">{demande.titre}</TableCell>
                    <TableCell>
                      {format(new Date(demande.created_at), "dd MMM yyyy", { locale: fr })}
                    </TableCell>
                    <TableCell className="max-w-xs">
                      {demande.type_demande === 'correction_pointage' ? (
                        <div className="text-sm">
                          <p className="truncate">{renderCorrectionDetails(demande)}</p>
                        </div>
                      ) : (
                        <div className="flex items-center gap-1">
                          <Calendar className="h-4 w-4 text-muted-foreground" />
                          <span className="text-sm">
                            {demande.date_debut && demande.date_fin ? (
                              <>
                                {format(new Date(demande.date_debut), "dd MMM", { locale: fr })} - 
                                {format(new Date(demande.date_fin), "dd MMM yyyy", { locale: fr })}
                              </>
                            ) : "-"}
                          </span>
                        </div>
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
                          <DialogContent className="max-w-4xl">
                            <DialogHeader>
                              <DialogTitle>{demande.titre}</DialogTitle>
                              <DialogDescription>
                                Demande de {getTypeLabel(demande.type_demande)} - {demande.profiles?.prenom} {demande.profiles?.nom}
                              </DialogDescription>
                            </DialogHeader>
                            <div className="space-y-4">
                              {demande.type_demande === 'correction_pointage' && demande.donnees_originales && demande.donnees_corrigees ? (
                                <div className="space-y-4">
                                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                    {/* Valeurs actuelles */}
                                    <div className="border border-red-200 rounded-lg p-4 bg-red-50">
                                      <h5 className="font-semibold mb-3 text-red-700 flex items-center gap-2">
                                        <Clock className="h-4 w-4" />
                                        Valeurs actuelles
                                      </h5>
                                      <div className="space-y-2 text-sm">
                                        <div>
                                          <span className="font-medium">Type:</span>
                                          <Badge variant="outline" className="ml-2">
                                            {getTypePointageLabel(demande.donnees_originales.type_pointage)}
                                          </Badge>
                                        </div>
                                        <div>
                                          <span className="font-medium">Date/Heure:</span>
                                          <div className="ml-2">
                                            {format(new Date(demande.donnees_originales.timestamp_pointage), "dd MMMM yyyy 'à' HH:mm", { locale: fr })}
                                          </div>
                                        </div>
                                        {demande.donnees_originales.localisation && (
                                          <div className="flex items-center gap-2">
                                            <MapPin className="h-4 w-4" />
                                            <span>{demande.donnees_originales.localisation}</span>
                                          </div>
                                        )}
                                        {demande.donnees_originales.notes && (
                                          <div className="flex items-center gap-2">
                                            <StickyNote className="h-4 w-4" />
                                            <span>{demande.donnees_originales.notes}</span>
                                          </div>
                                        )}
                                      </div>
                                    </div>

                                    {/* Valeurs demandées */}
                                    <div className="border border-green-200 rounded-lg p-4 bg-green-50">
                                      <h5 className="font-semibold mb-3 text-green-700 flex items-center gap-2">
                                        <Clock className="h-4 w-4" />
                                        Valeurs demandées
                                      </h5>
                                      <div className="space-y-2 text-sm">
                                        <div>
                                          <span className="font-medium">Type:</span>
                                          <Badge variant="outline" className="ml-2">
                                            {getTypePointageLabel(demande.donnees_corrigees.type_pointage)}
                                          </Badge>
                                        </div>
                                        <div>
                                          <span className="font-medium">Date/Heure:</span>
                                          <div className="ml-2">
                                            {format(new Date(demande.donnees_corrigees.timestamp_pointage), "dd MMMM yyyy 'à' HH:mm", { locale: fr })}
                                          </div>
                                        </div>
                                        {demande.donnees_corrigees.localisation && (
                                          <div className="flex items-center gap-2">
                                            <MapPin className="h-4 w-4" />
                                            <span>{demande.donnees_corrigees.localisation}</span>
                                          </div>
                                        )}
                                        {demande.donnees_corrigees.notes && (
                                          <div className="flex items-center gap-2">
                                            <StickyNote className="h-4 w-4" />
                                            <span>{demande.donnees_corrigees.notes}</span>
                                          </div>
                                        )}
                                      </div>
                                    </div>
                                  </div>
                                  
                                  {demande.donnees_corrigees.justification && (
                                    <div className="bg-blue-50 p-4 rounded-lg">
                                      <h5 className="font-semibold mb-2 text-blue-700">Justification</h5>
                                      <p className="text-sm text-blue-600">{demande.donnees_corrigees.justification}</p>
                                    </div>
                                  )}
                                </div>
                              ) : (
                                <div>
                                  <h4 className="font-medium mb-2">Description</h4>
                                  <p className="text-sm text-muted-foreground">
                                    {demande.description || "Aucune description"}
                                  </p>
                                  {demande.date_debut && (
                                    <div className="mt-4">
                                      <h4 className="font-medium mb-2">Période demandée</h4>
                                      <p className="text-sm">
                                        Du {format(new Date(demande.date_debut), "dd MMMM yyyy", { locale: fr })}
                                        {demande.date_fin && ` au ${format(new Date(demande.date_fin), "dd MMMM yyyy", { locale: fr })}`}
                                      </p>
                                    </div>
                                  )}
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
                ? "Vous allez approuver cette demande. Les corrections de pointage seront appliquées automatiquement."
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
                {selectedDemande.type_demande === 'correction_pointage' && actionType === "approuver" && (
                  <p className="text-sm text-green-600 mt-2">
                    ⚠️ Le pointage sera automatiquement mis à jour avec les nouvelles valeurs
                  </p>
                )}
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