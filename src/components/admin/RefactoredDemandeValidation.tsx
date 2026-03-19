import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useToast } from "@/hooks/use-toast";
import { supabase } from "@/integrations/supabase/client";
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
  Check,
  X
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
  motif_refus?: string | null;
  profiles?: {
    nom: string;
    prenom: string;
    email: string;
  } | null;
}

interface DemandeDetailModalProps {
  demande: DemandeRh | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

// Modal simplifiée pour les détails des demandes
function DemandeDetailModal({ demande, open, onOpenChange }: DemandeDetailModalProps) {
  if (!demande) return null;

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

  const formatDate = (dateStr: string) => {
    try {
      return format(new Date(dateStr), "dd MMMM yyyy", { locale: fr });
    } catch {
      return dateStr;
    }
  };

  const formatDateTime = (dateStr: string) => {
    try {
      return format(new Date(dateStr), "dd MMMM yyyy 'à' HH:mm", { locale: fr });
    } catch {
      return dateStr;
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <DialogTitle>{demande.titre}</DialogTitle>
              <Badge className={getStatusColor(demande.statut)}>
                {getStatusLabel(demande.statut)}
              </Badge>
            </div>
          </div>
          <DialogDescription>
            Détails de la demande {getTypeLabel(demande.type_demande)} - {demande.profiles?.prenom} {demande.profiles?.nom}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-6">
          {/* Informations générales */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <span className="font-medium">Type de demande:</span>
              <p className="text-sm text-muted-foreground mt-1">
                {getTypeLabel(demande.type_demande)}
              </p>
            </div>
            <div>
              <span className="font-medium">Date de création:</span>
              <p className="text-sm text-muted-foreground mt-1">
                {formatDateTime(demande.created_at)}
              </p>
            </div>
          </div>

          {/* Description générale */}
          {demande.description && (
            <div>
              <span className="font-medium">Description:</span>
              <p className="text-sm text-muted-foreground mt-1 bg-muted p-3 rounded-lg">
                {demande.description}
              </p>
            </div>
          )}

          {/* Cartes colorées pour les demandes de congé */}
          {demande.type_demande === 'conges' && (demande.date_debut || demande.date_fin) && (
            <div className="space-y-4">
              <h4 className="font-semibold text-lg">Détails du congé</h4>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {demande.date_debut && (
                  <div className="border border-blue-200 rounded-lg p-4 bg-blue-50">
                    <h5 className="font-semibold mb-3 text-blue-700 flex items-center gap-2">
                      🟢 Date d'entrée en congé
                    </h5>
                    <div className="text-lg font-medium text-blue-800">
                      {formatDate(demande.date_debut)}
                    </div>
                  </div>
                )}
                {demande.date_fin && (
                  <div className="border border-orange-200 rounded-lg p-4 bg-orange-50">
                    <h5 className="font-semibold mb-3 text-orange-700 flex items-center gap-2">
                      🔴 Date de retour
                    </h5>
                    <div className="text-lg font-medium text-orange-800">
                      {formatDate(demande.date_fin)}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Détails pour les corrections de pointage */}
          {demande.type_demande === 'correction_pointage' && demande.donnees_originales && demande.donnees_corrigees && (
            <div className="space-y-4">
              <h4 className="font-semibold text-lg">Détails de la correction</h4>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="border border-red-200 rounded-lg p-4 bg-red-50">
                  <h5 className="font-semibold mb-3 text-red-700">Valeurs actuelles</h5>
                  <div className="space-y-2 text-sm">
                    <div><strong>Type:</strong> {demande.donnees_originales.type_pointage || 'Non défini'}</div>
                    <div><strong>Date:</strong> {demande.donnees_originales.timestamp_pointage ? formatDateTime(demande.donnees_originales.timestamp_pointage) : 'Non défini'}</div>
                    {demande.donnees_originales.localisation && (
                      <div><strong>Lieu:</strong> {demande.donnees_originales.localisation}</div>
                    )}
                  </div>
                </div>
                <div className="border border-green-200 rounded-lg p-4 bg-green-50">
                  <h5 className="font-semibold mb-3 text-green-700">Valeurs demandées</h5>
                  <div className="space-y-2 text-sm">
                    <div><strong>Type:</strong> {demande.donnees_corrigees.type_pointage || 'Non défini'}</div>
                    <div><strong>Date:</strong> {demande.donnees_corrigees.timestamp_pointage ? formatDateTime(demande.donnees_corrigees.timestamp_pointage) : 'Non défini'}</div>
                    {demande.donnees_corrigees.localisation && (
                      <div><strong>Lieu:</strong> {demande.donnees_corrigees.localisation}</div>
                    )}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Motif de refus */}
          {demande.statut === 'refuse' && demande.motif_refus && (
            <div className="bg-red-50 p-4 rounded-lg border border-red-200">
              <span className="font-medium text-red-700">Motif du refus:</span>
              <p className="text-sm text-red-600 mt-1">
                {demande.motif_refus}
              </p>
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}

export function RefactoredDemandeValidation() {
  const [demandes, setDemandes] = useState<DemandeRh[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState("en_attente");
  const [selectedDemande, setSelectedDemande] = useState<DemandeRh | null>(null);
  const [validationDialog, setValidationDialog] = useState(false);
  const [detailDialog, setDetailDialog] = useState(false);
  const [commentaire, setCommentaire] = useState("");
  const [actionType, setActionType] = useState<"approuver" | "refuser">("approuver");
  const { toast } = useToast();

  useEffect(() => {
    loadDemandes();
  }, [filter]);

  const loadDemandes = async () => {
    try {
      setLoading(true);
      
      // Construction de la requête
      let query = supabase.from('demandes_rh').select('*').order('created_at', { ascending: false });
      
      if (filter !== "toutes") {
        query = query.eq('statut', filter as "en_attente" | "approuve" | "refuse" | "en_cours");
      }

      const { data: demandesData, error: demandesError } = await query;
      if (demandesError) {
        console.error('Erreur requête demandes:', demandesError);
        throw demandesError;
      }

      if (!demandesData || demandesData.length === 0) {
        setDemandes([]);
        return;
      }

      // Récupération des profils
      const profileIds = [...new Set(demandesData.map(d => d.demandeur_id))];
      const { data: profilesData, error: profilesError } = await supabase
        .from('profiles')
        .select('id, nom, prenom, email')
        .in('id', profileIds);

      if (profilesError) {
        console.warn('Erreur profils:', profilesError);
      }

      // Assemblage des données
      const demandesWithProfiles = demandesData.map(demande => ({
        ...demande,
        profiles: profilesData?.find(p => p.id === demande.demandeur_id) || null
      }));

      setDemandes(demandesWithProfiles);
    } catch (error) {
      console.error('Erreur chargement demandes:', error);
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
      console.log('Validation demande:', selectedDemande.id, actionType);
      
      // Traitement spécial pour les corrections de pointage approuvées
      if (selectedDemande.type_demande === 'correction_pointage' && 
          actionType === "approuver" && 
          selectedDemande.pointage_id && 
          selectedDemande.donnees_corrigees) {
        
        const corrections = selectedDemande.donnees_corrigees;
        console.log('Mise à jour pointage:', selectedDemande.pointage_id, corrections);
        
        // Utiliser la fonction RPC existante qui gère correctement les types ENUM
        const { error: pointageError } = await supabase.rpc('update_pointage_with_enum', {
          pointage_id: selectedDemande.pointage_id,
          new_type: corrections.type_pointage || null,
          new_timestamp: corrections.timestamp_pointage || null,
          new_localisation: corrections.localisation || null,
          new_notes: corrections.notes || null
        });

        if (pointageError) {
          console.error('Erreur pointage:', pointageError);
          throw pointageError;
        }
        
        console.log('Pointage mis à jour avec succès');
      }

      // Mise à jour de la demande
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
        console.error('Erreur demande:', error);
        throw error;
      }

      console.log('Demande validée avec succès');

      toast({
        title: "Succès",
        description: `Demande ${actionType === "approuver" ? "approuvée" : "refusée"} avec succès`,
      });

      setValidationDialog(false);
      setSelectedDemande(null);
      setCommentaire("");
      await loadDemandes();
    } catch (error) {
      console.error('Erreur validation:', error);
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

  // Formatage sécurisé des dates
  const formatDate = (dateStr: string | null | undefined) => {
    if (!dateStr) return '-';
    try {
      return format(new Date(dateStr), "dd MMM yyyy", { locale: fr });
    } catch {
      return dateStr;
    }
  };

  // Rendu simplifié des détails dans le tableau
  const renderDetailsSummary = (demande: DemandeRh) => {
    if (demande.type_demande === 'correction_pointage' && 
        demande.donnees_originales && 
        demande.donnees_corrigees) {
      return (
        <div className="space-y-1 text-xs">
          <div className="bg-red-50 text-red-800 px-2 py-1 rounded">
            <strong>Actuel:</strong> {demande.donnees_originales.type_pointage || 'N/D'}
          </div>
          <div className="bg-green-50 text-green-800 px-2 py-1 rounded">
            <strong>Demandé:</strong> {demande.donnees_corrigees.type_pointage || 'N/D'}
          </div>
        </div>
      );
    }
    
    if (demande.type_demande === 'conges' && (demande.date_debut || demande.date_fin)) {
      return (
        <div className="space-y-1 text-xs">
          {demande.date_debut && (
            <div className="bg-blue-50 text-blue-800 px-2 py-1 rounded">
              🟢 <strong>Début:</strong> {formatDate(demande.date_debut)}
            </div>
          )}
          {demande.date_fin && (
            <div className="bg-orange-50 text-orange-800 px-2 py-1 rounded">
              🔴 <strong>Fin:</strong> {formatDate(demande.date_fin)}
            </div>
          )}
        </div>
      );
    }
    
    return <span className="text-muted-foreground">-</span>;
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

      {/* Tableau des demandes */}
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
                <TableHead>Titre</TableHead>
                <TableHead>Date création</TableHead>
                <TableHead>Détails</TableHead>
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
                      {formatDate(demande.created_at)}
                    </TableCell>
                    <TableCell>
                      {renderDetailsSummary(demande)}
                    </TableCell>
                    <TableCell>
                      <Badge className={getStatusColor(demande.statut)}>
                        {getStatusLabel(demande.statut)}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <div className="flex gap-2">
                        <Button 
                          variant="outline" 
                          size="sm"
                          onClick={() => {
                            setSelectedDemande(demande);
                            setDetailDialog(true);
                          }}
                        >
                          <Eye className="h-4 w-4 mr-1" />
                          Voir
                        </Button>
                        
                        {demande.statut === "en_attente" && (
                          <>
                            <Button
                              size="sm"
                              variant="default"
                              onClick={() => {
                                setSelectedDemande(demande);
                                setActionType("approuver");
                                setValidationDialog(true);
                              }}
                            >
                              <Check className="h-4 w-4 mr-1" />
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
                              <X className="h-4 w-4 mr-1" />
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

      {/* Modal de détails */}
      <DemandeDetailModal 
        demande={selectedDemande}
        open={detailDialog}
        onOpenChange={setDetailDialog}
      />

      {/* Dialog de validation */}
      <Dialog open={validationDialog} onOpenChange={setValidationDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {actionType === "approuver" ? "Approuver" : "Refuser"} la demande
            </DialogTitle>
            <DialogDescription>
              {selectedDemande?.titre} - {selectedDemande?.profiles?.prenom} {selectedDemande?.profiles?.nom}
            </DialogDescription>
          </DialogHeader>
          
          <div className="space-y-4">
            {actionType === "refuser" && (
              <div>
                <label className="text-sm font-medium">Motif du refus (optionnel)</label>
                <Textarea
                  placeholder="Précisez la raison du refus..."
                  value={commentaire}
                  onChange={(e) => setCommentaire(e.target.value)}
                  className="mt-1"
                />
              </div>
            )}
          </div>
          
          <DialogFooter>
            <Button variant="outline" onClick={() => setValidationDialog(false)}>
              Annuler
            </Button>
            <Button 
              onClick={handleValidation}
              variant={actionType === "approuver" ? "default" : "destructive"}
            >
              {actionType === "approuver" ? "Approuver" : "Refuser"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}