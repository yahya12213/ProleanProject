import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { format } from "date-fns";
import { fr } from "date-fns/locale";
import { Trash2, Clock, MapPin, StickyNote } from "lucide-react";

interface DemandeRh {
  id: string;
  titre: string;
  description: string;
  type_demande: string;
  statut: string;
  date_debut?: string;
  date_fin?: string;
  montant?: number;
  created_at: string;
  donnees_originales?: any;
  donnees_corrigees?: any;
  motif_refus?: string;
  pointage_id?: string;
}

interface ImprovedDemandeDetailModalProps {
  demande: DemandeRh | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onDelete?: (demandeId: string) => void;
  showDeleteButton?: boolean;
}

export function ImprovedDemandeDetailModal({ 
  demande, 
  open, 
  onOpenChange,
  onDelete,
  showDeleteButton = false
}: ImprovedDemandeDetailModalProps) {
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
      case "en_attente": return "bg-yellow-100 text-yellow-800";
      case "approuve": return "bg-green-100 text-green-800";
      case "refuse": return "bg-red-100 text-red-800";
      default: return "bg-gray-100 text-gray-800";
    }
  };

  const getStatusLabel = (statut: string) => {
    switch (statut) {
      case "en_attente": return "En attente";
      case "approuve": return "Approuvé";
      case "refuse": return "Refusé";
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

  const renderCorrectionDetails = () => {
    if (demande.type_demande !== 'correction_pointage' || !demande.donnees_originales || !demande.donnees_corrigees) {
      return null;
    }

    const original = demande.donnees_originales;
    const corrigee = demande.donnees_corrigees;

    return (
      <div className="space-y-4">
        <h4 className="font-semibold text-lg">Comparaison des modifications</h4>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Valeurs actuelles */}
          <div className="border border-red-200 rounded-lg p-4 bg-red-50">
            <h5 className="font-semibold mb-3 text-red-700 flex items-center gap-2">
              <Clock className="h-4 w-4" />
              Valeurs actuelles
            </h5>
            <div className="space-y-3 text-sm">
              <div>
                <span className="font-medium">Type:</span>
                <Badge variant="outline" className="ml-2">
                  {getTypePointageLabel(original.type_pointage)}
                </Badge>
              </div>
              <div>
                <span className="font-medium">Date et heure:</span>
                <div className="ml-2 text-gray-700">
                  {format(new Date(original.timestamp_pointage), "dd MMMM yyyy 'à' HH:mm", { locale: fr })}
                </div>
              </div>
              {original.localisation && (
                <div className="flex items-start gap-2">
                  <MapPin className="h-4 w-4 mt-0.5 text-gray-500" />
                  <div>
                    <span className="font-medium">Lieu:</span>
                    <div className="text-gray-700">{original.localisation}</div>
                  </div>
                </div>
              )}
              {original.notes && (
                <div className="flex items-start gap-2">
                  <StickyNote className="h-4 w-4 mt-0.5 text-gray-500" />
                  <div>
                    <span className="font-medium">Notes:</span>
                    <div className="text-gray-700">{original.notes}</div>
                  </div>
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
            <div className="space-y-3 text-sm">
              <div>
                <span className="font-medium">Type:</span>
                <Badge variant="outline" className="ml-2">
                  {getTypePointageLabel(corrigee.type_pointage)}
                </Badge>
                {original.type_pointage !== corrigee.type_pointage && (
                  <span className="ml-2 text-green-600 font-medium">✓ Modifié</span>
                )}
              </div>
              <div>
                <span className="font-medium">Date et heure:</span>
                <div className="ml-2 text-gray-700">
                  {format(new Date(corrigee.timestamp_pointage), "dd MMMM yyyy 'à' HH:mm", { locale: fr })}
                </div>
                {original.timestamp_pointage !== corrigee.timestamp_pointage && (
                  <span className="ml-2 text-green-600 font-medium">✓ Modifié</span>
                )}
              </div>
              {corrigee.localisation && (
                <div className="flex items-start gap-2">
                  <MapPin className="h-4 w-4 mt-0.5 text-gray-500" />
                  <div>
                    <span className="font-medium">Lieu:</span>
                    <div className="text-gray-700">{corrigee.localisation}</div>
                    {original.localisation !== corrigee.localisation && (
                      <span className="ml-2 text-green-600 font-medium">✓ Modifié</span>
                    )}
                  </div>
                </div>
              )}
              {corrigee.notes && (
                <div className="flex items-start gap-2">
                  <StickyNote className="h-4 w-4 mt-0.5 text-gray-500" />
                  <div>
                    <span className="font-medium">Notes:</span>
                    <div className="text-gray-700">{corrigee.notes}</div>
                    {original.notes !== corrigee.notes && (
                      <span className="ml-2 text-green-600 font-medium">✓ Modifié</span>
                    )}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Justification */}
        {corrigee.justification && (
          <div className="bg-blue-50 p-4 rounded-lg">
            <h5 className="font-semibold mb-2 text-blue-700">Justification</h5>
            <p className="text-sm text-blue-600">{corrigee.justification}</p>
          </div>
        )}
      </div>
    );
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
            {showDeleteButton && demande.statut === 'en_attente' && onDelete && (
              <Button
                variant="destructive"
                size="sm"
                onClick={() => {
                  onDelete(demande.id);
                  onOpenChange(false);
                }}
              >
                <Trash2 className="h-4 w-4 mr-2" />
                Supprimer
              </Button>
            )}
          </div>
          <DialogDescription>
            Détails de la demande {getTypeLabel(demande.type_demande)}
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
                {format(new Date(demande.created_at), "dd MMMM yyyy 'à' HH:mm", { locale: fr })}
              </p>
            </div>
            {demande.date_debut && (
              <div>
                <span className="font-medium">Date de début:</span>
                <p className="text-sm text-muted-foreground mt-1">
                  {format(new Date(demande.date_debut), "dd MMMM yyyy", { locale: fr })}
                </p>
              </div>
            )}
            {demande.date_fin && (
              <div>
                <span className="font-medium">Date de fin:</span>
                <p className="text-sm text-muted-foreground mt-1">
                  {format(new Date(demande.date_fin), "dd MMMM yyyy", { locale: fr })}
                </p>
              </div>
            )}
            {demande.montant && (
              <div>
                <span className="font-medium">Montant:</span>
                <p className="text-sm text-muted-foreground mt-1">
                  {demande.montant.toLocaleString()} MAD
                </p>
              </div>
            )}
          </div>

          {/* Description générale */}
          {demande.description && demande.type_demande !== 'correction_pointage' && (
            <div>
              <span className="font-medium">Description:</span>
              <p className="text-sm text-muted-foreground mt-1 bg-muted p-3 rounded-lg">
                {demande.description}
              </p>
            </div>
          )}

          {/* Détails spécifiques aux demandes de congé */}
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
                      {format(new Date(demande.date_debut), "dd MMMM yyyy", { locale: fr })}
                    </div>
                  </div>
                )}
                {demande.date_fin && (
                  <div className="border border-orange-200 rounded-lg p-4 bg-orange-50">
                    <h5 className="font-semibold mb-3 text-orange-700 flex items-center gap-2">
                      🔴 Date de retour
                    </h5>
                    <div className="text-lg font-medium text-orange-800">
                      {format(new Date(demande.date_fin), "dd MMMM yyyy", { locale: fr })}
                    </div>
                  </div>
                )}
              </div>
              {demande.date_debut && demande.date_fin && (
                <div className="bg-gray-50 p-4 rounded-lg border">
                  <h5 className="font-semibold mb-2 text-gray-700">Durée du congé</h5>
                  <p className="text-sm text-gray-600">
                    {Math.ceil((new Date(demande.date_fin).getTime() - new Date(demande.date_debut).getTime()) / (1000 * 60 * 60 * 24))} jour(s)
                  </p>
                </div>
              )}
            </div>
          )}

          {/* Détails spécifiques aux corrections de pointage */}
          {renderCorrectionDetails()}

          {/* Motif de refus si applicable */}
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