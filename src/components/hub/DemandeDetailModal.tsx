import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Badge } from "@/components/ui/badge";
import { format } from "date-fns";
import { fr } from "date-fns/locale";

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
}

interface DemandeDetailModalProps {
  demande: DemandeRh | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function DemandeDetailModal({ demande, open, onOpenChange }: DemandeDetailModalProps) {
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

  const renderCorrectionDetails = () => {
    if (demande.type_demande !== 'correction_pointage' || !demande.donnees_originales || !demande.donnees_corrigees) {
      return null;
    }

    return (
      <div className="space-y-4">
        <div className="border rounded-lg p-4">
          <h4 className="font-semibold mb-3 text-destructive">Valeurs actuelles</h4>
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <span className="font-medium">Type:</span>
              <Badge variant="outline" className="ml-2">
                {demande.donnees_originales.type === 'entree' ? 'Entrée' : 'Sortie'}
              </Badge>
            </div>
            <div>
              <span className="font-medium">Heure:</span>
              <span className="ml-2">{demande.donnees_originales.heure}</span>
            </div>
            <div>
              <span className="font-medium">Date:</span>
              <span className="ml-2">
                {format(new Date(demande.donnees_originales.date), "dd MMMM yyyy", { locale: fr })}
              </span>
            </div>
          </div>
        </div>

        <div className="border rounded-lg p-4">
          <h4 className="font-semibold mb-3 text-green-600">Valeurs demandées</h4>
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <span className="font-medium">Type:</span>
              <Badge variant="outline" className="ml-2">
                {demande.donnees_corrigees.type === 'entree' ? 'Entrée' : 'Sortie'}
              </Badge>
            </div>
            <div>
              <span className="font-medium">Heure:</span>
              <span className="ml-2">{demande.donnees_corrigees.heure}</span>
            </div>
            <div>
              <span className="font-medium">Date:</span>
              <span className="ml-2">
                {format(new Date(demande.donnees_corrigees.date), "dd MMMM yyyy", { locale: fr })}
              </span>
            </div>
          </div>
        </div>

        {(demande.donnees_originales.type !== demande.donnees_corrigees.type ||
          demande.donnees_originales.heure !== demande.donnees_corrigees.heure) && (
          <div className="bg-blue-50 p-4 rounded-lg">
            <h4 className="font-semibold mb-2 text-blue-700">Changements demandés</h4>
            <ul className="text-sm text-blue-600 space-y-1">
              {demande.donnees_originales.type !== demande.donnees_corrigees.type && (
                <li>
                  • Type: {demande.donnees_originales.type === 'entree' ? 'Entrée' : 'Sortie'} → {demande.donnees_corrigees.type === 'entree' ? 'Entrée' : 'Sortie'}
                </li>
              )}
              {demande.donnees_originales.heure !== demande.donnees_corrigees.heure && (
                <li>
                  • Heure: {demande.donnees_originales.heure} → {demande.donnees_corrigees.heure}
                </li>
              )}
            </ul>
          </div>
        )}
      </div>
    );
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-3">
            {demande.titre}
            <Badge className={getStatusColor(demande.statut)}>
              {getStatusLabel(demande.statut)}
            </Badge>
          </DialogTitle>
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

          {/* Description */}
          <div>
            <span className="font-medium">Description:</span>
            <p className="text-sm text-muted-foreground mt-1 bg-muted p-3 rounded-lg">
              {demande.description}
            </p>
          </div>

          {/* Détails spécifiques aux corrections de pointage */}
          {renderCorrectionDetails()}

          {/* Motif de refus si applicable */}
          {demande.statut === 'refuse' && demande.motif_refus && (
            <div className="bg-red-50 p-4 rounded-lg">
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