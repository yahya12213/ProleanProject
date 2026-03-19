import { useEffect, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
// Supabase supprimé, toute la logique doit passer par l'API Express locale
import { Eye } from "lucide-react";

interface PointageStatusIndicatorProps {
  pointageId: string;
}

interface DemandeCorrection {
  id: string;
  statut: string;
  titre: string;
  donnees_originales: any;
  donnees_corrigees: any;
  description: string;
}

export function PointageStatusIndicator({ pointageId }: PointageStatusIndicatorProps) {
  const [demande, setDemande] = useState<DemandeCorrection | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const loadDemandeCorrection = async () => {
      try {
  // TODO: Remplacer par appel API Express ou mock
          .from('demandes_rh')
          .select('*')
          .eq('pointage_id', pointageId)
          .eq('type_demande', 'correction_pointage')
          .order('created_at', { ascending: false })
          .limit(1);

        if (error) {
          console.error('Erreur lors du chargement de la demande:', error);
          return;
        }

        if (data && data.length > 0) {
          setDemande(data[0]);
        }
      } catch (error) {
        console.error('Erreur:', error);
      } finally {
        setLoading(false);
      }
    };

    loadDemandeCorrection();
  }, [pointageId]);

  if (loading || !demande) {
    return null;
  }

  const getStatusBadge = (statut: string) => {
    switch (statut) {
      case 'en_attente':
        return (
          <Badge variant="outline" className="text-orange-600 border-orange-600">
            Correction en attente
          </Badge>
        );
      case 'approuve':
        return (
          <Badge variant="outline" className="text-green-600 border-green-600">
            Correction approuvée
          </Badge>
        );
      case 'refuse':
        return (
          <Badge variant="outline" className="text-red-600 border-red-600">
            Correction refusée
          </Badge>
        );
      default:
        return null;
    }
  };

  return (
    <div className="flex items-center gap-2">
      {getStatusBadge(demande.statut)}
    </div>
  );
}