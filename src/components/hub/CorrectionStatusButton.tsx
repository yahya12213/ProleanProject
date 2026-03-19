import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
// Supabase supprimé, toute la logique doit passer par l'API Express locale
import { Edit2, Clock, CheckCircle, XCircle } from "lucide-react";

interface CorrectionStatusButtonProps {
  pointageId: string;
  onOpenDialog: () => void;
  isVirtual?: boolean;
  virtualType?: 'weekend' | 'holiday' | 'absent';
}

interface DemandeCorrection {
  id: string;
  statut: string;
}

export function CorrectionStatusButton({ pointageId, onOpenDialog, isVirtual = false, virtualType }: CorrectionStatusButtonProps) {
  const [demande, setDemande] = useState<DemandeCorrection | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const loadDemandeCorrection = async () => {
      try {
  // TODO: Remplacer par appel API Express ou mock
          .from('demandes_rh')
          .select('id, statut')
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

    // Écouter les mises à jour en temps réel des demandes RH
  // TODO: Remplacer par appel API Express ou mock
      .channel(`correction-status-${pointageId}`)
      .on(
        'postgres_changes',
        {
          event: '*', // Écouter tous les événements (INSERT, UPDATE, DELETE)
          schema: 'public',
          table: 'demandes_rh',
          filter: `pointage_id=eq.${pointageId}`
        },
        (payload) => {
          console.log('Mise à jour temps réel demande correction:', payload);
          
          if (payload.eventType === 'UPDATE' || payload.eventType === 'INSERT') {
            const newData = payload.new as any;
            if (newData && newData.type_demande === 'correction_pointage') {
              setDemande({
                id: newData.id,
                statut: newData.statut
              });
            }
          } else if (payload.eventType === 'DELETE') {
            setDemande(null);
          }
        }
      )
      .subscribe();

    // Cleanup lors du démontage du composant
    return () => {
  // TODO: Remplacer par appel API Express ou mock
    };
  }, [pointageId]);

  const getButtonProps = () => {
    // Gestion spéciale pour les pointages virtuels
    if (isVirtual) {
      const virtualColors = {
        weekend: "text-gray-600 border-gray-400 hover:bg-gray-50",
        holiday: "text-yellow-600 border-yellow-400 hover:bg-yellow-50",
        absent: "text-blue-600 border-blue-400 hover:bg-blue-50"
      };
      
      return {
        variant: "outline" as const,
        className: virtualColors[virtualType || 'absent'],
        icon: Edit2,
        text: "Corriger"
      };
    }

    if (loading || !demande) {
      return {
        variant: "outline" as const,
        className: "",
        icon: Edit2,
        text: "Corriger"
      };
    }

    switch (demande.statut) {
      case 'en_attente':
        return {
          variant: "outline" as const,
          className: "text-orange-600 border-orange-600 hover:bg-orange-50",
          icon: Edit2,
          text: "Corriger"
        };
      case 'approuve':
        return {
          variant: "outline" as const,
          className: "text-green-600 border-green-600 hover:bg-green-50",
          icon: Edit2,
          text: "Corriger"
        };
      case 'refuse':
        return {
          variant: "outline" as const,
          className: "text-red-600 border-red-600 hover:bg-red-50",
          icon: Edit2,
          text: "Corriger"
        };
      default:
        return {
          variant: "outline" as const,
          className: "",
          icon: Edit2,
          text: "Corriger"
        };
    }
  };

  const buttonProps = getButtonProps();
  const IconComponent = buttonProps.icon;

  return (
    <Button
      variant={buttonProps.variant}
      size="sm"
      className={buttonProps.className}
      onClick={onOpenDialog}
      disabled={demande?.statut === 'approuve'}
    >
      <IconComponent className="h-4 w-4 mr-2" />
      {buttonProps.text}
    </Button>
  );
}