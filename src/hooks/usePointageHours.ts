import { useMemo } from "react";
import { calculateRealHours, getDayKey, type PointageRecord, type DemandeHeuresSup } from "@/lib/pointage-calculations";

export type HoraireActif = {
  horaires_semaine: {
    [key: string]: {
      actif: boolean;
      heureDebut: string;
      heureFin: string;
      pauses?: Array<{
        id: string;
        nom: string;
        heureDebut: string;
        heureFin: string;
        remuneree: boolean;
      }>;
    };
  };
};

/**
 * Hook pour calculer les heures réelles d'un pointage
 */
export function usePointageHours(
  pointage: PointageRecord,
  allPointages: PointageRecord[],
  horaireActif: HoraireActif | null,
  demandesHeuresSup: DemandeHeuresSup[]
) {
  return useMemo(() => {
    if (!horaireActif) return "-";

    // Obtenir la date et le jour de la semaine
    const currentDate = pointage.timestamp_pointage.split('T')[0]; // YYYY-MM-DD
    const dayKey = getDayKey(currentDate);
    
    console.log(`HOOK DEBUG: ${currentDate} -> ${dayKey}`, {
      availableDays: Object.keys(horaireActif.horaires_semaine),
      foundDay: !!horaireActif.horaires_semaine?.[dayKey]
    });
    
    // Obtenir la configuration d'horaire pour ce jour
    const horaireJour = horaireActif.horaires_semaine?.[dayKey];
    console.log(`HORAIRE JOUR pour ${dayKey}:`, horaireJour);
    if (!horaireJour) return "-";

    // Vérifier s'il y a une demande d'heures supplémentaires approuvée
    const demandeHeuresSup = demandesHeuresSup.find(d => 
      currentDate >= d.date_debut && 
      currentDate <= d.date_fin && 
      d.statut === 'approuve'
    );

    // Calculer les heures réelles
    return calculateRealHours(
      currentDate,
      allPointages,
      horaireJour,
      demandeHeuresSup
    );
  }, [pointage.timestamp_pointage, allPointages, horaireActif, demandesHeuresSup]);
}