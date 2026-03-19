import React from "react";
import { format } from "date-fns";
import { fr } from "date-fns/locale";
import { getDayKey, type PointageRecord } from "@/lib/pointage-calculations";
import { type HoraireActif } from "@/hooks/usePointageHours";

interface ConfiguredHourCellProps {
  pointage: PointageRecord;
  horaireActif: HoraireActif | null;
}

export function ConfiguredHourCell({ pointage, horaireActif }: ConfiguredHourCellProps) {
  if (!horaireActif) return <>-</>;

  // Obtenir la date et le jour de la semaine
  const currentDate = pointage.timestamp_pointage.split('T')[0];
  const dayKey = getDayKey(currentDate);
  
  // Obtenir la configuration d'horaire pour ce jour
  const horaireJour = horaireActif.horaires_semaine?.[dayKey];
  if (!horaireJour || !horaireJour.heureDebut || !horaireJour.heureFin) {
    return <>-</>;
  }

  // Afficher l'heure configurée selon le type de pointage
  const configuredHour = pointage.type_pointage === "entree" 
    ? horaireJour.heureDebut 
    : horaireJour.heureFin;

  return <>{configuredHour}</>;
}