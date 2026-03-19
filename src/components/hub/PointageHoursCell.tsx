import React from "react";
import { usePointageHours, type HoraireActif } from "@/hooks/usePointageHours";
import { type PointageRecord, type DemandeHeuresSup } from "@/lib/pointage-calculations";

interface PointageHoursCellProps {
  pointage: PointageRecord;
  allPointages: PointageRecord[];
  horaireActif: HoraireActif | null;
  demandesHeuresSup: DemandeHeuresSup[];
}

export function PointageHoursCell({
  pointage,
  allPointages,
  horaireActif,
  demandesHeuresSup
}: PointageHoursCellProps) {
  // Utiliser directement heures_reelles de la base de données
  if (pointage.heures_reelles !== null && pointage.heures_reelles !== undefined) {
    return <>{pointage.heures_reelles.toFixed(2)}h</>;
  }

  // Fallback vers le calcul si heures_reelles n'est pas disponible
  const realHours = usePointageHours(
    pointage,
    allPointages,
    horaireActif,
    demandesHeuresSup
  );

  return <>{realHours}</>;
}