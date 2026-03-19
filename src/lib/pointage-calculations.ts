import { format } from "date-fns";
import { fr } from "date-fns/locale";

export type PointageRecord = {
  id: string;
  timestamp_pointage: string;
  type_pointage: string;
  profile_id: string;
  localisation?: string;
  notes?: string;
  heures_reelles?: number;
};

export type HoraireJour = {
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

export type DemandeHeuresSup = {
  date_debut: string;
  date_fin: string;
  statut: string;
};

/**
 * Calcule les heures réelles travaillées pour une date donnée
 */
export function calculateRealHours(
  currentDate: string,
  pointages: PointageRecord[],
  horaireJour: HoraireJour,
  demandeHeuresSup?: DemandeHeuresSup
): string {
  const dayKey = getDayKey(currentDate);
  
  // Vérifier si l'horaire est configuré et actif
  // Exception: les samedis peuvent être calculés même si pas actifs
  if (!horaireJour || !horaireJour.heureDebut || !horaireJour.heureFin) {
    return "-";
  }
  
  // Les dimanches ne sont jamais calculés s'ils ne sont pas actifs
  if (dayKey === 'dimanche' && !horaireJour.actif) {
    return "-";
  }
  
  // Pour les autres jours (y compris samedi), on peut calculer même si pas actif

  // Filtrer les pointages du jour et les trier par timestamp
  const dayPointages = pointages
    .filter(p => format(new Date(p.timestamp_pointage), "yyyy-MM-dd") === currentDate)
    .sort((a, b) => new Date(a.timestamp_pointage).getTime() - new Date(b.timestamp_pointage).getTime());

  if (dayPointages.length === 0) return "-";

  // Séparer les entrées et sorties
  const entryPointages = dayPointages.filter(p => p.type_pointage === "entree");
  const exitPointages = dayPointages.filter(p => p.type_pointage === "sortie");

  if (entryPointages.length === 0 || exitPointages.length === 0) return "-";

  // Prendre la première entrée et la dernière sortie
  const firstEntry = entryPointages[0];
  const lastExit = exitPointages[exitPointages.length - 1];

  // Créer les objets Date pour l'entrée et la sortie
  let entryTime = new Date(firstEntry.timestamp_pointage);
  let exitTime = new Date(lastExit.timestamp_pointage);

  // Définir les limites d'horaire
  const [heureDebut, minuteDebut] = horaireJour.heureDebut.split(':').map(Number);
  const [heureFin, minuteFin] = horaireJour.heureFin.split(':').map(Number);
  
  const debutHoraire = new Date(currentDate);
  debutHoraire.setHours(heureDebut, minuteDebut, 0, 0);
  
  const finHoraire = new Date(currentDate);
  finHoraire.setHours(heureFin, minuteFin, 0, 0);

  // Appliquer les limites d'horaire (sauf si heures supplémentaires approuvées)
  const hasApprovedOvertime = demandeHeuresSup && 
    currentDate >= demandeHeuresSup.date_debut && 
    currentDate <= demandeHeuresSup.date_fin && 
    demandeHeuresSup.statut === 'approuve';

  if (!hasApprovedOvertime) {
    if (entryTime < debutHoraire) {
      entryTime = debutHoraire;
    }
    if (exitTime > finHoraire) {
      exitTime = finHoraire;
    }
  }

  // Calculer le temps de travail brut
  const workTimeMs = Math.max(0, exitTime.getTime() - entryTime.getTime());
  const workTime = workTimeMs / (1000 * 60 * 60); // Convertir en heures

  // Calculer les pauses non rémunérées
  let totalPausesNonRemunerees = 0;
  const pausesNonRemunerees = horaireJour.pauses?.filter(pause => !pause.remuneree) || [];

  pausesNonRemunerees.forEach(pause => {
    const [debutH, debutM] = pause.heureDebut.split(':').map(Number);
    const [finH, finM] = pause.heureFin.split(':').map(Number);
    
    const pauseStart = new Date(currentDate);
    pauseStart.setHours(debutH, debutM, 0, 0);
    
    const pauseEnd = new Date(currentDate);
    pauseEnd.setHours(finH, finM, 0, 0);
    
    // Calculer le chevauchement entre la pause et la période de présence
    const overlapStart = new Date(Math.max(entryTime.getTime(), pauseStart.getTime()));
    const overlapEnd = new Date(Math.min(exitTime.getTime(), pauseEnd.getTime()));
    
    if (overlapStart < overlapEnd) {
      const dureePause = (overlapEnd.getTime() - overlapStart.getTime()) / (1000 * 60 * 60);
      totalPausesNonRemunerees += dureePause;
    }
  });

  // Calculer les heures réelles
  const realHours = Math.max(0, workTime - totalPausesNonRemunerees);

  // Log de débogage pour comprendre le problème
  console.log(`DEBUG JOUR: ${currentDate} -> ${dayKey}`, {
    horaireJour: `${horaireJour.heureDebut}-${horaireJour.heureFin}`,
    pausesLength: horaireJour.pauses?.length || 0
  });

  // Log de débogage
  console.log(`Calcul heures réelles ${currentDate}:`, {
    entryOriginal: format(new Date(firstEntry.timestamp_pointage), "HH:mm"),
    exitOriginal: format(new Date(lastExit.timestamp_pointage), "HH:mm"),
    entryLimited: format(entryTime, "HH:mm"),
    exitLimited: format(exitTime, "HH:mm"),
    workTime: workTime.toFixed(2),
    pausesNonRemunerees: totalPausesNonRemunerees.toFixed(2),
    pausesConfigures: pausesNonRemunerees.map(p => `${p.heureDebut}-${p.heureFin}`),
    hasApprovedOvertime,
    finalResult: realHours.toFixed(2),
    horaire: `${horaireJour.heureDebut}-${horaireJour.heureFin}`
  });

  return realHours > 0 ? `${realHours.toFixed(2)}h` : "-";
}

/**
 * Obtient la clé du jour de la semaine pour la base de données
 */
export function getDayKey(dateStr: string): string {
  console.log(`🗓️ getDayKey: Traitement de "${dateStr}"`);
  
  try {
    let date: Date;
    
    // Nettoyage et normalisation de la chaîne de date
    const cleanDateStr = dateStr.trim();
    
    // Gestion des différents formats de date
    if (cleanDateStr.includes('/')) {
      // Format DD/MM/YYYY
      const parts = cleanDateStr.split('/');
      if (parts.length !== 3) {
        console.error('🗓️ getDayKey: Format DD/MM/YYYY invalide:', cleanDateStr);
        return 'invalid';
      }
      
      const [day, month, year] = parts.map(num => parseInt(num, 10));
      
      // Validation des parties
      if (isNaN(day) || isNaN(month) || isNaN(year)) {
        console.error('🗓️ getDayKey: Parties de date non numériques:', { day, month, year });
        return 'invalid';
      }
      
      if (day < 1 || day > 31 || month < 1 || month > 12) {
        console.error('🗓️ getDayKey: Valeurs de date hors limites:', { day, month, year });
        return 'invalid';
      }
      
      // Création de la date avec gestion du fuseau horaire UTC pour éviter les décalages
      date = new Date(Date.UTC(year, month - 1, day, 12, 0, 0));
      console.log(`🗓️ getDayKey: Date créée depuis DD/MM/YYYY:`, date.toISOString());
      
    } else if (cleanDateStr.includes('-')) {
      // Format YYYY-MM-DD ou autres formats ISO
      date = new Date(cleanDateStr + 'T12:00:00.000Z'); // Force UTC et milieu de journée
      console.log(`🗓️ getDayKey: Date créée depuis ISO:`, date.toISOString());
      
    } else {
      // Tentative de parsing direct
      date = new Date(cleanDateStr);
      console.log(`🗓️ getDayKey: Date créée par parsing direct:`, date.toISOString());
    }
    
    // Vérification de validité
    if (isNaN(date.getTime())) {
      console.error('🗓️ getDayKey: Date résultante invalide:', date);
      return 'invalid';
    }
    
    // Utiliser date-fns pour obtenir le jour en français
    const dayName = format(date, 'EEEE', { locale: fr }).toLowerCase();
    
    // Debug spécial pour les vendredis
    if (dayName === 'vendredi') {
      console.log(`🎯 VENDREDI DETECTÉ! Date: "${cleanDateStr}" -> ${dayName} (${date.toISOString()})`);
      console.log(`🎯 Date details: jour=${date.getUTCDate()}, mois=${date.getUTCMonth() + 1}, année=${date.getUTCFullYear()}`);
    }
    
    console.log(`🗓️ getDayKey: "${cleanDateStr}" -> ${dayName} (${date.toISOString()})`);
    
    return dayName;
    
  } catch (error) {
    console.error('🗓️ getDayKey: Erreur lors du parsing de la date:', dateStr, error);
    return 'invalid';
  }
}