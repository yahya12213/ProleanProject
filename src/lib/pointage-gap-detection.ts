import { format, addDays, isAfter, isBefore, isSameDay, getDay } from "date-fns";
import { fr } from "date-fns/locale";

export interface PointageRecord {
  id: string;
  timestamp_pointage: string;
  type_pointage: string;
  profile_id: string;
  localisation?: string;
  notes?: string;
}

export interface VirtualPointageRecord extends PointageRecord {
  isVirtual?: boolean;
  heures_travaillees?: number;
  isWeekend?: boolean;
  isHoliday?: boolean;
  dayType?: 'weekday' | 'weekend' | 'holiday';
  // Champs calculés
  ecart_minutes?: number;
  heures_reelles?: number;
  heures_configurees?: number;
  heure_configuree_entree?: string;
  heure_configuree_sortie?: string;
}

export interface DateRange {
  startDate: Date;
  endDate: Date;
}

/**
 * Détecte les dates manquantes dans une série de pointages et crée des entrées virtuelles
 */
export function detectMissingDatesAndFill(
  pointages: PointageRecord[],
  dateRange?: DateRange
): VirtualPointageRecord[] {
  if (pointages.length === 0) {
    return [];
  }

  // Trier les pointages par date
  const sortedPointages = [...pointages].sort((a, b) => 
    new Date(a.timestamp_pointage).getTime() - new Date(b.timestamp_pointage).getTime()
  );

  // Déterminer la plage de dates
  let startDate: Date;
  let endDate: Date;

  if (dateRange) {
    startDate = dateRange.startDate;
    endDate = dateRange.endDate;
  } else {
    // Utiliser les dates des pointages existants
    startDate = new Date(sortedPointages[0].timestamp_pointage);
    endDate = new Date(sortedPointages[sortedPointages.length - 1].timestamp_pointage);
  }

  // Grouper les pointages par date
  const pointagesByDate = new Map<string, PointageRecord[]>();
  
  sortedPointages.forEach(pointage => {
    const dateKey = format(new Date(pointage.timestamp_pointage), 'yyyy-MM-dd');
    if (!pointagesByDate.has(dateKey)) {
      pointagesByDate.set(dateKey, []);
    }
    pointagesByDate.get(dateKey)!.push(pointage);
  });

  // Générer toutes les dates dans la plage et créer des entrées virtuelles si nécessaire
  const result: VirtualPointageRecord[] = [];
  let currentDate = new Date(startDate);

  while (isBefore(currentDate, endDate) || isSameDay(currentDate, endDate)) {
    const dateKey = format(currentDate, 'yyyy-MM-dd');
    const existingPointages = pointagesByDate.get(dateKey);

    if (existingPointages && existingPointages.length > 0) {
      // Ajouter les pointages existants
      result.push(...existingPointages.map(p => ({ ...p, isVirtual: false })));
    } else {
      // Créer des pointages virtuels pour les dates manquantes
      const virtualPointages = createVirtualPointagesForDate(currentDate, sortedPointages[0].profile_id);
      result.push(...virtualPointages);
    }

    currentDate = addDays(currentDate, 1);
  }

  return result.sort((a, b) => 
    new Date(b.timestamp_pointage).getTime() - new Date(a.timestamp_pointage).getTime()
  );
}

/**
 * Jours fériés au Maroc (dates fixes et approximatives pour les fêtes religieuses)
 * Note: Les dates des fêtes religieuses varient chaque année selon le calendrier lunaire
 */
const MOROCCAN_HOLIDAYS = {
  // Fêtes fixes
  '01-01': 'Nouvel An',
  '01-11': 'Manifeste de l\'Indépendance',
  '05-01': 'Fête du Travail',
  '07-30': 'Fête du Trône',
  '08-14': 'Journée de Oued Ed-Dahab',
  '08-20': 'Révolution du Roi et du Peuple',
  '08-21': 'Fête de la Jeunesse',
  '11-06': 'Marche Verte',
  '11-18': 'Fête de l\'Indépendance',
  
  // Fêtes religieuses (dates approximatives - à ajuster chaque année)
  // Ces dates changent selon le calendrier lunaire
  '04-10': 'Aid El-Fitr (approximatif)',
  '06-17': 'Aid Al-Adha (approximatif)',
  '07-07': 'Nouvel An Hégire (approximatif)',
  '09-15': 'Mawlid Nabawi (approximatif)'
};

/**
 * Vérifie si une date est un week-end (samedi ou dimanche)
 */
export function isWeekend(date: Date): boolean {
  const dayOfWeek = getDay(date);
  return dayOfWeek === 0 || dayOfWeek === 6; // 0 = dimanche, 6 = samedi
}

/**
 * Vérifie si une date est un jour férié au Maroc
 */
export function isHoliday(date: Date): boolean {
  const monthDay = format(date, 'MM-dd');
  return monthDay in MOROCCAN_HOLIDAYS;
}

/**
 * Obtient le type de jour pour une date donnée
 */
export function getDayType(date: Date): 'weekday' | 'weekend' | 'holiday' {
  if (isHoliday(date)) return 'holiday';
  if (isWeekend(date)) return 'weekend';
  return 'weekday';
}

/**
 * Crée des pointages virtuels (entrée et sortie) pour une date donnée
 */
function createVirtualPointagesForDate(date: Date, profileId: string): VirtualPointageRecord[] {
  const baseDateStr = format(date, 'yyyy-MM-dd');
  const dayType = getDayType(date);
  
  let notes = 'Aucun pointage - Journée manquante';
  if (dayType === 'weekend') {
    notes = 'Week-end';
  } else if (dayType === 'holiday') {
    const monthDay = format(date, 'MM-dd');
    const holidayName = MOROCCAN_HOLIDAYS[monthDay as keyof typeof MOROCCAN_HOLIDAYS];
    notes = `Jour férié - ${holidayName}`;
  }
  
  return [
    {
      id: `virtual-entry-${baseDateStr}`,
      timestamp_pointage: `${baseDateStr}T00:00:00.000Z`,
      type_pointage: 'entree',
      profile_id: profileId,
      localisation: 'Absent',
      notes,
      isVirtual: true,
      heures_travaillees: 0,
      isWeekend: dayType === 'weekend',
      isHoliday: dayType === 'holiday',
      dayType
    },
    {
      id: `virtual-exit-${baseDateStr}`,
      timestamp_pointage: `${baseDateStr}T00:00:00.000Z`,
      type_pointage: 'sortie',
      profile_id: profileId,
      localisation: 'Absent',
      notes,
      isVirtual: true,
      heures_travaillees: 0,
      isWeekend: dayType === 'weekend',
      isHoliday: dayType === 'holiday',
      dayType
    }
  ];
}

/**
 * Obtient la plage de dates pour un mois donné
 */
export function getMonthDateRange(year: string, month: string): DateRange | null {
  if (year === "all" || month === "all") {
    return null;
  }

  const startDate = new Date(parseInt(year), parseInt(month) - 1, 1);
  const endDate = new Date(parseInt(year), parseInt(month), 0); // Dernier jour du mois

  return { startDate, endDate };
}

/**
 * Obtient la plage de dates pour une année donnée
 */
export function getYearDateRange(year: string): DateRange | null {
  if (year === "all") {
    return null;
  }

  const startDate = new Date(parseInt(year), 0, 1); // 1er janvier
  const endDate = new Date(parseInt(year), 11, 31); // 31 décembre

  return { startDate, endDate };
}

/**
 * Vérifie si un pointage est virtuel
 */
export function isVirtualPointage(pointage: VirtualPointageRecord): boolean {
  return pointage.isVirtual === true;
}

/**
 * Calcule les heures travaillées pour une date donnée en prenant en compte les pointages virtuels
 */
export function calculateDayHours(pointages: VirtualPointageRecord[], date: string): number {
  const dayPointages = pointages.filter(p => 
    format(new Date(p.timestamp_pointage), 'yyyy-MM-dd') === date
  );

  // Si il y a des pointages virtuels, retourner 0
  if (dayPointages.some(p => isVirtualPointage(p))) {
    return 0;
  }

  // Sinon, calculer normalement
  const entrees = dayPointages.filter(p => p.type_pointage === 'entree');
  const sorties = dayPointages.filter(p => p.type_pointage === 'sortie');

  if (entrees.length === 0 || sorties.length === 0) {
    return 0;
  }

  const firstEntry = new Date(entrees[0].timestamp_pointage);
  const lastExit = new Date(sorties[sorties.length - 1].timestamp_pointage);

  const diffMs = lastExit.getTime() - firstEntry.getTime();
  return diffMs / (1000 * 60 * 60); // Convertir en heures
}