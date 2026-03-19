// Moteur de calcul de paie intelligent - Gestion des horaires standards et pointages
// ...existing code...

export interface StandardSchedule {
  id: string;
  nom: string;
  horaires_semaine: {
    [key: string]: {
      travaille: boolean;
      debut: string;
      fin: string;
      pauses: Array<{
        debut: string;
        fin: string;
        remuneree: boolean;
      }>;
    };
  };
  jours_feries: string[];
}

export interface TimeEntry {
  profile_id: string;
  date: string;
  entree?: string;
  sortie?: string;
  type_pointage: string;
  timestamp_pointage: string;
}

export interface WorkDayResult {
  date: string;
  heures_theoriques: number;
  heures_pointees: number;
  heures_effectivas: number;
  heures_sup_autorisees: number;
  heures_sup_non_autorisees: number;
  absence: boolean;
  jour_ferie: boolean;
  jour_repos: boolean;
  details: any;
}

export interface PayrollCalculationResult {
  profile_id: string;
  period_start: string;
  period_end: string;
  total_heures_theoriques: number;
  total_heures_effectivas: number;
  total_heures_sup_autorisees: number;
  total_heures_sup_non_autorisees: number;
  total_absences: number;
  details_par_jour: WorkDayResult[];
  taux_horaire: number;
  salaire_brut_calculé: number;
}

/**
 * Récupère l'horaire standard actif
 */
export async function getActiveStandardSchedule(): Promise<StandardSchedule | null> {
  // TODO: Remplacer par appel à l'API Express locale
    .from('horaires_modeles')
    .select('*')
    .eq('is_active', true)
    .single();

  if (error || !data) {
    console.warn('Aucun horaire standard actif trouvé:', error);
    return null;
  }

  return {
    ...data,
    horaires_semaine: data.horaires_semaine as any
  } as StandardSchedule;
}

/**
 * Récupère les pointages d'un employé pour une période
 */
import axios from 'axios';

export async function getEmployeeTimeEntries(
  profileId: string,
  startDate: string,
  endDate: string
): Promise<TimeEntry[]> {
  try {
    const response = await axios.get('/api/time-entries', {
      params: { profileId, startDate, endDate },
    });

    const data = response.data;

    // Grouper les pointages par date et type
    const entriesMap = new Map<string, { entree?: TimeEntry; sortie?: TimeEntry }>();

    data.forEach((entry: any) => {
      const date = entry.timestamp_pointage.split('T')[0];
      if (!entriesMap.has(date)) {
        entriesMap.set(date, {});
      }

      const dayEntries = entriesMap.get(date)!;
      if (entry.type_pointage === 'entree') {
        dayEntries.entree = { ...entry, date };
      } else if (entry.type_pointage === 'sortie') {
        dayEntries.sortie = { ...entry, date };
      }
    });

    // Convertir en liste d'entrées avec entree/sortie par jour
    const result: TimeEntry[] = [];
    entriesMap.forEach((entries, date) => {
      if (entries.entree && entries.sortie) {
        result.push({
          profile_id: profileId,
          date,
          entree: entries.entree.timestamp_pointage.split('T')[1].substring(0, 5),
          sortie: entries.sortie.timestamp_pointage.split('T')[1].substring(0, 5),
          type_pointage: 'entree',
          timestamp_pointage: entries.entree.timestamp_pointage,
        });
      }
    });

    return result;
  } catch (error: unknown) {
    if (error instanceof Error) {
      console.warn('Erreur lors de la récupération des pointages:', error.message);
    } else {
      console.warn('Erreur inconnue lors de la récupération des pointages');
    }
    return [];
  }
}

/**
 * Récupère les déclarations d'heures sup approuvées pour un employé et une période
 */
export async function getApprovedOvertimeDeclarations(
  profileId: string,
  startDate: string,
  endDate: string
): Promise<any[]> {
  try {
    const response = await axios.get('/api/overtime-declarations', {
      params: { profileId, startDate, endDate },
    });

    return response.data || [];
  } catch (error) {
    console.warn('Erreur lors de la récupération des déclarations heures sup:', error);
    return [];
  }
}

/**
 * Calcule les heures travaillées selon l'horaire standard
 */
export function calculateStandardHours(
  schedule: StandardSchedule,
  date: string
): { heures_theoriques: number; jour_travaille: boolean; details: any } {
  const dayOfWeek = new Date(date).toLocaleDateString('fr-FR', { weekday: 'long' });
  const daySchedule = schedule.horaires_semaine[dayOfWeek];

  if (!daySchedule || !daySchedule.travaille) {
    return { heures_theoriques: 0, jour_travaille: false, details: { jour_repos: true } };
  }

  // Calculer les heures de travail théoriques
  const debut = parseTime(daySchedule.debut);
  const fin = parseTime(daySchedule.fin);
  let heures_brutes = (fin - debut) / (1000 * 60 * 60);

  // Déduire les pauses non rémunérées
  let pause_non_remuneree = 0;
  if (daySchedule.pauses) {
    daySchedule.pauses.forEach(pause => {
      if (!pause.remuneree) {
        const debut_pause = parseTime(pause.debut);
        const fin_pause = parseTime(pause.fin);
        pause_non_remuneree += (fin_pause - debut_pause) / (1000 * 60 * 60);
      }
    });
  }

  const heures_theoriques = heures_brutes - pause_non_remuneree;

  return {
    heures_theoriques,
    jour_travaille: true,
    details: {
      debut: daySchedule.debut,
      fin: daySchedule.fin,
      heures_brutes,
      pause_non_remuneree,
      pauses: daySchedule.pauses
    }
  };
}

/**
 * Calcule les heures réellement pointées
 */
export function calculateActualHours(timeEntry: TimeEntry): number {
  if (!timeEntry.entree || !timeEntry.sortie) {
    return 0;
  }

  const entree = parseTime(timeEntry.entree);
  const sortie = parseTime(timeEntry.sortie);
  
  return (sortie - entree) / (1000 * 60 * 60);
}

/**
 * Vérifie si une date est un jour férié
 */
export function isHoliday(date: string, holidays: string[]): boolean {
  return holidays.includes(date);
}

/**
 * Calcule une journée de travail complète
 */
export function calculateWorkDay(
  date: string,
  schedule: StandardSchedule,
  timeEntry: TimeEntry | null,
  overtimeDeclarations: any[]
): WorkDayResult {
  const standardResult = calculateStandardHours(schedule, date);
  const heures_theoriques = standardResult.heures_theoriques;
  const jour_travaille = standardResult.jour_travaille;
  
  // Vérifier si c'est un jour férié
  const jour_ferie = isHoliday(date, schedule.jours_feries);
  const jour_repos = !jour_travaille;
  
  let heures_pointees = 0;
  let heures_effectivas = 0;
  let heures_sup_autorisees = 0;
  let heures_sup_non_autorisees = 0;
  let absence = false;

  if (timeEntry) {
    // Il y a des pointages
    heures_pointees = calculateActualHours(timeEntry);
    
    if (jour_travaille) {
      // Jour de travail normal
      heures_effectivas = Math.min(heures_pointees, heures_theoriques);
      
      if (heures_pointees > heures_theoriques) {
        const heures_sup_totales = heures_pointees - heures_theoriques;
        
        // Vérifier s'il y a une déclaration d'heures sup approuvée
        const hasApprovedOvertime = overtimeDeclarations.some(decl => 
          date >= decl.date_debut && date <= decl.date_fin
        );
        
        if (hasApprovedOvertime) {
          heures_sup_autorisees = heures_sup_totales;
        } else {
          heures_sup_non_autorisees = heures_sup_totales;
        }
      }
    } else if (jour_ferie && heures_pointees > 0) {
      // Travail un jour férié - compter comme heures sup si autorisé
      const hasApprovedOvertime = overtimeDeclarations.some(decl => 
        date >= decl.date_debut && date <= decl.date_fin
      );
      
      if (hasApprovedOvertime) {
        heures_sup_autorisees = heures_pointees;
      } else {
        heures_sup_non_autorisees = heures_pointees;
      }
    }
  } else {
    // Pas de pointages
    if (jour_travaille && !jour_ferie) {
      absence = true;
    }
    // Si c'est un jour férié qui tombe sur un jour de travail, ne pas compter comme absence
    // Si c'est un jour de repos, ignore
  }

  return {
    date,
    heures_theoriques,
    heures_pointees,
    heures_effectivas,
    heures_sup_autorisees,
    heures_sup_non_autorisees,
    absence,
    jour_ferie,
    jour_repos: !jour_travaille,
    details: {
      standard_schedule: standardResult.details,
      time_entry: timeEntry,
      has_approved_overtime: overtimeDeclarations.length > 0
    }
  };
}

/**
 * Moteur principal de calcul intelligent
 */
export async function calculateSmartPayroll(
  profileId: string,
  startDate: string,
  endDate: string,
  tauxHoraire: number
): Promise<PayrollCalculationResult> {
  // 1. Récupérer l'horaire standard actif
  const schedule = await getActiveStandardSchedule();
  if (!schedule) {
    throw new Error('Aucun horaire standard actif trouvé');
  }

  // 2. Récupérer les pointages
  const timeEntries = await getEmployeeTimeEntries(profileId, startDate, endDate);
  const timeEntriesMap = new Map(timeEntries.map(entry => [entry.date, entry]));

  // 3. Récupérer les déclarations d'heures sup
  const overtimeDeclarations = await getApprovedOvertimeDeclarations(profileId, startDate, endDate);

  // 4. Générer toutes les dates de la période
  const dates = generateDateRange(startDate, endDate);
  
  // 5. Calculer chaque jour
  const details_par_jour: WorkDayResult[] = dates.map(date => {
    const timeEntry = timeEntriesMap.get(date) || null;
    return calculateWorkDay(date, schedule, timeEntry, overtimeDeclarations);
  });

  // 6. Calculer les totaux
  const totals = details_par_jour.reduce(
    (acc, day) => ({
      total_heures_theoriques: acc.total_heures_theoriques + day.heures_theoriques,
      total_heures_effectivas: acc.total_heures_effectivas + day.heures_effectivas,
      total_heures_sup_autorisees: acc.total_heures_sup_autorisees + day.heures_sup_autorisees,
      total_heures_sup_non_autorisees: acc.total_heures_sup_non_autorisees + day.heures_sup_non_autorisees,
      total_absences: acc.total_absences + (day.absence ? day.heures_theoriques : 0)
    }),
    {
      total_heures_theoriques: 0,
      total_heures_effectivas: 0,
      total_heures_sup_autorisees: 0,
      total_heures_sup_non_autorisees: 0,
      total_absences: 0
    }
  );

  // 7. Calculer le salaire brut
  const salaire_heures_normales = totals.total_heures_effectivas * tauxHoraire;
  const salaire_heures_sup = totals.total_heures_sup_autorisees * tauxHoraire * 1.25; // Majoration 25%
  const salaire_brut_calculé = salaire_heures_normales + salaire_heures_sup;

  return {
    profile_id: profileId,
    period_start: startDate,
    period_end: endDate,
    ...totals,
    details_par_jour,
    taux_horaire: tauxHoraire,
    salaire_brut_calculé
  };
}

// Fonctions utilitaires
function parseTime(timeStr: string): number {
  const [hours, minutes] = timeStr.split(':').map(Number);
  const today = new Date();
  today.setHours(hours, minutes, 0, 0);
  return today.getTime();
}

function generateDateRange(startDate: string, endDate: string): string[] {
  const dates: string[] = [];
  const current = new Date(startDate);
  const end = new Date(endDate);

  while (current <= end) {
    dates.push(current.toISOString().split('T')[0]);
    current.setDate(current.getDate() + 1);
  }

  return dates;
}