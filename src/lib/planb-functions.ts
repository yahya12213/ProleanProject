/**
 * PLAN B - Fonctions Utilitaires
 * Fonctions réutilisables pour la base de données PLAN B
 */

import { PLANB_TABLES, PLANB_FUNCTIONS } from './planb-database';

// ===============================================
// TYPES PLAN B
// ===============================================

export type PlanbStatut = 'actif' | 'inactif' | 'suspendu' | 'archive';
export type PlanbNiveau = 'debutant' | 'intermediaire' | 'avance' | 'expert';
export type PlanbTypeFormation = 'physique' | 'en_ligne' | 'hybride';
export type PlanbStatutClasse = 'programmee' | 'en_cours' | 'terminee' | 'annulee';
export type PlanbStatutInscription = 'en_attente' | 'confirmee' | 'validee' | 'annulee' | 'terminee';
export type PlanbStatutCompte = 'valide' | 'non_valide' | 'en_cours' | 'suspendu';
export type PlanbTypeContrat = 'cdi' | 'cdd' | 'stage' | 'freelance' | 'consultant';

// ===============================================
// INTERFACES PLAN B
// ===============================================

export interface PlanbProfile {
  id: string;
  user_id: string;
  nom: string;
  prenom: string;
  email: string;
  telephone?: string;
  photo_url?: string;
  poste?: string;
  departement?: string;
  statut: PlanbStatut;
  created_at: string;
  updated_at: string;
}

export interface PlanbEtudiant {
  id: string;
  nom: string;
  prenom: string;
  cin?: string;
  email?: string;
  telephone?: string;
  whatsapp?: string;
  date_naissance?: string;
  lieu_naissance?: string;
  adresse_complete?: string;
  ville?: string;
  photo_url?: string;
  statut: PlanbStatut;
  created_at: string;
  updated_at: string;
}

export interface PlanbFormation {
  id: string;
  titre: string;
  description?: string;
  reference?: string;
  type_formation: PlanbTypeFormation;
  niveau: PlanbNiveau;
  duree_heures: number;
  duree_jours?: number;
  prix?: number;
  prix_en_ligne?: number;
  statut: PlanbStatut;
  created_at: string;
  updated_at: string;
}

export interface PlanbClasse {
  id: string;
  nom_classe: string;
  formation_id?: string;
  centre_id: string;
  date_debut: string;
  date_fin: string;
  horaire_debut?: string;
  horaire_fin?: string;
  nombre_places: number;
  places_reservees?: number;
  statut: PlanbStatutClasse;
  created_at: string;
  updated_at: string;
}

export interface PlanbInscription {
  id: string;
  etudiant_id: string;
  formation_id: string;
  classe_id?: string;
  numero_inscription?: string;
  student_id_unique?: string;
  date_inscription: string;
  prix_formation?: number;
  remise_accordee?: number;
  prix_final?: number;
  statut_inscription: PlanbStatutInscription;
  statut_compte: PlanbStatutCompte;
  created_at: string;
  updated_at: string;
}

export interface PlanbPaiement {
  id: string;
  inscription_id: string;
  montant: number;
  devise: string;
  methode_paiement: string;
  date_paiement: string;
  valide: boolean;
  created_at: string;
  updated_at: string;
}

// ===============================================
// FONCTIONS UTILITAIRES GÉNÉRALES
// ===============================================

/**
 * Génère un ID étudiant unique pour PLAN B
 */
export async function generatePlanbStudentId(year?: string): Promise<string | null> {
  try {
    const response = await fetch(`/api/student-id?year=${year || ''}`);
    if (!response.ok) {
      console.error('Erreur génération ID PLANB:', response.statusText);
      return null;
    }
    const data = await response.json();
    return data as string;
  } catch (error) {
    console.error('Erreur appel fonction génération ID PLANB:', error);
    return null;
  }
}

/**
 * Obtient le rôle de l'utilisateur actuel dans PLAN B
 */
export async function getPlanbUserRole(): Promise<string | null> {
  try {
    const response = await fetch('/api/user-role');
    if (!response.ok) {
      console.error('Erreur récupération rôle PLANB:', response.statusText);
      return null;
    }
    const data = await response.json();
    return data as string;
  } catch (error) {
    console.error('Erreur appel fonction rôle PLANB:', error);
    return null;
  }
}

/**
 * Vérifie si l'utilisateur actuel est admin dans PLAN B
 */
export async function isPlanbAdmin(): Promise<boolean> {
  try {
    const response = await fetch('/api/is-admin');
    if (!response.ok) {
      console.error('Erreur vérification admin PLANB:', response.statusText);
      return false;
    }
    const data = await response.json();
    return data as boolean;
  } catch (error) {
    console.error('Erreur appel fonction admin PLANB:', error);
    return false;
  }
}

// ===============================================
// FONCTIONS CRUD POUR LES TABLES PRINCIPALES
// ===============================================

/**
 * Récupère tous les segments actifs PLAN B
 */
export async function getPlanbSegments() {
  try {
    const response = await fetch('/api/segments?statut=actif');
    if (!response.ok) {
      console.error('Erreur récupération segments PLANB:', response.statusText);
      return { data: null, error: response.statusText };
    }
    const data = await response.json();
    return { data, error: null };
  } catch (error) {
    console.error('Erreur appel fonction segments PLANB:', error);
    return { data: null, error };
  }
}

/**
 * Récupère toutes les villes actives PLAN B
 */
export async function getPlanbVilles() {
  const response = await fetch('/api/villes?statut=actif');
  const data = await response.json();
  return { data, error: null };
}

/**
 * Récupère tous les centres avec détails PLAN B
 */
export async function getPlanbCentresWithDetails() {
  const response = await fetch('/api/centres?statut=actif&details=true');
  const data = await response.json();
  return { data, error: null };
}

/**
 * Récupère toutes les formations avec détails PLAN B
 */
export async function getPlanbFormationsWithDetails() {
  const response = await fetch('/api/formations?statut=actif&details=true');
  const data = await response.json();
  return { data, error: null };
}

/**
 * Récupère toutes les classes avec détails complets PLAN B
 */
export async function getPlanbClassesWithDetails() {
  const response = await fetch('/api/classes?details=true');
  const data = await response.json();
  return { data, error: null };
}

/**
 * Récupère les inscriptions d'une classe PLAN B
 */
export async function getPlanbInscriptionsForClasse(classeId: string) {
  const response = await fetch(`/api/inscriptions?classeId=${classeId}`);
  const data = await response.json();
  return { data, error: null };
}

/**
 * Récupère les paiements d'une inscription PLAN B
 */
export async function getPlanbPaiementsForInscription(inscriptionId: string) {
  const response = await fetch(`/api/paiements?inscriptionId=${inscriptionId}`);
  const data = await response.json();
  return { data, error: null };
}

// ===============================================
// FONCTIONS DE CRÉATION
// ===============================================

/**
 * Crée un étudiant PLAN B
 */
export async function createPlanbEtudiant(etudiant: { name: string; age: number; email: string }) {
  const response = await fetch(`/api/etudiants`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(etudiant)
  });
  const data = await response.json();
  return { data, error: null };
}

/**
 * Crée une inscription PLAN B avec génération automatique d'ID
 */
export async function createPlanbInscription(inscription: { student_id_unique?: string; course_id: string }) {
  // Générer un ID étudiant unique si pas fourni
  if (!inscription.student_id_unique) {
    inscription.student_id_unique = await generatePlanbStudentId();
  }

  const response = await fetch(`/api/inscriptions`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(inscription)
  });
  const data = await response.json();
  return { data, error: null };
}

/**
 * Crée un paiement PLAN B
 */
export async function createPlanbPaiement(paiement: { inscriptionId: string; amount: number; date: string }) {
  try {
    const response = await fetch(`/api/paiements`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(paiement)
    });
    if (!response.ok) {
      console.error('Erreur création paiement PLANB:', response.statusText);
      return { data: null, error: response.statusText };
    }
    const data = await response.json();
    return { data, error: null };
  } catch (error) {
    console.error('Erreur appel fonction création paiement PLANB:', error);
    return { data: null, error };
  }
}

// ===============================================
// FONCTIONS DE MISE À JOUR
// ===============================================

/**
 * Met à jour un étudiant PLAN B
 */
export async function updatePlanbEtudiant(id: string, updates: Partial<PlanbEtudiant>) {
  const response = await fetch(`/api/etudiants/${id}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(updates)
  });
  const data = await response.json();
  return { data, error: null };
}

/**
 * Met à jour une inscription PLAN B
 */
export async function updatePlanbInscription(id: string, updates: Partial<PlanbInscription>) {
  const response = await fetch(`/api/inscriptions/${id}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(updates)
  });
  const data = await response.json();
  return { data, error: null };
}

// ===============================================
// FONCTIONS STATISTIQUES
// ===============================================

/**
 * Obtient les statistiques d'une classe PLAN B
 */
export async function getPlanbClasseStats(classeId: string) {
  const response = await fetch(`/api/classes/${classeId}/stats`);
  const data = await response.json();
  return { data, error: null };
}

/**
 * Obtient le tableau de bord financier PLAN B
 */
export async function getPlanbFinancialDashboard() {
  try {
    const response = await fetch('/api/financial-dashboard');
    if (!response.ok) {
      console.error('Erreur récupération tableau de bord financier PLANB:', response.statusText);
      return { data: null, error: response.statusText };
    }
    const data = await response.json();
    return { data, error: null };
  } catch (error) {
    console.error('Erreur appel fonction tableau de bord financier PLANB:', error);
    return { data: null, error };
  }
}

// ===============================================
// FONCTIONS DE VALIDATION
// ===============================================

/**
 * Valide un CIN PLAN B (vérifie l'unicité)
 */
export async function validatePlanbCin(cin: string, excludeId?: string) {
  const url = excludeId
    ? `/api/etudiants?cin=${cin.toUpperCase().trim()}&excludeId=${excludeId}`
    : `/api/etudiants?cin=${cin.toUpperCase().trim()}`;

  const response = await fetch(url);
  const data = await response.json();

  return { isValid: data.length === 0, error: null };
}

/**
 * Valide la capacité d'une classe PLAN B
 */
export async function validatePlanbClasseCapacity(classeId: string) {
  const classeResponse = await fetch(`/api/classes/${classeId}/capacity`);
  const classe = await classeResponse.json();

  const inscriptionsResponse = await fetch(`/api/inscriptions?classeId=${classeId}`);
  const inscriptions = await inscriptionsResponse.json();

  const placesOccupees = inscriptions.length;
  const placesDisponibles = classe.nombre_places - placesOccupees;

  return {
    isValid: placesDisponibles > 0,
    placesDisponibles,
    placesOccupees,
  };
}

// ===============================================
// EXPORT PRINCIPAL
// ===============================================

export default {
  // Fonctions utilitaires
  generatePlanbStudentId,
  getPlanbUserRole,
  isPlanbAdmin,
  
  // Fonctions CRUD
  getPlanbSegments,
  getPlanbVilles,
  getPlanbCentresWithDetails,
  getPlanbFormationsWithDetails,
  getPlanbClassesWithDetails,
  getPlanbInscriptionsForClasse,
  getPlanbPaiementsForInscription,
  createPlanbEtudiant,
  createPlanbInscription,
  createPlanbPaiement,
  updatePlanbEtudiant,
  updatePlanbInscription,
  
  // Fonctions statistiques
  getPlanbClasseStats,
  getPlanbFinancialDashboard,
  
  // Fonctions validation
  validatePlanbCin,
  validatePlanbClasseCapacity,
};