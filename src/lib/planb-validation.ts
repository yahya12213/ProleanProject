/**
 * PLAN B - Validation et Cohérence des Données
 * Système de validation centralisé pour assurer la cohérence
 */

// ===============================================
// TYPES DE VALIDATION
// ===============================================

export interface ValidationResult {
  isValid: boolean;
  errors: string[];
  warnings: string[];
}

export interface ValidationRule<T> {
  name: string;
  validate: (data: T) => Promise<ValidationResult> | ValidationResult;
  level: 'error' | 'warning';
}

// ===============================================
// VALIDATEURS GÉNÉRIQUES
// ===============================================

export class PlanbValidator {
  private static rules: Map<string, ValidationRule<unknown>[]> = new Map();

  static addRule<T>(entity: string, rule: ValidationRule<T>) {
    if (!this.rules.has(entity)) {
      this.rules.set(entity, []);
    }
    this.rules.get(entity)!.push(rule);
  }

  static async validate<T>(entity: string, data: T): Promise<ValidationResult> {
    const rules = this.rules.get(entity) || [];
    const result: ValidationResult = {
      isValid: true,
      errors: [],
      warnings: []
    };

    for (const rule of rules) {
      try {
        const ruleResult = await rule.validate(data);
        
        if (!ruleResult.isValid) {
          result.isValid = false;
        }
        
        if (rule.level === 'error') {
          result.errors.push(...ruleResult.errors);
        } else {
          result.warnings.push(...ruleResult.warnings);
        }
      } catch (error) {
        console.error(`Erreur validation règle ${rule.name}:`, error);
        result.errors.push(`Erreur interne: ${rule.name}`);
        result.isValid = false;
      }
    }

    return result;
  }
}

// ===============================================
// RÈGLES DE VALIDATION ÉTUDIANT
// ===============================================

export interface PlanbEtudiantData {
  nom: string;
  prenom: string;
  cin?: string;
  email?: string;
  telephone?: string;
  date_naissance?: string;
}

// Validation nom/prénom obligatoires
PlanbValidator.addRule<PlanbEtudiantData>('etudiant', {
  name: 'nom_prenom_obligatoires',
  level: 'error',
  validate: (data) => ({
    isValid: !!(data.nom?.trim() && data.prenom?.trim()),
    errors: data.nom?.trim() && data.prenom?.trim() ? [] : ['Nom et prénom sont obligatoires'],
    warnings: []
  })
});

// Validation CIN unique
PlanbValidator.addRule<PlanbEtudiantData>('etudiant', {
  name: 'cin_unique',
  level: 'error',
  validate: async (data) => {
    if (!data.cin?.trim()) {
      return { isValid: true, errors: [], warnings: ['CIN non fourni'] };
    }

    // TODO: Remplacer par appel à l'API Express locale
    const etudiantResponse = await fetch(`/api/etudiants?cin=${data.cin.toUpperCase().trim()}`);
    const existing = await etudiantResponse.json();

    return {
      isValid: !existing || existing.length === 0,
      errors: existing && existing.length > 0 ? [`CIN ${data.cin} déjà utilisé`] : [],
      warnings: []
    };
  }
});

// Validation email format
PlanbValidator.addRule<PlanbEtudiantData>('etudiant', {
  name: 'email_format',
  level: 'warning',
  validate: (data) => {
    if (!data.email?.trim()) {
      return { isValid: true, errors: [], warnings: [] };
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const isValid = emailRegex.test(data.email);

    return {
      isValid: true, // Warning seulement
      errors: [],
      warnings: isValid ? [] : ['Format email invalide']
    };
  }
});

// Validation téléphone marocain
PlanbValidator.addRule<PlanbEtudiantData>('etudiant', {
  name: 'telephone_maroc',
  level: 'warning',
  validate: (data) => {
    if (!data.telephone?.trim()) {
      return { isValid: true, errors: [], warnings: [] };
    }

    const phoneRegex = /^(\+212|0)[5-7][0-9]{8}$/;
    const cleanPhone = data.telephone.replace(/[\s-]/g, '');
    const isValid = phoneRegex.test(cleanPhone);

    return {
      isValid: true, // Warning seulement
      errors: [],
      warnings: isValid ? [] : ['Format téléphone marocain invalide (ex: 0612345678)']
    };
  }
});

// ===============================================
// RÈGLES DE VALIDATION INSCRIPTION
// ===============================================

export interface PlanbInscriptionData {
  etudiant_id: string;
  formation_id: string;
  classe_id?: string;
  prix_formation?: number;
  remise_accordee?: number;
}

// Validation cohérence classe-formation
PlanbValidator.addRule<PlanbInscriptionData>('inscription', {
  name: 'classe_formation_coherence',
  level: 'error',
  validate: async (data) => {
    if (!data.classe_id) {
      return { isValid: true, errors: [], warnings: [] };
    }

    // TODO: Remplacer par appel à l'API Express locale
    const classeResponse = await fetch(`/api/classes/${data.classe_id}`);
    const classe = await classeResponse.json();

    if (!classe) {
      return {
        isValid: false,
        errors: ['Classe non trouvée'],
        warnings: []
      };
    }

    const isCoherent = classe.formation_id === data.formation_id;
    
    return {
      isValid: isCoherent,
      errors: isCoherent ? [] : ['La classe ne correspond pas à la formation sélectionnée'],
      warnings: []
    };
  }
});

// Validation capacité classe
PlanbValidator.addRule<PlanbInscriptionData>('inscription', {
  name: 'capacite_classe',
  level: 'error',
  validate: async (data) => {
    if (!data.classe_id) {
      return { isValid: true, errors: [], warnings: [] };
    }

    try {
      const classeResponse = await fetch(`/api/classes/${data.classe_id}`);
      const classe = await classeResponse.json();

      if (!classe) {
        return { isValid: true, errors: [], warnings: [] };
      }

      const inscriptionsResponse = await fetch(`/api/inscriptions?classeId=${data.classe_id}`);
      const inscriptions = await inscriptionsResponse.json();

      const placesOccupees = inscriptions?.length || 0;
      const placesDisponibles = classe.nombre_places - placesOccupees;

      return {
        isValid: placesDisponibles > 0,
        errors: placesDisponibles <= 0 ? ['Classe complète, aucune place disponible'] : [],
        warnings: placesDisponibles <= 2 ? [`Plus que ${placesDisponibles} place(s) disponible(s)`] : []
      };
    } catch (error) {
      console.error('Error fetching class or inscriptions data:', error);
      return { isValid: false, errors: ['Unable to validate class data'], warnings: [] };
    }
  }
});

// Validation remise raisonnable
PlanbValidator.addRule<PlanbInscriptionData>('inscription', {
  name: 'remise_raisonnable',
  level: 'warning',
  validate: (data) => {
    if (!data.remise_accordee || !data.prix_formation) {
      return { isValid: true, errors: [], warnings: [] };
    }

    const pourcentageRemise = (data.remise_accordee / data.prix_formation) * 100;
    
    return {
      isValid: true,
      errors: [],
      warnings: pourcentageRemise > 50 ? [`Remise importante: ${pourcentageRemise.toFixed(1)}%`] : []
    };
  }
});

// ===============================================
// FONCTIONS UTILITAIRES DE VALIDATION
// ===============================================

/**
 * Valide un étudiant avant création
 */
export async function validateEtudiant(etudiant: PlanbEtudiantData): Promise<ValidationResult> {
  return PlanbValidator.validate('etudiant', etudiant);
}

/**
 * Valide une inscription avant création
 */
export async function validateInscription(inscription: PlanbInscriptionData): Promise<ValidationResult> {
  return PlanbValidator.validate('inscription', inscription);
}

/**
 * Nettoie et formate les données d'un étudiant
 */
export function sanitizeEtudiantData(data: PlanbEtudiantData): PlanbEtudiantData {
  return {
    nom: data.nom?.trim() || '',
    prenom: data.prenom?.trim() || '',
    cin: data.cin?.trim().toUpperCase() || undefined,
    email: data.email?.trim().toLowerCase() || undefined,
    telephone: data.telephone?.replace(/[\s-]/g, '') || undefined,
    date_naissance: data.date_naissance || undefined
  };
}

/**
 * Vérifie la cohérence globale des données
 */
export async function checkDataIntegrity(): Promise<ValidationResult> {
  const result: ValidationResult = {
    isValid: true,
    errors: [],
    warnings: []
  };

  try {
    // Vérifier les étudiants sans inscription
    const etudiantsSansInscriptionResponse = await fetch(`/api/etudiants?inscriptions=null`);
    const etudiantsSansInscription = await etudiantsSansInscriptionResponse.json();

    if (etudiantsSansInscription && etudiantsSansInscription.length > 0) {
      result.warnings.push(`${etudiantsSansInscription.length} étudiant(s) sans inscription`);
    }

    // Vérifier les inscriptions sans paiement
    const inscriptionsSansPaiementResponse = await fetch(`/api/inscriptions?paiements=null`);
    const inscriptionsSansPaiement = await inscriptionsSansPaiementResponse.json();

    if (inscriptionsSansPaiement && inscriptionsSansPaiement.length > 0) {
      result.warnings.push(`${inscriptionsSansPaiement.length} inscription(s) sans paiement`);
    }

    // Vérifier les classes vides
    const classesVidesResponse = await fetch(`/api/classes?statut=programmee&inscriptions=null`);
    const classesVides = await classesVidesResponse.json();

    if (classesVides && classesVides.length > 0) {
      result.warnings.push(`${classesVides.length} classe(s) programmée(s) sans inscription`);
    }

  } catch (error) {
    console.error('Erreur vérification intégrité:', error);
    result.isValid = false;
    result.errors.push('Erreur lors de la vérification de l\'intégrité des données');
  }

  return result;
}

// ===============================================
// HOOK REACT POUR VALIDATION
// ===============================================

export function useValidation() {
  const [isValidating, setIsValidating] = React.useState(false);
  const [validationResult, setValidationResult] = React.useState<ValidationResult | null>(null);

  const validate = React.useCallback(async <T>(entity: string, data: T) => {
    setIsValidating(true);
    try {
      const result = await PlanbValidator.validate(entity, data);
      setValidationResult(result);
      return result;
    } finally {
      setIsValidating(false);
    }
  }, []);

  const clearValidation = React.useCallback(() => {
    setValidationResult(null);
  }, []);

  return {
    isValidating,
    validationResult,
    validate,
    clearValidation
  };
}

import React from 'react'; // Ajout nécessaire pour useCallback et useState