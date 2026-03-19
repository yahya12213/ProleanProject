/**
 * PLAN B - Configuration et Adressage de la Base de Données
 * Fichier central pour la gestion des tables et relations PLAN B
 */

// ===============================================
// CONFIGURATION GÉNÉRALE PLAN B
// ===============================================

export const PLANB_CONFIG = {
  name: 'PLAN B',
  version: '1.0.0',
  description: 'Base de données restructurée et optimisée pour la gestion de formation',
  prefix: 'planb_',
  created: new Date().toISOString(),
} as const;

// ===============================================
// TABLES PLAN B - ADRESSAGE
// ===============================================

export const PLANB_TABLES = {
  // Tables de référence
  SEGMENTS: 'planb_segments',
  VILLES: 'planb_villes',
  CENTRES: 'planb_centres',
  
  // Tables d'authentification
  PROFILES: 'planb_profiles',
  ROLES: 'planb_roles',
  PERMISSIONS: 'planb_permissions',
  ROLE_PERMISSIONS: 'planb_role_permissions',
  USER_ROLES: 'planb_user_roles',
  
  // Tables formation
  PLATEFORMES: 'planb_plateformes',
  CORPS_FORMATIONS: 'planb_corps_formations',
  FAMILLES_DOCUMENTS: 'planb_familles_documents',
  FORMATIONS: 'planb_formations',
  GROUPES_CLASSES: 'planb_groupes_classes',
  CLASSES: 'planb_classes',
  
  // Tables étudiants
  ETUDIANTS: 'planb_etudiants',
  INSCRIPTIONS: 'planb_inscriptions',
  
  // Tables financières
  PAIEMENTS: 'planb_paiements',
} as const;

// ===============================================
// FONCTIONS PLAN B - ADRESSAGE
// ===============================================

export const PLANB_FUNCTIONS = {
  GENERATE_STUDENT_ID: 'planb_generate_student_id',
  GET_USER_ROLE: 'planb_get_user_role',
  IS_ADMIN: 'planb_is_admin',
} as const;

// ===============================================
// TYPES ENUM PLAN B
// ===============================================

export const PLANB_ENUMS = {
  STATUT: 'planb_statut_enum',
  NIVEAU: 'planb_niveau_enum',
  PRIORITE: 'planb_priorite_enum',
  TYPE_FORMATION: 'planb_type_formation_enum',
  STATUT_CLASSE: 'planb_statut_classe_enum',
  STATUT_INSCRIPTION: 'planb_statut_inscription_enum',
  TYPE_CONTRAT: 'planb_type_contrat_enum',
  STATUT_COMPTE: 'planb_statut_compte_enum',
  TYPE_DOCUMENT: 'planb_type_document_enum',
  ORIENTATION: 'planb_orientation_enum',
} as const;

// ===============================================
// VALEURS DES ENUMS
// ===============================================

export const PLANB_ENUM_VALUES = {
  STATUT: ['actif', 'inactif', 'suspendu', 'archive'] as const,
  NIVEAU: ['debutant', 'intermediaire', 'avance', 'expert'] as const,
  PRIORITE: ['basse', 'normale', 'haute', 'critique'] as const,
  TYPE_FORMATION: ['physique', 'en_ligne', 'hybride'] as const,
  STATUT_CLASSE: ['programmee', 'en_cours', 'terminee', 'annulee'] as const,
  STATUT_INSCRIPTION: ['en_attente', 'confirmee', 'validee', 'annulee', 'terminee'] as const,
  TYPE_CONTRAT: ['cdi', 'cdd', 'stage', 'freelance', 'consultant'] as const,
  STATUT_COMPTE: ['valide', 'non_valide', 'en_cours', 'suspendu'] as const,
  TYPE_DOCUMENT: ['badge', 'certificat', 'attestation', 'diplome', 'convention'] as const,
  ORIENTATION: ['portrait', 'paysage'] as const,
} as const;

// ===============================================
// STRUCTURE DES TABLES
// ===============================================

export const PLANB_SCHEMA = {
  [PLANB_TABLES.SEGMENTS]: {
    id: 'UUID PRIMARY KEY',
    nom: 'TEXT NOT NULL UNIQUE',
    description: 'TEXT',
    couleur_hex: 'TEXT DEFAULT #3B82F6',
    logo_url: 'TEXT',
    statut: 'planb_statut_enum NOT NULL DEFAULT actif',
    created_at: 'TIMESTAMPTZ NOT NULL DEFAULT now()',
    updated_at: 'TIMESTAMPTZ NOT NULL DEFAULT now()',
  },
  
  [PLANB_TABLES.VILLES]: {
    id: 'UUID PRIMARY KEY',
    nom: 'TEXT NOT NULL',
    code_postal: 'TEXT',
    region: 'TEXT',
    pays: 'TEXT DEFAULT Maroc',
    statut: 'planb_statut_enum NOT NULL DEFAULT actif',
    created_at: 'TIMESTAMPTZ NOT NULL DEFAULT now()',
    updated_at: 'TIMESTAMPTZ NOT NULL DEFAULT now()',
  },
  
  [PLANB_TABLES.CENTRES]: {
    id: 'UUID PRIMARY KEY',
    nom: 'TEXT NOT NULL',
    segment_id: 'UUID REFERENCES planb_segments(id)',
    ville_id: 'UUID REFERENCES planb_villes(id)',
    adresse_complete: 'TEXT',
    telephone: 'TEXT',
    email: 'TEXT',
    capacite_max: 'INTEGER DEFAULT 50',
    equipements: 'JSONB DEFAULT []',
    horaires_ouverture: 'JSONB DEFAULT {}',
    coordonnees_gps: 'POINT',
    statut: 'planb_statut_enum NOT NULL DEFAULT actif',
    created_at: 'TIMESTAMPTZ NOT NULL DEFAULT now()',
    updated_at: 'TIMESTAMPTZ NOT NULL DEFAULT now()',
  },
  
  [PLANB_TABLES.PROFILES]: {
    id: 'UUID PRIMARY KEY',
    user_id: 'UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE',
    nom: 'TEXT NOT NULL',
    prenom: 'TEXT NOT NULL',
    email: 'TEXT NOT NULL UNIQUE',
    telephone: 'TEXT',
    photo_url: 'TEXT',
    poste: 'TEXT',
    departement: 'TEXT',
    manager_id: 'UUID REFERENCES planb_profiles(id)',
    centre_id: 'UUID REFERENCES planb_centres(id)',
    segment_id: 'UUID REFERENCES planb_segments(id)',
    date_naissance: 'DATE',
    cin: 'TEXT',
    adresse_ligne1: 'TEXT',
    adresse_ligne2: 'TEXT',
    ville: 'TEXT',
    code_postal: 'TEXT',
    pays: 'TEXT DEFAULT Maroc',
    date_embauche: 'DATE',
    type_contrat: 'planb_type_contrat_enum',
    salaire_base: 'DECIMAL(12,2)',
    numero_cnss: 'TEXT',
    rib: 'TEXT',
    statut: 'planb_statut_enum NOT NULL DEFAULT actif',
    created_at: 'TIMESTAMPTZ NOT NULL DEFAULT now()',
    updated_at: 'TIMESTAMPTZ NOT NULL DEFAULT now()',
  },
  
  [PLANB_TABLES.ETUDIANTS]: {
    id: 'UUID PRIMARY KEY',
    nom: 'TEXT NOT NULL',
    prenom: 'TEXT NOT NULL',
    cin: 'TEXT UNIQUE',
    email: 'TEXT',
    telephone: 'TEXT',
    whatsapp: 'TEXT',
    date_naissance: 'DATE',
    lieu_naissance: 'TEXT',
    adresse_complete: 'TEXT',
    ville: 'TEXT',
    code_postal: 'TEXT',
    pays: 'TEXT DEFAULT Maroc',
    niveau_etudes: 'TEXT',
    profession: 'TEXT',
    entreprise: 'TEXT',
    experience_professionnelle: 'TEXT',
    photo_url: 'TEXT',
    source_inscription: 'TEXT',
    commentaires_internes: 'TEXT',
    statut: 'planb_statut_enum NOT NULL DEFAULT actif',
    created_at: 'TIMESTAMPTZ NOT NULL DEFAULT now()',
    updated_at: 'TIMESTAMPTZ NOT NULL DEFAULT now()',
  },
  
  [PLANB_TABLES.FORMATIONS]: {
    id: 'UUID PRIMARY KEY',
    titre: 'TEXT NOT NULL',
    description: 'TEXT',
    reference: 'TEXT',
    corps_formation_id: 'UUID REFERENCES planb_corps_formations(id)',
    type_formation: 'planb_type_formation_enum NOT NULL DEFAULT physique',
    niveau: 'planb_niveau_enum NOT NULL DEFAULT debutant',
    duree_heures: 'INTEGER NOT NULL DEFAULT 0',
    duree_jours: 'INTEGER GENERATED ALWAYS AS (CEIL(duree_heures::DECIMAL / 8)) STORED',
    prix: 'DECIMAL(10,2)',
    prix_en_ligne: 'DECIMAL(10,2)',
    centre_id: 'UUID REFERENCES planb_centres(id)',
    plateforme_id: 'UUID REFERENCES planb_plateformes(id)',
    objectifs_pedagogiques: 'TEXT[]',
    prerequis: 'TEXT[]',
    programme_detaille: 'JSONB',
    statut: 'planb_statut_enum NOT NULL DEFAULT actif',
    created_at: 'TIMESTAMPTZ NOT NULL DEFAULT now()',
    updated_at: 'TIMESTAMPTZ NOT NULL DEFAULT now()',
  },
  
  [PLANB_TABLES.CLASSES]: {
    id: 'UUID PRIMARY KEY',
    nom_classe: 'TEXT NOT NULL',
    formation_id: 'UUID REFERENCES planb_formations(id)',
    groupe_classe_id: 'UUID REFERENCES planb_groupes_classes(id)',
    centre_id: 'UUID NOT NULL REFERENCES planb_centres(id)',
    date_debut: 'DATE NOT NULL',
    date_fin: 'DATE NOT NULL',
    horaire_debut: 'TIME',
    horaire_fin: 'TIME',
    nombre_places: 'INTEGER NOT NULL DEFAULT 20',
    places_reservees: 'INTEGER DEFAULT 0',
    formateur_principal_id: 'UUID REFERENCES planb_profiles(id)',
    formateurs_assistants: 'UUID[] DEFAULT {}',
    salle: 'TEXT',
    equipements_requis: 'TEXT[]',
    materiel_fourni: 'TEXT[]',
    statut: 'planb_statut_classe_enum NOT NULL DEFAULT programmee',
    created_at: 'TIMESTAMPTZ NOT NULL DEFAULT now()',
    updated_at: 'TIMESTAMPTZ NOT NULL DEFAULT now()',
  },
  
  [PLANB_TABLES.INSCRIPTIONS]: {
    id: 'UUID PRIMARY KEY',
    etudiant_id: 'UUID NOT NULL REFERENCES planb_etudiants(id) ON DELETE CASCADE',
    formation_id: 'UUID NOT NULL REFERENCES planb_formations(id)',
    classe_id: 'UUID REFERENCES planb_classes(id)',
    numero_inscription: 'TEXT UNIQUE',
    student_id_unique: 'TEXT UNIQUE',
    date_inscription: 'TIMESTAMPTZ NOT NULL DEFAULT now()',
    date_confirmation: 'TIMESTAMPTZ',
    date_debut_formation: 'DATE',
    date_fin_formation: 'DATE',
    prix_formation: 'DECIMAL(10,2)',
    remise_accordee: 'DECIMAL(10,2) DEFAULT 0',
    prix_final: 'DECIMAL(10,2) GENERATED ALWAYS AS (prix_formation - COALESCE(remise_accordee, 0)) STORED',
    bon_commande: 'TEXT',
    convention_signee: 'BOOLEAN DEFAULT false',
    documents_fournis: 'TEXT[]',
    note_finale: 'DECIMAL(4,2)',
    appreciation: 'TEXT',
    presence_heures: 'INTEGER DEFAULT 0',
    absence_heures: 'INTEGER DEFAULT 0',
    taux_presence: 'DECIMAL(5,2) GENERATED STORED',
    certifie: 'BOOLEAN DEFAULT false',
    date_certification: 'TIMESTAMPTZ',
    numero_certificat: 'TEXT',
    statut_inscription: 'planb_statut_inscription_enum NOT NULL DEFAULT en_attente',
    statut_compte: 'planb_statut_compte_enum NOT NULL DEFAULT en_cours',
    notes_internes: 'TEXT',
    created_at: 'TIMESTAMPTZ NOT NULL DEFAULT now()',
    updated_at: 'TIMESTAMPTZ NOT NULL DEFAULT now()',
  },
  
  [PLANB_TABLES.PAIEMENTS]: {
    id: 'UUID PRIMARY KEY',
    inscription_id: 'UUID NOT NULL REFERENCES planb_inscriptions(id) ON DELETE CASCADE',
    montant: 'DECIMAL(10,2) NOT NULL',
    devise: 'TEXT DEFAULT DH',
    methode_paiement: 'TEXT NOT NULL',
    reference_transaction: 'TEXT',
    numero_piece: 'TEXT',
    date_paiement: 'TIMESTAMPTZ NOT NULL DEFAULT now()',
    date_encaissement: 'TIMESTAMPTZ',
    valide: 'BOOLEAN DEFAULT true',
    valide_par: 'UUID REFERENCES planb_profiles(id)',
    date_validation: 'TIMESTAMPTZ',
    notes: 'TEXT',
    created_by: 'UUID REFERENCES planb_profiles(id)',
    created_at: 'TIMESTAMPTZ NOT NULL DEFAULT now()',
    updated_at: 'TIMESTAMPTZ NOT NULL DEFAULT now()',
  },
} as const;

// ===============================================
// RELATIONS ENTRE TABLES
// ===============================================

export const PLANB_RELATIONS = {
  // Centres liés aux segments et villes
  centres_segments: {
    from: PLANB_TABLES.CENTRES,
    to: PLANB_TABLES.SEGMENTS,
    key: 'segment_id',
    type: 'many-to-one',
  },
  centres_villes: {
    from: PLANB_TABLES.CENTRES,
    to: PLANB_TABLES.VILLES,
    key: 'ville_id',
    type: 'many-to-one',
  },
  
  // Profils liés aux centres et segments
  profiles_centres: {
    from: PLANB_TABLES.PROFILES,
    to: PLANB_TABLES.CENTRES,
    key: 'centre_id',
    type: 'many-to-one',
  },
  profiles_segments: {
    from: PLANB_TABLES.PROFILES,
    to: PLANB_TABLES.SEGMENTS,
    key: 'segment_id',
    type: 'many-to-one',
  },
  
  // Formations liées aux centres et corps de formation
  formations_centres: {
    from: PLANB_TABLES.FORMATIONS,
    to: PLANB_TABLES.CENTRES,
    key: 'centre_id',
    type: 'many-to-one',
  },
  formations_corps: {
    from: PLANB_TABLES.FORMATIONS,
    to: PLANB_TABLES.CORPS_FORMATIONS,
    key: 'corps_formation_id',
    type: 'many-to-one',
  },
  
  // Classes liées aux formations et centres
  classes_formations: {
    from: PLANB_TABLES.CLASSES,
    to: PLANB_TABLES.FORMATIONS,
    key: 'formation_id',
    type: 'many-to-one',
  },
  classes_centres: {
    from: PLANB_TABLES.CLASSES,
    to: PLANB_TABLES.CENTRES,
    key: 'centre_id',
    type: 'many-to-one',
  },
  
  // Inscriptions liées aux étudiants, formations et classes
  inscriptions_etudiants: {
    from: PLANB_TABLES.INSCRIPTIONS,
    to: PLANB_TABLES.ETUDIANTS,
    key: 'etudiant_id',
    type: 'many-to-one',
  },
  inscriptions_formations: {
    from: PLANB_TABLES.INSCRIPTIONS,
    to: PLANB_TABLES.FORMATIONS,
    key: 'formation_id',
    type: 'many-to-one',
  },
  inscriptions_classes: {
    from: PLANB_TABLES.INSCRIPTIONS,
    to: PLANB_TABLES.CLASSES,
    key: 'classe_id',
    type: 'many-to-one',
  },
  
  // Paiements liés aux inscriptions
  paiements_inscriptions: {
    from: PLANB_TABLES.PAIEMENTS,
    to: PLANB_TABLES.INSCRIPTIONS,
    key: 'inscription_id',
    type: 'many-to-one',
  },
} as const;

// ===============================================
// REQUÊTES FRÉQUENTES PLAN B
// ===============================================

export const PLANB_QUERIES = {
  // Requêtes segments
  GET_ACTIVE_SEGMENTS: `SELECT * FROM ${PLANB_TABLES.SEGMENTS} WHERE statut = 'actif' ORDER BY nom`,
  
  // Requêtes villes
  GET_ACTIVE_CITIES: `SELECT * FROM ${PLANB_TABLES.VILLES} WHERE statut = 'actif' ORDER BY nom`,
  
  // Requêtes centres avec relations
  GET_CENTRES_WITH_DETAILS: `
    SELECT c.*, s.nom as segment_nom, v.nom as ville_nom 
    FROM ${PLANB_TABLES.CENTRES} c
    LEFT JOIN ${PLANB_TABLES.SEGMENTS} s ON c.segment_id = s.id
    LEFT JOIN ${PLANB_TABLES.VILLES} v ON c.ville_id = v.id
    WHERE c.statut = 'actif'
    ORDER BY c.nom
  `,
  
  // Requêtes formations avec détails
  GET_FORMATIONS_WITH_DETAILS: `
    SELECT f.*, c.nom as centre_nom, cf.nom as corps_formation_nom
    FROM ${PLANB_TABLES.FORMATIONS} f
    LEFT JOIN ${PLANB_TABLES.CENTRES} c ON f.centre_id = c.id
    LEFT JOIN ${PLANB_TABLES.CORPS_FORMATIONS} cf ON f.corps_formation_id = cf.id
    WHERE f.statut = 'actif'
    ORDER BY f.titre
  `,
  
  // Requêtes classes avec détails complets
  GET_CLASSES_WITH_DETAILS: `
    SELECT 
      cl.*,
      f.titre as formation_titre,
      f.prix as formation_prix,
      c.nom as centre_nom,
      v.nom as ville_nom,
      COUNT(i.id) as inscriptions_count
    FROM ${PLANB_TABLES.CLASSES} cl
    LEFT JOIN ${PLANB_TABLES.FORMATIONS} f ON cl.formation_id = f.id
    LEFT JOIN ${PLANB_TABLES.CENTRES} c ON cl.centre_id = c.id
    LEFT JOIN ${PLANB_TABLES.VILLES} v ON c.ville_id = v.id
    LEFT JOIN ${PLANB_TABLES.INSCRIPTIONS} i ON cl.id = i.classe_id
    GROUP BY cl.id, f.titre, f.prix, c.nom, v.nom
    ORDER BY cl.date_debut DESC
  `,
  
  // Requêtes étudiants avec inscriptions
  GET_STUDENTS_WITH_INSCRIPTIONS: `
    SELECT 
      e.*,
      i.id as inscription_id,
      i.student_id_unique,
      i.statut_inscription,
      i.statut_compte,
      f.titre as formation_titre,
      cl.nom_classe,
      SUM(p.montant) as total_paiements
    FROM ${PLANB_TABLES.ETUDIANTS} e
    LEFT JOIN ${PLANB_TABLES.INSCRIPTIONS} i ON e.id = i.etudiant_id
    LEFT JOIN ${PLANB_TABLES.FORMATIONS} f ON i.formation_id = f.id
    LEFT JOIN ${PLANB_TABLES.CLASSES} cl ON i.classe_id = cl.id
    LEFT JOIN ${PLANB_TABLES.PAIEMENTS} p ON i.id = p.inscription_id
    WHERE e.statut = 'actif'
    GROUP BY e.id, i.id, f.titre, cl.nom_classe
    ORDER BY e.nom, e.prenom
  `,
  
  // Requête tableau de bord financier
  GET_FINANCIAL_DASHBOARD: `
    SELECT 
      DATE_TRUNC('month', p.date_paiement) as mois,
      SUM(p.montant) as total_paiements,
      COUNT(p.id) as nombre_paiements,
      COUNT(DISTINCT i.etudiant_id) as nombre_etudiants
    FROM ${PLANB_TABLES.PAIEMENTS} p
    JOIN ${PLANB_TABLES.INSCRIPTIONS} i ON p.inscription_id = i.id
    WHERE p.valide = true
    GROUP BY DATE_TRUNC('month', p.date_paiement)
    ORDER BY mois DESC
    LIMIT 12
  `,
} as const;

// ===============================================
// EXPORT PRINCIPAL
// ===============================================

export default {
  CONFIG: PLANB_CONFIG,
  TABLES: PLANB_TABLES,
  FUNCTIONS: PLANB_FUNCTIONS,
  ENUMS: PLANB_ENUMS,
  ENUM_VALUES: PLANB_ENUM_VALUES,
  SCHEMA: PLANB_SCHEMA,
  RELATIONS: PLANB_RELATIONS,
  QUERIES: PLANB_QUERIES,
} as const;