CREATE SCHEMA IF NOT EXISTS auth;
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Vérification et création des types ENUM uniquement s'ils n'existent pas déjà
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'statut_candidat') THEN
        CREATE TYPE statut_candidat AS ENUM ('nouveau', 'en_attente', 'accepte', 'refuse');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'statut_classe') THEN
        CREATE TYPE statut_classe AS ENUM ('programmee', 'terminee', 'annulee');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'formation_type') THEN
        CREATE TYPE formation_type AS ENUM ('physique', 'en_ligne');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'statut_demande_rh') THEN
        CREATE TYPE statut_demande_rh AS ENUM ('en_attente', 'validee', 'refusee');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'statut_entretien') THEN
        CREATE TYPE statut_entretien AS ENUM ('programme', 'termine', 'annule');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'planb_statut_enum') THEN
        CREATE TYPE planb_statut_enum AS ENUM ('actif', 'inactif', 'archive');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'planb_statut_classe_enum') THEN
        CREATE TYPE planb_statut_classe_enum AS ENUM ('programmee', 'terminee', 'annulee');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'planb_type_formation_enum') THEN
        CREATE TYPE planb_type_formation_enum AS ENUM ('physique', 'en_ligne');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'planb_niveau_enum') THEN
        CREATE TYPE planb_niveau_enum AS ENUM ('debutant', 'intermediaire', 'avance');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'planb_statut_inscription_enum') THEN
        CREATE TYPE planb_statut_inscription_enum AS ENUM ('en_attente', 'valide', 'refusee');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'planb_statut_compte_enum') THEN
        CREATE TYPE planb_statut_compte_enum AS ENUM ('en_cours', 'suspendu', 'ferme');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'role_type') THEN
        CREATE TYPE role_type AS ENUM ('custom', 'admin', 'user');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'type_message') THEN
        CREATE TYPE type_message AS ENUM ('direct', 'groupe');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'statut_poste') THEN
        CREATE TYPE statut_poste AS ENUM ('ouvert', 'ferme');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'priorite_tache') THEN
        CREATE TYPE priorite_tache AS ENUM ('normale', 'haute', 'basse');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'statut_tache') THEN
        CREATE TYPE statut_tache AS ENUM ('a_faire', 'en_cours', 'terminee');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'statut_projet') THEN
        CREATE TYPE statut_projet AS ENUM ('planifie', 'en_cours', 'termine', 'archive');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'statut_demande_rh_new') THEN
        CREATE TYPE statut_demande_rh_new AS ENUM ('en_attente', 'validee', 'refusee');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'statut_projet_new') THEN
        CREATE TYPE statut_projet_new AS ENUM ('planifie', 'en_cours', 'termine', 'archive');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'priorite_tache_new') THEN
        CREATE TYPE priorite_tache_new AS ENUM ('normale', 'haute', 'basse');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'statut_tache_new') THEN
        CREATE TYPE statut_tache_new AS ENUM ('a_faire', 'en_cours', 'terminee');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'statut_workflow') THEN
        CREATE TYPE statut_workflow AS ENUM ('en_attente', 'valide', 'refuse');
    END IF;
END $$;

-- Remplacement des types USER-DEFINED par des types ENUM appropriés
ALTER TABLE public.demandes_rh ALTER COLUMN type_demande TYPE statut_demande_rh USING type_demande::statut_demande_rh;
ALTER TABLE public.exercises ALTER COLUMN category TYPE text;
ALTER TABLE public.fitshape_profiles ALTER COLUMN sex TYPE text;

-- Correction de la syntaxe ARRAY
ALTER TABLE public.user_profiles ALTER COLUMN goals TYPE text[] USING string_to_array(goals, ',');

-- Suppression des valeurs par défaut invalides
ALTER TABLE public.planb_formations ALTER COLUMN duree_jours DROP DEFAULT;
ALTER TABLE public.planb_inscriptions ALTER COLUMN prix_final DROP DEFAULT;

-- Ajout de vérifications pour les clés étrangères
-- Exemple : Vérification de l'existence de la table public.profiles avant d'ajouter une contrainte
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'profiles') THEN
        ALTER TABLE public.actions_disciplinaires ADD CONSTRAINT actions_disciplinaires_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES public.profiles(id);
    END IF;
END $$;

-- WARNING: This schema is for context only and is not meant to be run.
-- Table order and constraints may not be valid for execution.

CREATE TABLE public.absences_retards (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  profile_id uuid NOT NULL,
  date_absence date NOT NULL,
  type_absence text NOT NULL CHECK (type_absence = ANY (ARRAY['absence_justifiee', 'absence_non_justifiee', 'retard'])),
  duree_heures numeric NOT NULL DEFAULT 0,
  duree_jours numeric NOT NULL DEFAULT 0,
  justificatif text,
  document_url text,
  created_at timestamp with time zone DEFAULT now(),
  updated_at timestamp with time zone DEFAULT now(),
  CONSTRAINT absences_retards_pkey PRIMARY KEY (id),
  CONSTRAINT absences_retards_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES public.profiles(id)
);
CREATE TABLE public.actions_disciplinaires (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  profile_id uuid NOT NULL,
  date_action date NOT NULL,
  type_action text NOT NULL CHECK (type_action = ANY (ARRAY['avertissement_oral'::text, 'avertissement_ecrit'::text, 'mise_a_pied'::text, 'autre'::text])),
  motif text NOT NULL,
  document_url text,
  created_by uuid,
  created_at timestamp with time zone DEFAULT now(),
  updated_at timestamp with time zone DEFAULT now(),
  CONSTRAINT actions_disciplinaires_pkey PRIMARY KEY (id),
  CONSTRAINT actions_disciplinaires_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.profiles(id),
  CONSTRAINT actions_disciplinaires_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES public.profiles(id)
);
CREATE TABLE public.audit_logs (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  table_name text NOT NULL,
  operation text NOT NULL,
  record_id uuid,
  old_values jsonb,
  new_values jsonb,
  user_id uuid,
  session_id text,
  ip_address inet,
  user_agent text,
  created_at timestamp with time zone DEFAULT now(),
  error_message text,
  context jsonb DEFAULT '{}'::jsonb,
  CONSTRAINT audit_logs_pkey PRIMARY KEY (id)
);
CREATE TABLE public.campagnes_marketing (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  nom text NOT NULL,
  description text,
  type_campagne text NOT NULL,
  date_debut date NOT NULL,
  date_fin date,
  budget numeric,
  objectif_prospects integer,
  prospects_generes integer DEFAULT 0,
  created_by uuid NOT NULL,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT campagnes_marketing_pkey PRIMARY KEY (id)
);
CREATE TABLE public.candidats (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  nom text NOT NULL,
  prenom text NOT NULL,
  email text NOT NULL UNIQUE,
  telephone text,
  cv_url text,
  lettre_motivation_url text,
  experience_annees integer DEFAULT 0,
  statut statut_candidat NOT NULL DEFAULT 'nouveau'::statut_candidat,
  poste_id uuid,
  notes text,
  source text,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT candidats_pkey PRIMARY KEY (id),
  CONSTRAINT candidats_poste_id_fkey FOREIGN KEY (poste_id) REFERENCES public.postes_ouverts(id)
);
CREATE TABLE public.centre_assignments (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL,
  centre_id uuid NOT NULL,
  assigned_by uuid NOT NULL,
  assigned_at timestamp with time zone NOT NULL DEFAULT now(),
  is_active boolean NOT NULL DEFAULT true,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT centre_assignments_pkey PRIMARY KEY (id),
  CONSTRAINT fk_centre_assignments_centre FOREIGN KEY (centre_id) REFERENCES public.centres(id)
);
CREATE TABLE public.centres (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  nom text NOT NULL,
  adresse text,
  ville_id uuid,
  telephone text,
  email text,
  capacite integer DEFAULT 0,
  equipements text[],
  is_active boolean NOT NULL DEFAULT true,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  segment_id uuid,
  CONSTRAINT centres_pkey PRIMARY KEY (id),
  CONSTRAINT centres_segment_id_fkey FOREIGN KEY (segment_id) REFERENCES public.segments(id),
  CONSTRAINT fk_centres_ville FOREIGN KEY (ville_id) REFERENCES public.villes(id)
);
CREATE TABLE public.classes (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  formation_id uuid,
  centre_id uuid NOT NULL,
  nom_classe text NOT NULL,
  nombre_places integer NOT NULL DEFAULT 0,
  date_debut date NOT NULL,
  date_fin date NOT NULL,
  formateur text,
  statut statut_classe NOT NULL DEFAULT 'programmee'::statut_classe,
  is_active boolean NOT NULL DEFAULT true,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  groupe_classe_id uuid,
  corps_formation_id uuid,
  ville_id uuid,
  CONSTRAINT classes_pkey PRIMARY KEY (id),
  CONSTRAINT classes_centre_id_fkey FOREIGN KEY (centre_id) REFERENCES public.centres(id),
  CONSTRAINT classes_formation_id_fkey FOREIGN KEY (formation_id) REFERENCES public.formations(id),
  CONSTRAINT classes_groupe_classe_id_fkey FOREIGN KEY (groupe_classe_id) REFERENCES public.groupes_classes(id),
  CONSTRAINT fk_classes_corps_formation FOREIGN KEY (corps_formation_id) REFERENCES public.corps_formation(id),
  CONSTRAINT fk_classes_ville FOREIGN KEY (ville_id) REFERENCES public.villes(id)
);
CREATE TABLE public.contract_types (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  nom text NOT NULL,
  is_active boolean NOT NULL DEFAULT true,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT contract_types_pkey PRIMARY KEY (id)
);
CREATE TABLE public.conversation_participants (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  conversation_id uuid NOT NULL,
  profile_id uuid NOT NULL,
  joined_at timestamp with time zone NOT NULL DEFAULT now(),
  last_read_at timestamp with time zone DEFAULT now(),
  is_admin boolean NOT NULL DEFAULT false,
  CONSTRAINT conversation_participants_pkey PRIMARY KEY (id),
  CONSTRAINT conversation_participants_conversation_id_fkey FOREIGN KEY (conversation_id) REFERENCES public.conversations(id)
);
CREATE TABLE public.conversations (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  titre text,
  type_conversation type_message NOT NULL DEFAULT 'direct'::type_message,
  created_by uuid NOT NULL,
  last_message_at timestamp with time zone DEFAULT now(),
  is_archived boolean NOT NULL DEFAULT false,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT conversations_pkey PRIMARY KEY (id)
);
CREATE TABLE public.corps_formation (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  nom text NOT NULL,
  description text,
  is_active boolean NOT NULL DEFAULT true,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT corps_formation_pkey PRIMARY KEY (id)
);
CREATE TABLE public.corps_formation_familles (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  corps_formation_id uuid NOT NULL,
  famille_nom text NOT NULL,
  famille_description text,
  famille_icone text DEFAULT 'FileText'::text,
  is_active boolean NOT NULL DEFAULT true,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT corps_formation_familles_pkey PRIMARY KEY (id),
  CONSTRAINT corps_formation_familles_corps_formation_id_fkey FOREIGN KEY (corps_formation_id) REFERENCES public.corps_formation(id)
);
CREATE TABLE public.declarations_heures_sup (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  profile_id uuid NOT NULL,
  date_debut date NOT NULL,
  date_fin date NOT NULL,
  heures_max_autorisees numeric NOT NULL DEFAULT 0 CHECK (heures_max_autorisees >= 0::numeric),
  type_autorisation text NOT NULL DEFAULT 'ponctuelle'::text,
  statut text NOT NULL DEFAULT 'en_attente'::text,
  approuve_par uuid,
  date_approbation timestamp with time zone,
  is_active boolean NOT NULL DEFAULT true,
  created_by uuid,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  motif text,
  commentaires text,
  CONSTRAINT declarations_heures_sup_pkey PRIMARY KEY (id),
  CONSTRAINT declarations_heures_sup_approuve_par_fkey FOREIGN KEY (approuve_par) REFERENCES public.profiles(id),
  CONSTRAINT declarations_heures_sup_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.profiles(id),
  CONSTRAINT declarations_heures_sup_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES public.profiles(id)
);
CREATE TABLE public.declarations_inscriptions (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  declared_at date NOT NULL DEFAULT CURRENT_DATE,
  profile_id uuid NOT NULL,
  classe_id uuid NOT NULL,
  ville_id uuid NOT NULL,
  segment_id uuid NOT NULL,
  inscriptions_count integer NOT NULL DEFAULT 0 CHECK (inscriptions_count >= 0),
  inscriptions_ratees_count integer NOT NULL DEFAULT 0 CHECK (inscriptions_ratees_count >= 0),
  commentaire text,
  CONSTRAINT declarations_inscriptions_pkey PRIMARY KEY (id),
  CONSTRAINT declarations_inscriptions_classe_id_fkey FOREIGN KEY (classe_id) REFERENCES public.classes(id),
  CONSTRAINT declarations_inscriptions_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES public.profiles(id),
  CONSTRAINT declarations_inscriptions_segment_id_fkey FOREIGN KEY (segment_id) REFERENCES public.segments(id),
  CONSTRAINT declarations_inscriptions_ville_id_fkey FOREIGN KEY (ville_id) REFERENCES public.villes(id)
);
CREATE TABLE public.demandes_rh (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  demandeur_id uuid NOT NULL,
  type_demande USER-DEFINED NOT NULL,
  titre text NOT NULL,
  description text,
  date_debut date,
  date_fin date,
  montant numeric,
  statut statut_demande_rh NOT NULL DEFAULT 'en_attente'::statut_demande_rh,
  documents_urls jsonb DEFAULT '[]'::jsonb,
  motif_refus text,
  approuve_par uuid,
  date_approbation timestamp with time zone,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  pointage_id uuid,
  donnees_originales jsonb,
  donnees_corrigees jsonb,
  CONSTRAINT demandes_rh_pkey PRIMARY KEY (id),
  CONSTRAINT demandes_rh_pointage_id_fkey FOREIGN KEY (pointage_id) REFERENCES public.pointages(id)
);
CREATE TABLE public.document_blocs (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  modele_id uuid NOT NULL,
  nom_bloc text NOT NULL,
  type_contenu text NOT NULL DEFAULT 'texte'::text,
  face text NOT NULL DEFAULT 'recto'::text,
  position_x numeric NOT NULL DEFAULT 0,
  position_y numeric NOT NULL DEFAULT 0,
  largeur numeric NOT NULL DEFAULT 100,
  hauteur numeric NOT NULL DEFAULT 30,
  styles_css jsonb DEFAULT '{}'::jsonb,
  ordre_affichage integer DEFAULT 0,
  is_active boolean NOT NULL DEFAULT true,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT document_blocs_pkey PRIMARY KEY (id),
  CONSTRAINT document_blocs_modele_id_fkey FOREIGN KEY (modele_id) REFERENCES public.modeles_documents(id)
);
CREATE TABLE public.document_generation_logs (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  etudiant_id uuid,
  formation_id uuid,
  famille_type text NOT NULL,
  modele_id uuid,
  modele_nom text,
  status text NOT NULL CHECK (status = ANY (ARRAY['started'::text, 'success'::text, 'failed'::text, 'not_found'::text])),
  error_message text,
  file_path text,
  file_name text,
  execution_time_ms integer,
  metadata jsonb DEFAULT '{}'::jsonb,
  created_at timestamp with time zone DEFAULT now(),
  updated_at timestamp with time zone DEFAULT now(),
  CONSTRAINT document_generation_logs_pkey PRIMARY KEY (id),
  CONSTRAINT document_generation_logs_etudiant_id_fkey FOREIGN KEY (etudiant_id) REFERENCES public.etudiants(id),
  CONSTRAINT document_generation_logs_formation_id_fkey FOREIGN KEY (formation_id) REFERENCES public.formations(id)
);
CREATE TABLE public.documents_generes (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  modele_id uuid NOT NULL,
  etudiant_id uuid NOT NULL,
  fichier_url text NOT NULL,
  generated_by uuid,
  generated_at timestamp with time zone NOT NULL DEFAULT now(),
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT documents_generes_pkey PRIMARY KEY (id),
  CONSTRAINT documents_generes_etudiant_id_fkey FOREIGN KEY (etudiant_id) REFERENCES public.etudiants(id),
  CONSTRAINT documents_generes_generated_by_fkey FOREIGN KEY (generated_by) REFERENCES public.profiles(user_id),
  CONSTRAINT documents_generes_modele_id_fkey FOREIGN KEY (modele_id) REFERENCES public.modeles_documents(id)
);
CREATE TABLE public.employee_documents (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  profile_id uuid NOT NULL,
  type_document text NOT NULL,
  document_url text NOT NULL,
  document_name text NOT NULL,
  uploaded_at timestamp with time zone NOT NULL DEFAULT now(),
  description text,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT employee_documents_pkey PRIMARY KEY (id)
);
CREATE TABLE public.employee_payroll_settings (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  profile_id uuid NOT NULL UNIQUE,
  cnss_enabled boolean NOT NULL DEFAULT true,
  amo_enabled boolean NOT NULL DEFAULT true,
  igr_enabled boolean NOT NULL DEFAULT true,
  mutuelle_enabled boolean NOT NULL DEFAULT false,
  autres_retenues jsonb DEFAULT '{}'::jsonb,
  created_at timestamp with time zone DEFAULT now(),
  updated_at timestamp with time zone DEFAULT now(),
  CONSTRAINT employee_payroll_settings_pkey PRIMARY KEY (id),
  CONSTRAINT employee_payroll_settings_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES public.profiles(id)
);
CREATE TABLE public.entretiens (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  candidat_id uuid NOT NULL,
  poste_id uuid NOT NULL,
  interviewer_id uuid NOT NULL,
  date_entretien timestamp with time zone NOT NULL,
  duree_minutes integer DEFAULT 60,
  statut statut_entretien NOT NULL DEFAULT 'programme'::statut_entretien,
  type_entretien text DEFAULT 'technique'::text,
  notes text,
  evaluation_globale integer CHECK (evaluation_globale >= 1 AND evaluation_globale <= 5),
  recommandation text,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT entretiens_pkey PRIMARY KEY (id),
  CONSTRAINT entretiens_candidat_id_fkey FOREIGN KEY (candidat_id) REFERENCES public.candidats(id),
  CONSTRAINT entretiens_poste_id_fkey FOREIGN KEY (poste_id) REFERENCES public.postes_ouverts(id)
);
CREATE TABLE public.equipes_projet (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  projet_id uuid NOT NULL,
  profile_id uuid NOT NULL,
  role_projet text NOT NULL,
  date_affectation date NOT NULL DEFAULT CURRENT_DATE,
  date_retrait date,
  is_active boolean NOT NULL DEFAULT true,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT equipes_projet_pkey PRIMARY KEY (id),
  CONSTRAINT equipes_projet_projet_id_fkey FOREIGN KEY (projet_id) REFERENCES public.projets(id)
);
CREATE TABLE public.etudiants (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  nom text NOT NULL,
  prenom text NOT NULL,
  cin text,
  email text,
  telephone text,
  whatsapp text,
  date_naissance date,
  lieu_naissance text,
  adresse text,
  photo_url text,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT etudiants_pkey PRIMARY KEY (id)
);
CREATE TABLE public.evaluations_performance (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  profile_id uuid NOT NULL,
  evaluateur_id uuid NOT NULL,
  template_id uuid NOT NULL,
  periode_debut date NOT NULL,
  periode_fin date NOT NULL,
  scores jsonb DEFAULT '{}'::jsonb,
  commentaires text,
  objectifs_atteints text,
  axes_amelioration text,
  note_globale numeric,
  is_finalized boolean NOT NULL DEFAULT false,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT evaluations_performance_pkey PRIMARY KEY (id),
  CONSTRAINT evaluations_performance_template_id_fkey FOREIGN KEY (template_id) REFERENCES public.templates_evaluation(id)
);
CREATE TABLE public.exercises (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  name text NOT NULL,
  category USER-DEFINED NOT NULL,
  target_zones text[] DEFAULT '{}'::text[],
  equipment text[] DEFAULT '{}'::text[],
  description text,
  video_url text,
  difficulty_level integer DEFAULT 1 CHECK (difficulty_level >= 1 AND difficulty_level <= 5),
  duration_minutes integer,
  calories_per_minute numeric,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT exercises_pkey PRIMARY KEY (id)
);
CREATE TABLE public.fitshape_profiles (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL UNIQUE,
  first_name text,
  last_name text,
  sex USER-DEFINED,
  height_cm integer,
  weight_kg numeric,
  goal USER-DEFINED,
  body_shape USER-DEFINED,
  level USER-DEFINED DEFAULT 'debutant'::user_level,
  days_per_week integer DEFAULT 3,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT fitshape_profiles_pkey PRIMARY KEY (id),
  CONSTRAINT fitshape_profiles_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id)
);
CREATE TABLE public.formation_assignments (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL,
  formation_id uuid NOT NULL,
  assigned_by uuid NOT NULL,
  assigned_at timestamp with time zone NOT NULL DEFAULT now(),
  is_active boolean NOT NULL DEFAULT true,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT formation_assignments_pkey PRIMARY KEY (id),
  CONSTRAINT fk_formation_assignments_formation FOREIGN KEY (formation_id) REFERENCES public.formations(id)
);
CREATE TABLE public.formation_modeles (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  formation_id uuid NOT NULL,
  modele_id uuid NOT NULL,
  is_active boolean NOT NULL DEFAULT true,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  famille_context_id uuid,
  CONSTRAINT formation_modeles_pkey PRIMARY KEY (id),
  CONSTRAINT fk_formation_modeles_formation FOREIGN KEY (formation_id) REFERENCES public.formations(id),
  CONSTRAINT fk_formation_modeles_modele FOREIGN KEY (modele_id) REFERENCES public.modeles_documents(id),
  CONSTRAINT formation_modeles_famille_context_id_fkey FOREIGN KEY (famille_context_id) REFERENCES public.corps_formation_familles(id)
);
CREATE TABLE public.formations (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  titre text NOT NULL,
  description text,
  duree_heures integer NOT NULL DEFAULT 0,
  niveau text NOT NULL DEFAULT 'debutant'::text,
  prix numeric,
  centre_id uuid,
  is_active boolean NOT NULL DEFAULT true,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  type_formation formation_type NOT NULL DEFAULT 'physique'::formation_type,
  plateforme_id uuid,
  reference text,
  horaire text DEFAULT 'matin'::text,
  corps_formation_id uuid,
  CONSTRAINT formations_pkey PRIMARY KEY (id),
  CONSTRAINT fk_formations_centre FOREIGN KEY (centre_id) REFERENCES public.centres(id),
  CONSTRAINT formations_corps_formation_id_fkey FOREIGN KEY (corps_formation_id) REFERENCES public.corps_formation(id),
  CONSTRAINT formations_plateforme_id_fkey FOREIGN KEY (plateforme_id) REFERENCES public.plateformes(id)
);
CREATE TABLE public.formats_documents (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  nom text NOT NULL,
  largeur_mm numeric NOT NULL,
  hauteur_mm numeric NOT NULL,
  is_predefined boolean NOT NULL DEFAULT false,
  is_active boolean NOT NULL DEFAULT true,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT formats_documents_pkey PRIMARY KEY (id)
);
CREATE TABLE public.groupes_classes (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  nom text NOT NULL,
  description text,
  corps_formation_id uuid NOT NULL UNIQUE,
  is_active boolean NOT NULL DEFAULT true,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT groupes_classes_pkey PRIMARY KEY (id),
  CONSTRAINT groupes_classes_corps_formation_id_fkey FOREIGN KEY (corps_formation_id) REFERENCES public.corps_formation(id)
);
CREATE TABLE public.groupes_documents (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  nom text NOT NULL UNIQUE,
  description text,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  is_active boolean NOT NULL DEFAULT true,
  CONSTRAINT groupes_documents_pkey PRIMARY KEY (id)
);
CREATE TABLE public.horaires_modeles (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  nom text NOT NULL,
  description text,
  is_active boolean NOT NULL DEFAULT false,
  horaires_semaine jsonb NOT NULL DEFAULT '{}'::jsonb,
  jours_feries text[] DEFAULT '{}'::text[],
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT horaires_modeles_pkey PRIMARY KEY (id)
);
CREATE TABLE public.inscriptions (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  etudiant_id uuid NOT NULL,
  classe_id uuid,
  session_en_ligne_id uuid,
  numero_bon text,
  avance numeric DEFAULT 0,
  statut_compte text,
  statut_inscription statut_inscription NOT NULL DEFAULT 'en_attente'::statut_inscription,
  date_inscription timestamp with time zone NOT NULL DEFAULT now(),
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  student_id_unique text,
  formation_id uuid,
  statut_connexion text NOT NULL DEFAULT 'active'::text CHECK (statut_connexion = ANY (ARRAY['active'::text, 'bloquer'::text])),
  statut_document text NOT NULL DEFAULT 'valide'::text CHECK (statut_document = ANY (ARRAY['valide'::text, 'abondan'::text])),
  CONSTRAINT inscriptions_pkey PRIMARY KEY (id),
  CONSTRAINT inscriptions_classe_id_fkey FOREIGN KEY (classe_id) REFERENCES public.classes(id),
  CONSTRAINT inscriptions_etudiant_id_fkey FOREIGN KEY (etudiant_id) REFERENCES public.etudiants(id),
  CONSTRAINT inscriptions_formation_id_fkey FOREIGN KEY (formation_id) REFERENCES public.formations(id),
  CONSTRAINT inscriptions_session_en_ligne_id_fkey FOREIGN KEY (session_en_ligne_id) REFERENCES public.sessions_en_ligne(id)
);
CREATE TABLE public.interactions_prospects (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  prospect_id uuid NOT NULL,
  type_interaction text NOT NULL,
  description text NOT NULL,
  date_interaction timestamp with time zone NOT NULL DEFAULT now(),
  duree_minutes integer,
  resultat text,
  prochaine_action text,
  created_by uuid NOT NULL,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT interactions_prospects_pkey PRIMARY KEY (id),
  CONSTRAINT interactions_prospects_prospect_id_fkey FOREIGN KEY (prospect_id) REFERENCES public.prospects(id)
);
CREATE TABLE public.jours_feries (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  nom text NOT NULL,
  date_ferie date NOT NULL,
  type_ferie text NOT NULL DEFAULT 'national'::text,
  is_active boolean NOT NULL DEFAULT true,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT jours_feries_pkey PRIMARY KEY (id)
);
CREATE TABLE public.jours_feries_collectifs (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  nom text NOT NULL,
  date_debut date NOT NULL,
  date_fin date NOT NULL,
  type_conge text NOT NULL DEFAULT 'ferie'::text,
  description text,
  is_recurrent boolean NOT NULL DEFAULT false,
  is_active boolean NOT NULL DEFAULT true,
  created_by uuid,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT jours_feries_collectifs_pkey PRIMARY KEY (id),
  CONSTRAINT jours_feries_collectifs_created_by_fkey FOREIGN KEY (created_by) REFERENCES auth.users(id)
);
CREATE TABLE public.measurements (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL,
  date date NOT NULL DEFAULT CURRENT_DATE,
  weight_kg numeric,
  waist_cm numeric,
  hip_cm numeric,
  chest_cm numeric,
  arm_cm numeric,
  thigh_cm numeric,
  note text,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT measurements_pkey PRIMARY KEY (id),
  CONSTRAINT measurements_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id)
);
CREATE TABLE public.messages (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  conversation_id uuid NOT NULL,
  sender_id uuid NOT NULL,
  contenu text NOT NULL,
  fichier_url text,
  reply_to_id uuid,
  is_edited boolean NOT NULL DEFAULT false,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT messages_pkey PRIMARY KEY (id),
  CONSTRAINT messages_conversation_id_fkey FOREIGN KEY (conversation_id) REFERENCES public.conversations(id),
  CONSTRAINT messages_reply_to_id_fkey FOREIGN KEY (reply_to_id) REFERENCES public.messages(id)
);
CREATE TABLE public.modeles_documents (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  formation_id uuid,
  type_document USER-DEFINED NOT NULL,
  nom_modele text NOT NULL,
  fichier_url text,
  variables_disponibles jsonb DEFAULT '[]'::jsonb,
  is_active boolean NOT NULL DEFAULT true,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  format_page text DEFAULT 'A4'::text,
  orientation text DEFAULT 'portrait'::text,
  image_recto_url text,
  image_verso_url text,
  groupe text DEFAULT 'Général'::text,
  famille text DEFAULT 'Général'::text,
  corps_formation_famille_id uuid,
  CONSTRAINT modeles_documents_pkey PRIMARY KEY (id),
  CONSTRAINT modeles_documents_corps_formation_famille_id_fkey FOREIGN KEY (corps_formation_famille_id) REFERENCES public.corps_formation_familles(id),
  CONSTRAINT modeles_documents_formation_id_fkey FOREIGN KEY (formation_id) REFERENCES public.formations(id)
);
CREATE TABLE public.new_absences_retards (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  profile_id uuid NOT NULL,
  type_absence text NOT NULL,
  date_debut date NOT NULL,
  date_fin date,
  duree_heures numeric DEFAULT 0,
  justifie boolean DEFAULT false,
  justificatif_url text,
  notes text,
  created_at timestamp with time zone DEFAULT now(),
  CONSTRAINT new_absences_retards_pkey PRIMARY KEY (id)
);
CREATE TABLE public.new_configuration (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  cle text NOT NULL UNIQUE,
  valeur jsonb NOT NULL,
  description text,
  module text NOT NULL,
  is_public boolean DEFAULT false,
  updated_by uuid,
  updated_at timestamp with time zone DEFAULT now(),
  CONSTRAINT new_configuration_pkey PRIMARY KEY (id)
);
CREATE TABLE public.new_corps_formation (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  nom text NOT NULL UNIQUE,
  description text,
  secteur text,
  is_active boolean DEFAULT true,
  created_at timestamp with time zone DEFAULT now(),
  CONSTRAINT new_corps_formation_pkey PRIMARY KEY (id)
);
CREATE TABLE public.new_demandes_rh (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  demandeur_id uuid NOT NULL,
  type_demande USER-DEFINED NOT NULL,
  titre text NOT NULL,
  description text,
  date_debut date,
  date_fin date,
  montant numeric,
  statut statut_demande_rh_new DEFAULT 'en_attente'::statut_demande_rh_new,
  approuve_par uuid,
  date_approbation timestamp with time zone,
  motif_refus text,
  documents_urls jsonb DEFAULT '[]'::jsonb,
  created_at timestamp with time zone DEFAULT now(),
  updated_at timestamp with time zone DEFAULT now(),
  CONSTRAINT new_demandes_rh_pkey PRIMARY KEY (id)
);
CREATE TABLE public.new_equipes_projet (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  projet_id uuid,
  profile_id uuid,
  role_projet text,
  date_affectation timestamp with time zone DEFAULT now(),
  date_fin_affectation timestamp with time zone,
  taux_implication integer DEFAULT 100,
  CONSTRAINT new_equipes_projet_pkey PRIMARY KEY (id),
  CONSTRAINT new_equipes_projet_projet_id_fkey FOREIGN KEY (projet_id) REFERENCES public.new_projets(id)
);
CREATE TABLE public.new_notifications (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  destinataire_id uuid NOT NULL,
  titre text NOT NULL,
  message text NOT NULL,
  type_notification text DEFAULT 'info'::text,
  lu boolean DEFAULT false,
  date_lecture timestamp with time zone,
  lien_action text,
  metadata jsonb DEFAULT '{}'::jsonb,
  created_at timestamp with time zone DEFAULT now(),
  CONSTRAINT new_notifications_pkey PRIMARY KEY (id)
);
CREATE TABLE public.new_projets (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  nom text NOT NULL,
  description text,
  client text,
  chef_projet_id uuid NOT NULL,
  date_debut date NOT NULL,
  date_fin_prevue date NOT NULL,
  date_fin_reelle date,
  budget numeric,
  cout_reel numeric DEFAULT 0,
  progression_percent integer DEFAULT 0,
  statut statut_projet_new DEFAULT 'planifie'::statut_projet_new,
  priorite priorite_tache_new DEFAULT 'normale'::priorite_tache_new,
  segment_id uuid,
  tags jsonb DEFAULT '[]'::jsonb,
  created_at timestamp with time zone DEFAULT now(),
  updated_at timestamp with time zone DEFAULT now(),
  CONSTRAINT new_projets_pkey PRIMARY KEY (id)
);
CREATE TABLE public.new_taches_projet (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  projet_id uuid NOT NULL,
  titre text NOT NULL,
  description text,
  assignee_id uuid,
  date_debut date,
  date_fin_prevue date,
  date_fin_reelle date,
  estimation_heures numeric,
  heures_reelles numeric DEFAULT 0,
  parent_tache_id uuid,
  priorite priorite_tache_new DEFAULT 'normale'::priorite_tache_new,
  statut statut_tache_new DEFAULT 'a_faire'::statut_tache_new,
  progression_percent integer DEFAULT 0,
  tags jsonb DEFAULT '[]'::jsonb,
  created_by uuid,
  created_at timestamp with time zone DEFAULT now(),
  updated_at timestamp with time zone DEFAULT now(),
  CONSTRAINT new_taches_projet_pkey PRIMARY KEY (id),
  CONSTRAINT new_taches_projet_parent_tache_id_fkey FOREIGN KEY (parent_tache_id) REFERENCES public.new_taches_projet(id),
  CONSTRAINT new_taches_projet_projet_id_fkey FOREIGN KEY (projet_id) REFERENCES public.new_projets(id)
);
CREATE TABLE public.objectifs (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  profile_id uuid NOT NULL,
  titre text NOT NULL,
  description text,
  date_echeance date,
  progression_percent integer DEFAULT 0 CHECK (progression_percent >= 0 AND progression_percent <= 100),
  is_completed boolean NOT NULL DEFAULT false,
  created_by uuid NOT NULL,
  evaluation_id uuid,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT objectifs_pkey PRIMARY KEY (id),
  CONSTRAINT objectifs_evaluation_id_fkey FOREIGN KEY (evaluation_id) REFERENCES public.evaluations_performance(id)
);
CREATE TABLE public.paiement_audit (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  paiement_id uuid NOT NULL,
  action text NOT NULL CHECK (action = ANY (ARRAY['INSERT'::text, 'UPDATE'::text, 'DELETE'::text])),
  old_values jsonb,
  new_values jsonb,
  modified_by uuid NOT NULL,
  modified_at timestamp with time zone NOT NULL DEFAULT now(),
  ip_address inet,
  user_agent text,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT paiement_audit_pkey PRIMARY KEY (id)
);
CREATE TABLE public.paiements (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  inscription_id uuid NOT NULL,
  montant numeric NOT NULL DEFAULT 0,
  date_paiement timestamp with time zone NOT NULL DEFAULT now(),
  methode_paiement text NOT NULL DEFAULT 'Espèces'::text,
  numero_piece text,
  notes text,
  created_by uuid NOT NULL,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT paiements_pkey PRIMARY KEY (id)
);
CREATE TABLE public.payroll_auto_corrections (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  period_id uuid,
  profile_id uuid,
  error_type text NOT NULL,
  error_description text NOT NULL,
  original_values jsonb NOT NULL,
  corrected_values jsonb NOT NULL,
  correction_method text NOT NULL,
  applied boolean NOT NULL DEFAULT false,
  applied_at timestamp with time zone,
  applied_by uuid,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT payroll_auto_corrections_pkey PRIMARY KEY (id),
  CONSTRAINT payroll_auto_corrections_applied_by_fkey FOREIGN KEY (applied_by) REFERENCES auth.users(id),
  CONSTRAINT payroll_auto_corrections_period_id_fkey FOREIGN KEY (period_id) REFERENCES public.payroll_periods(id),
  CONSTRAINT payroll_auto_corrections_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES public.profiles(id)
);
CREATE TABLE public.payroll_automated_tests (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  test_name text NOT NULL,
  test_category text NOT NULL,
  test_type text NOT NULL,
  test_data jsonb NOT NULL,
  expected_result jsonb NOT NULL,
  is_active boolean NOT NULL DEFAULT true,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT payroll_automated_tests_pkey PRIMARY KEY (id)
);
CREATE TABLE public.payroll_calculation_logs (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  period_id uuid,
  profile_id uuid,
  operation_type text NOT NULL,
  status text NOT NULL DEFAULT 'started'::text,
  execution_time_ms integer,
  input_data jsonb NOT NULL DEFAULT '{}'::jsonb,
  output_data jsonb,
  error_details jsonb,
  warnings jsonb DEFAULT '[]'::jsonb,
  metadata jsonb DEFAULT '{}'::jsonb,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT payroll_calculation_logs_pkey PRIMARY KEY (id),
  CONSTRAINT payroll_calculation_logs_period_id_fkey FOREIGN KEY (period_id) REFERENCES public.payroll_periods(id),
  CONSTRAINT payroll_calculation_logs_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES public.profiles(id)
);
CREATE TABLE public.payroll_config (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  key text NOT NULL UNIQUE,
  value jsonb NOT NULL DEFAULT '{}'::jsonb,
  description text,
  is_active boolean NOT NULL DEFAULT true,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT payroll_config_pkey PRIMARY KEY (id)
);
CREATE TABLE public.payroll_lines (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  code text NOT NULL UNIQUE,
  name text NOT NULL,
  type text NOT NULL CHECK (type = ANY (ARRAY['gain'::text, 'retenue'::text])),
  formula text,
  base_amount numeric DEFAULT 0,
  percentage numeric DEFAULT 0,
  soumis_cnss boolean NOT NULL DEFAULT false,
  soumis_amo boolean NOT NULL DEFAULT false,
  imposable_igr boolean NOT NULL DEFAULT false,
  is_active boolean NOT NULL DEFAULT true,
  ordre_affichage integer DEFAULT 0,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT payroll_lines_pkey PRIMARY KEY (id)
);
CREATE TABLE public.payroll_performance_metrics (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  period_id uuid,
  metric_name text NOT NULL,
  metric_value numeric NOT NULL,
  metric_unit text NOT NULL,
  benchmark_value numeric,
  is_within_threshold boolean,
  recorded_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT payroll_performance_metrics_pkey PRIMARY KEY (id),
  CONSTRAINT payroll_performance_metrics_period_id_fkey FOREIGN KEY (period_id) REFERENCES public.payroll_periods(id)
);
CREATE TABLE public.payroll_periods (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  segment_id uuid,
  year integer NOT NULL,
  month integer NOT NULL CHECK (month >= 1 AND month <= 12),
  start_date date NOT NULL,
  end_date date NOT NULL,
  payday date,
  status text NOT NULL DEFAULT 'draft'::text CHECK (status = ANY (ARRAY['draft'::text, 'active'::text, 'validated'::text, 'closed'::text])),
  window_config jsonb NOT NULL DEFAULT '{"day": 19, "type": "fixed_day"}'::jsonb,
  created_by uuid NOT NULL,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT payroll_periods_pkey PRIMARY KEY (id),
  CONSTRAINT payroll_periods_segment_id_fkey FOREIGN KEY (segment_id) REFERENCES public.segments(id)
);
CREATE TABLE public.payroll_results (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  period_id uuid NOT NULL,
  profile_id uuid NOT NULL,
  gross_pay numeric NOT NULL DEFAULT 0,
  net_pay numeric NOT NULL DEFAULT 0,
  cnss_employee numeric NOT NULL DEFAULT 0,
  cnss_employer numeric NOT NULL DEFAULT 0,
  amo_employee numeric NOT NULL DEFAULT 0,
  amo_employer numeric NOT NULL DEFAULT 0,
  igr_amount numeric NOT NULL DEFAULT 0,
  leave_accrual_days numeric NOT NULL DEFAULT 0,
  worked_hours numeric NOT NULL DEFAULT 0,
  overtime_hours numeric NOT NULL DEFAULT 0,
  absence_hours numeric NOT NULL DEFAULT 0,
  lines_detail jsonb NOT NULL DEFAULT '[]'::jsonb,
  calculation_snapshot jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT payroll_results_pkey PRIMARY KEY (id),
  CONSTRAINT payroll_results_period_id_fkey FOREIGN KEY (period_id) REFERENCES public.payroll_periods(id),
  CONSTRAINT payroll_results_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES public.profiles(id)
);
CREATE TABLE public.payroll_test_results (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  test_id uuid,
  test_run_id uuid NOT NULL,
  status text NOT NULL,
  actual_result jsonb,
  execution_time_ms integer,
  error_message text,
  differences jsonb,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT payroll_test_results_pkey PRIMARY KEY (id),
  CONSTRAINT payroll_test_results_test_id_fkey FOREIGN KEY (test_id) REFERENCES public.payroll_automated_tests(id)
);
CREATE TABLE public.permissions (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  nom text NOT NULL UNIQUE,
  description text,
  module text NOT NULL,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT permissions_pkey PRIMARY KEY (id)
);
CREATE TABLE public.planb_centres (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  nom text NOT NULL,
  segment_id uuid,
  ville_id uuid,
  adresse_complete text,
  telephone text,
  email text,
  capacite_max integer DEFAULT 50,
  equipements jsonb DEFAULT '[]'::jsonb,
  horaires_ouverture jsonb DEFAULT '{}'::jsonb,
  coordonnees_gps point,
  statut planb_statut_enum NOT NULL DEFAULT 'actif'::planb_statut_enum,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT planb_centres_pkey PRIMARY KEY (id),
  CONSTRAINT planb_centres_segment_id_fkey FOREIGN KEY (segment_id) REFERENCES public.planb_segments(id),
  CONSTRAINT planb_centres_ville_id_fkey FOREIGN KEY (ville_id) REFERENCES public.planb_villes(id)
);
CREATE TABLE public.planb_classes (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  nom_classe text NOT NULL,
  formation_id uuid,
  groupe_classe_id uuid,
  centre_id uuid NOT NULL,
  date_debut date NOT NULL,
  date_fin date NOT NULL,
  horaire_debut time without time zone,
  horaire_fin time without time zone,
  nombre_places integer NOT NULL DEFAULT 20 CHECK (nombre_places > 0),
  places_reservees integer DEFAULT 0,
  formateur_principal_id uuid,
  formateurs_assistants uuid[] DEFAULT '{}'::uuid[],
  salle text,
  equipements_requis text[],
  materiel_fourni text[],
  statut planb_statut_classe_enum NOT NULL DEFAULT 'programmee'::planb_statut_classe_enum,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT planb_classes_pkey PRIMARY KEY (id),
  CONSTRAINT planb_classes_centre_id_fkey FOREIGN KEY (centre_id) REFERENCES public.planb_centres(id),
  CONSTRAINT planb_classes_formateur_principal_id_fkey FOREIGN KEY (formateur_principal_id) REFERENCES public.planb_profiles(id),
  CONSTRAINT planb_classes_formation_id_fkey FOREIGN KEY (formation_id) REFERENCES public.planb_formations(id),
  CONSTRAINT planb_classes_groupe_classe_id_fkey FOREIGN KEY (groupe_classe_id) REFERENCES public.planb_groupes_classes(id)
);
CREATE TABLE public.planb_corps_formations (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  nom text NOT NULL UNIQUE,
  description text,
  icone text,
  couleur_hex text DEFAULT '#10B981'::text,
  ordre_affichage integer DEFAULT 0,
  statut planb_statut_enum NOT NULL DEFAULT 'actif'::planb_statut_enum,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT planb_corps_formations_pkey PRIMARY KEY (id)
);
CREATE TABLE public.planb_etudiants (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  nom text NOT NULL,
  prenom text NOT NULL,
  cin text UNIQUE,
  email text,
  telephone text,
  whatsapp text,
  date_naissance date,
  lieu_naissance text,
  adresse_complete text,
  ville text,
  code_postal text,
  pays text DEFAULT 'Maroc'::text,
  niveau_etudes text,
  profession text,
  entreprise text,
  experience_professionnelle text,
  photo_url text,
  source_inscription text,
  commentaires_internes text,
  statut planb_statut_enum NOT NULL DEFAULT 'actif'::planb_statut_enum,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT planb_etudiants_pkey PRIMARY KEY (id)
);
CREATE TABLE public.planb_familles_documents (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  corps_formation_id uuid NOT NULL,
  nom text NOT NULL,
  description text,
  icone text,
  ordre_affichage integer DEFAULT 0,
  statut planb_statut_enum NOT NULL DEFAULT 'actif'::planb_statut_enum,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT planb_familles_documents_pkey PRIMARY KEY (id),
  CONSTRAINT planb_familles_documents_corps_formation_id_fkey FOREIGN KEY (corps_formation_id) REFERENCES public.planb_corps_formations(id)
);
CREATE TABLE public.planb_formations (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  titre text NOT NULL,
  description text,
  reference text,
  corps_formation_id uuid,
  type_formation planb_type_formation_enum NOT NULL DEFAULT 'physique'::planb_type_formation_enum,
  niveau planb_niveau_enum NOT NULL DEFAULT 'debutant'::planb_niveau_enum,
  duree_heures integer NOT NULL DEFAULT 0,
  duree_jours integer DEFAULT ceil(((duree_heures)::numeric / (8)::numeric)),
  prix numeric,
  prix_en_ligne numeric,
  centre_id uuid,
  plateforme_id uuid,
  objectifs_pedagogiques text[],
  prerequis text[],
  programme_detaille jsonb,
  statut planb_statut_enum NOT NULL DEFAULT 'actif'::planb_statut_enum,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT planb_formations_pkey PRIMARY KEY (id),
  CONSTRAINT planb_formations_centre_id_fkey FOREIGN KEY (centre_id) REFERENCES public.planb_centres(id),
  CONSTRAINT planb_formations_corps_formation_id_fkey FOREIGN KEY (corps_formation_id) REFERENCES public.planb_corps_formations(id),
  CONSTRAINT planb_formations_plateforme_id_fkey FOREIGN KEY (plateforme_id) REFERENCES public.planb_plateformes(id)
);
CREATE TABLE public.planb_groupes_classes (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  nom text NOT NULL,
  description text,
  corps_formation_id uuid NOT NULL,
  statut planb_statut_enum NOT NULL DEFAULT 'actif'::planb_statut_enum,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT planb_groupes_classes_pkey PRIMARY KEY (id),
  CONSTRAINT planb_groupes_classes_corps_formation_id_fkey FOREIGN KEY (corps_formation_id) REFERENCES public.corps_formation(id)
);
CREATE TABLE public.planb_inscriptions (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  etudiant_id uuid NOT NULL,
  formation_id uuid NOT NULL,
  classe_id uuid,
  numero_inscription text UNIQUE,
  student_id_unique text UNIQUE,
  date_inscription timestamp with time zone NOT NULL DEFAULT now(),
  date_confirmation timestamp with time zone,
  date_debut_formation date,
  date_fin_formation date,
  prix_formation numeric CHECK (prix_formation >= 0::numeric),
  remise_accordee numeric DEFAULT 0 CHECK (remise_accordee >= 0::numeric),
  prix_final numeric DEFAULT (prix_formation - COALESCE(remise_accordee, (0)::numeric)),
  bon_commande text,
  convention_signee boolean DEFAULT false,
  documents_fournis text[],
  note_finale numeric CHECK (note_finale IS NULL OR note_finale >= 0::numeric AND note_finale <= 20::numeric),
  appreciation text,
  presence_heures integer DEFAULT 0 CHECK (presence_heures >= 0),
  absence_heures integer DEFAULT 0 CHECK (absence_heures >= 0),
  taux_presence numeric DEFAULT 
CASE
    WHEN ((presence_heures + absence_heures) > 0) THEN (((presence_heures)::numeric / ((presence_heures + absence_heures))::numeric) * (100)::numeric)
    ELSE (0)::numeric
END,
  certifie boolean DEFAULT false,
  date_certification timestamp with time zone,
  numero_certificat text,
  statut_inscription planb_statut_inscription_enum NOT NULL DEFAULT 'en_attente'::planb_statut_inscription_enum,
  statut_compte planb_statut_compte_enum NOT NULL DEFAULT 'en_cours'::planb_statut_compte_enum,
  notes_internes text,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT planb_inscriptions_pkey PRIMARY KEY (id),
  CONSTRAINT planb_inscriptions_classe_id_fkey FOREIGN KEY (classe_id) REFERENCES public.planb_classes(id),
  CONSTRAINT planb_inscriptions_etudiant_id_fkey FOREIGN KEY (etudiant_id) REFERENCES public.planb_etudiants(id),
  CONSTRAINT planb_inscriptions_formation_id_fkey FOREIGN KEY (formation_id) REFERENCES public.planb_formations(id)
);
CREATE TABLE public.planb_paiements (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  inscription_id uuid NOT NULL,
  montant numeric NOT NULL CHECK (montant > 0::numeric),
  devise text DEFAULT 'DH'::text,
  methode_paiement text NOT NULL,
  reference_transaction text,
  numero_piece text,
  date_paiement timestamp with time zone NOT NULL DEFAULT now(),
  date_encaissement timestamp with time zone,
  valide boolean DEFAULT true,
  valide_par uuid,
  date_validation timestamp with time zone,
  notes text,
  created_by uuid,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT planb_paiements_pkey PRIMARY KEY (id),
  CONSTRAINT planb_paiements_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.planb_profiles(id),
  CONSTRAINT planb_paiements_inscription_id_fkey FOREIGN KEY (inscription_id) REFERENCES public.planb_inscriptions(id),
  CONSTRAINT planb_paiements_valide_par_fkey FOREIGN KEY (valide_par) REFERENCES public.planb_profiles(id)
);
CREATE TABLE public.planb_permissions (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  nom text NOT NULL UNIQUE,
  description text,
  module text NOT NULL,
  action text NOT NULL,
  ressource text,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT planb_permissions_pkey PRIMARY KEY (id)
);
CREATE TABLE public.planb_plateformes (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  nom text NOT NULL UNIQUE,
  url_base text,
  api_key_encrypted text,
  configuration jsonb DEFAULT '{}'::jsonb,
  statut planb_statut_enum NOT NULL DEFAULT 'actif'::planb_statut_enum,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT planb_plateformes_pkey PRIMARY KEY (id)
);
CREATE TABLE public.planb_profiles (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL UNIQUE,
  nom text NOT NULL,
  prenom text NOT NULL,
  email text NOT NULL UNIQUE,
  telephone text,
  photo_url text,
  poste text,
  departement text,
  manager_id uuid,
  centre_id uuid,
  segment_id uuid,
  date_naissance date,
  cin text,
  adresse_ligne1 text,
  adresse_ligne2 text,
  ville text,
  code_postal text,
  pays text DEFAULT 'Maroc'::text,
  date_embauche date,
  type_contrat USER-DEFINED,
  salaire_base numeric,
  numero_cnss text,
  rib text,
  statut planb_statut_enum NOT NULL DEFAULT 'actif'::planb_statut_enum,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT planb_profiles_pkey PRIMARY KEY (id),
  CONSTRAINT planb_profiles_centre_id_fkey FOREIGN KEY (centre_id) REFERENCES public.planb_centres(id),
  CONSTRAINT planb_profiles_manager_id_fkey FOREIGN KEY (manager_id) REFERENCES public.planb_profiles(id),
  CONSTRAINT planb_profiles_segment_id_fkey FOREIGN KEY (segment_id) REFERENCES public.planb_segments(id),
  CONSTRAINT planb_profiles_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id)
);
CREATE TABLE public.planb_role_permissions (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  role_id uuid NOT NULL,
  permission_id uuid NOT NULL,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT planb_role_permissions_pkey PRIMARY KEY (id),
  CONSTRAINT planb_role_permissions_permission_id_fkey FOREIGN KEY (permission_id) REFERENCES public.planb_permissions(id),
  CONSTRAINT planb_role_permissions_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.planb_roles(id)
);
CREATE TABLE public.planb_roles (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  nom text NOT NULL UNIQUE,
  description text,
  niveau_acces integer DEFAULT 1,
  statut planb_statut_enum NOT NULL DEFAULT 'actif'::planb_statut_enum,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT planb_roles_pkey PRIMARY KEY (id)
);
CREATE TABLE public.planb_segments (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  nom text NOT NULL UNIQUE,
  description text,
  couleur_hex text DEFAULT '#3B82F6'::text,
  logo_url text,
  statut planb_statut_enum NOT NULL DEFAULT 'actif'::planb_statut_enum,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT planb_segments_pkey PRIMARY KEY (id)
);
CREATE TABLE public.planb_user_roles (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL,
  role_id uuid NOT NULL,
  assigned_by uuid,
  assigned_at timestamp with time zone NOT NULL DEFAULT now(),
  expires_at timestamp with time zone,
  statut planb_statut_enum NOT NULL DEFAULT 'actif'::planb_statut_enum,
  CONSTRAINT planb_user_roles_pkey PRIMARY KEY (id),
  CONSTRAINT planb_user_roles_assigned_by_fkey FOREIGN KEY (assigned_by) REFERENCES auth.users(id),
  CONSTRAINT planb_user_roles_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.planb_roles(id),
  CONSTRAINT planb_user_roles_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id)
);
CREATE TABLE public.planb_villes (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  nom text NOT NULL,
  code_postal text,
  region text,
  pays text DEFAULT 'Maroc'::text,
  statut planb_statut_enum NOT NULL DEFAULT 'actif'::planb_statut_enum,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT planb_villes_pkey PRIMARY KEY (id)
);
CREATE TABLE public.plannings_individuels (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  profile_id uuid NOT NULL,
  date_planning date NOT NULL,
  heure_debut time without time zone NOT NULL,
  heure_fin time without time zone NOT NULL,
  type_activite text DEFAULT 'travail'::text,
  description text,
  couleur text DEFAULT '#3B82F6'::text,
  created_by uuid NOT NULL,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT plannings_individuels_pkey PRIMARY KEY (id)
);
CREATE TABLE public.plateformes (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  nom text NOT NULL,
  description text,
  url_plateforme text,
  contact_email text,
  is_active boolean NOT NULL DEFAULT true,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT plateformes_pkey PRIMARY KEY (id)
);
CREATE TABLE public.pointages (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  profile_id uuid NOT NULL,
  type_pointage USER-DEFINED NOT NULL,
  timestamp_pointage timestamp with time zone NOT NULL DEFAULT now(),
  localisation text,
  notes text,
  valide_par uuid,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  ecart_minutes integer,
  heures_reelles numeric,
  heures_configurees numeric,
  heure_configuree_entree time without time zone,
  heure_configuree_sortie time without time zone,
  CONSTRAINT pointages_pkey PRIMARY KEY (id)
);
CREATE TABLE public.pointages_automatiques (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  profile_id uuid NOT NULL,
  date_pointage date NOT NULL,
  type_pointage text NOT NULL,
  horaire_debut time without time zone,
  horaire_fin time without time zone,
  heures_travaillees numeric DEFAULT 0,
  motif text,
  demande_rh_id uuid,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT pointages_automatiques_pkey PRIMARY KEY (id)
);
CREATE TABLE public.postes_ouverts (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  titre text NOT NULL,
  description text,
  departement text,
  localisation text,
  salaire_min numeric,
  salaire_max numeric,
  statut statut_poste NOT NULL DEFAULT 'ouvert'::statut_poste,
  date_ouverture date NOT NULL DEFAULT CURRENT_DATE,
  date_fermeture date,
  competences_requises jsonb DEFAULT '[]'::jsonb,
  created_by uuid NOT NULL,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT postes_ouverts_pkey PRIMARY KEY (id)
);
CREATE TABLE public.profile_segments (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  profile_id uuid NOT NULL,
  segment_id uuid NOT NULL,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT profile_segments_pkey PRIMARY KEY (id),
  CONSTRAINT profile_segments_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES public.profiles(id),
  CONSTRAINT profile_segments_segment_id_fkey FOREIGN KEY (segment_id) REFERENCES public.segments(id)
);
CREATE TABLE public.profiles (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL UNIQUE,
  nom text NOT NULL,
  prenom text NOT NULL,
  poste text,
  email text NOT NULL,
  photo_url text,
  chef_hierarchique_id uuid,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  date_naissance date,
  adresse_complete text,
  cin_numero text,
  cin_scan_url text,
  cnss_numero text,
  cnss_scan_url text,
  type_contrat text,
  date_debut_contrat date,
  date_fin_contrat date,
  contrat_scan_url text,
  solde_conges_payes numeric DEFAULT 0,
  telephone_personnel text,
  email_personnel text,
  rib_numero text,
  rib_scan_url text,
  salaire_base numeric,
  date_embauche date,
  numero_cnss text,
  dependents_count integer DEFAULT 0,
  is_manager boolean DEFAULT false,
  salaire_horaire numeric DEFAULT NULL::numeric,
  payroll_enabled boolean NOT NULL DEFAULT true,
  account_status text DEFAULT 'active'::text CHECK (account_status = ANY (ARRAY['active'::text, 'suspended'::text])),
  CONSTRAINT profiles_pkey PRIMARY KEY (id),
  CONSTRAINT profiles_chef_hierarchique_id_fkey FOREIGN KEY (chef_hierarchique_id) REFERENCES public.profiles(id),
  CONSTRAINT profiles_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id)
);
CREATE TABLE public.program_days (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  program_id uuid NOT NULL,
  week_number integer NOT NULL DEFAULT 1,
  day_number integer NOT NULL CHECK (day_number >= 1 AND day_number <= 7),
  name text,
  description text,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT program_days_pkey PRIMARY KEY (id),
  CONSTRAINT program_days_program_id_fkey FOREIGN KEY (program_id) REFERENCES public.programs(id)
);
CREATE TABLE public.program_exercises (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  program_day_id uuid NOT NULL,
  exercise_id uuid NOT NULL,
  sets integer DEFAULT 1,
  reps integer,
  duration_seconds integer,
  rest_seconds integer DEFAULT 60,
  order_index integer NOT NULL DEFAULT 0,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT program_exercises_pkey PRIMARY KEY (id),
  CONSTRAINT program_exercises_exercise_id_fkey FOREIGN KEY (exercise_id) REFERENCES public.exercises(id),
  CONSTRAINT program_exercises_program_day_id_fkey FOREIGN KEY (program_day_id) REFERENCES public.program_days(id)
);
CREATE TABLE public.programs (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL,
  name text NOT NULL,
  description text,
  weeks_duration integer DEFAULT 4,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT programs_pkey PRIMARY KEY (id),
  CONSTRAINT programs_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id)
);
CREATE TABLE public.progress_photos (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL,
  taken_at timestamp with time zone NOT NULL DEFAULT now(),
  storage_path text NOT NULL,
  description text,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT progress_photos_pkey PRIMARY KEY (id),
  CONSTRAINT progress_photos_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id)
);
CREATE TABLE public.project_action_comments (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  action_id uuid NOT NULL,
  author_profile_id uuid NOT NULL,
  commentaire text NOT NULL,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT project_action_comments_pkey PRIMARY KEY (id),
  CONSTRAINT project_action_comments_action_id_fkey FOREIGN KEY (action_id) REFERENCES public.project_actions(id),
  CONSTRAINT project_action_comments_author_profile_id_fkey FOREIGN KEY (author_profile_id) REFERENCES public.profiles(id)
);
CREATE TABLE public.project_actions (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  titre text NOT NULL,
  description text,
  segment_id uuid,
  assigned_to_profile_id uuid NOT NULL,
  assigned_by_profile_id uuid NOT NULL,
  assigned_at timestamp with time zone NOT NULL DEFAULT now(),
  due_date date,
  statut action_statut NOT NULL DEFAULT 'todo'::action_statut,
  progress_percent smallint NOT NULL DEFAULT 0 CHECK (progress_percent = ANY (ARRAY[0, 20, 50, 80, 100])),
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  commentaire text,
  CONSTRAINT project_actions_pkey PRIMARY KEY (id),
  CONSTRAINT project_actions_assigned_by_profile_id_fkey FOREIGN KEY (assigned_by_profile_id) REFERENCES public.profiles(id),
  CONSTRAINT project_actions_assigned_to_profile_id_fkey FOREIGN KEY (assigned_to_profile_id) REFERENCES public.profiles(id),
  CONSTRAINT project_actions_segment_id_fkey FOREIGN KEY (segment_id) REFERENCES public.segments(id)
);
CREATE TABLE public.projet_actions (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  projet_id uuid NOT NULL,
  action_id uuid NOT NULL,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT projet_actions_pkey PRIMARY KEY (id),
  CONSTRAINT projet_actions_action_id_fkey FOREIGN KEY (action_id) REFERENCES public.project_actions(id),
  CONSTRAINT projet_actions_projet_id_fkey FOREIGN KEY (projet_id) REFERENCES public.new_projets(id)
);
CREATE TABLE public.projets (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  nom text NOT NULL,
  description text,
  date_debut date NOT NULL,
  date_fin_prevue date NOT NULL,
  date_fin_reelle date,
  statut statut_projet NOT NULL DEFAULT 'planifie'::statut_projet,
  budget numeric,
  chef_projet_id uuid NOT NULL,
  client text,
  progression_percent integer DEFAULT 0 CHECK (progression_percent >= 0 AND progression_percent <= 100),
  segment_id uuid,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT projets_pkey PRIMARY KEY (id)
);
CREATE TABLE public.prospects (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  nom text NOT NULL,
  prenom text NOT NULL,
  email text NOT NULL,
  telephone text,
  entreprise text,
  poste text,
  ville_id uuid,
  statut text NOT NULL DEFAULT 'nouveau'::text,
  source text,
  notes text,
  date_contact date,
  created_by uuid,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  cin text,
  ville text,
  segment text NOT NULL DEFAULT ''::text,
  statut_contact text NOT NULL DEFAULT 'non contacté'::text,
  statut_inscription text NOT NULL DEFAULT 'Non inscrit'::text,
  rdv_a text,
  rdv_le timestamp with time zone,
  formation_interesse text,
  commercial text,
  derniere_interaction timestamp with time zone,
  prospect_id_unique text,
  segment_id uuid,
  duree_appel integer,
  CONSTRAINT prospects_pkey PRIMARY KEY (id),
  CONSTRAINT fk_prospects_segment FOREIGN KEY (segment_id) REFERENCES public.segments(id),
  CONSTRAINT fk_prospects_ville FOREIGN KEY (ville_id) REFERENCES public.villes(id),
  CONSTRAINT prospects_segment_id_fkey FOREIGN KEY (segment_id) REFERENCES public.segments(id)
);
CREATE TABLE public.role_permissions (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  role_id uuid NOT NULL,
  permission_id uuid NOT NULL,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT role_permissions_pkey PRIMARY KEY (id),
  CONSTRAINT role_permissions_permission_id_fkey FOREIGN KEY (permission_id) REFERENCES public.permissions(id),
  CONSTRAINT role_permissions_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.roles(id)
);
CREATE TABLE public.roles (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  nom text NOT NULL UNIQUE,
  description text,
  type role_type NOT NULL DEFAULT 'custom'::role_type,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  hierarchy_level integer DEFAULT 1,
  is_active boolean DEFAULT true,
  CONSTRAINT roles_pkey PRIMARY KEY (id)
);
CREATE TABLE public.salary_advance_installments (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  advance_id uuid NOT NULL,
  mois_echeance date NOT NULL,
  montant numeric NOT NULL,
  statut_paiement text NOT NULL DEFAULT 'en_attente'::text CHECK (statut_paiement = ANY (ARRAY['en_attente'::text, 'paye'::text, 'reporte'::text])),
  date_paiement timestamp with time zone,
  payroll_period_id uuid,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT salary_advance_installments_pkey PRIMARY KEY (id),
  CONSTRAINT salary_advance_installments_advance_id_fkey FOREIGN KEY (advance_id) REFERENCES public.salary_advances(id)
);
CREATE TABLE public.salary_advances (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  profile_id uuid NOT NULL,
  montant_avance numeric NOT NULL CHECK (montant_avance > 0::numeric),
  retenue_mensuelle numeric NOT NULL CHECK (retenue_mensuelle > 0::numeric),
  date_octroi date NOT NULL DEFAULT CURRENT_DATE,
  date_debut_retenue date NOT NULL,
  nombre_traites_total integer NOT NULL,
  traites_payees integer NOT NULL DEFAULT 0,
  statut text NOT NULL DEFAULT 'en_cours'::text CHECK (statut = ANY (ARRAY['en_cours'::text, 'termine'::text, 'annule'::text])),
  motif text,
  notes text,
  created_by uuid,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT salary_advances_pkey PRIMARY KEY (id)
);
CREATE TABLE public.saved_exercises (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL,
  exercise_id uuid NOT NULL,
  created_at timestamp with time zone DEFAULT now(),
  CONSTRAINT saved_exercises_pkey PRIMARY KEY (id),
  CONSTRAINT saved_exercises_exercise_id_fkey FOREIGN KEY (exercise_id) REFERENCES public.exercises(id),
  CONSTRAINT saved_exercises_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id)
);
CREATE TABLE public.security_audit_log (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  user_id uuid,
  action text NOT NULL,
  table_accessed text NOT NULL,
  record_id uuid,
  access_granted boolean NOT NULL,
  reason text,
  ip_address inet,
  user_agent text,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT security_audit_log_pkey PRIMARY KEY (id),
  CONSTRAINT security_audit_log_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id)
);
CREATE TABLE public.segments (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  nom text NOT NULL UNIQUE,
  couleur text NOT NULL DEFAULT '#3B82F6'::text,
  logo_url text,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT segments_pkey PRIMARY KEY (id)
);
CREATE TABLE public.session_exercises (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  session_id uuid NOT NULL,
  exercise_id uuid NOT NULL,
  sets_completed integer DEFAULT 0,
  reps_completed integer,
  duration_completed_seconds integer,
  weight_used numeric,
  notes text,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT session_exercises_pkey PRIMARY KEY (id),
  CONSTRAINT session_exercises_exercise_id_fkey FOREIGN KEY (exercise_id) REFERENCES public.exercises(id),
  CONSTRAINT session_exercises_session_id_fkey FOREIGN KEY (session_id) REFERENCES public.sessions(id)
);
CREATE TABLE public.sessions (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL,
  program_day_id uuid,
  started_at timestamp with time zone NOT NULL DEFAULT now(),
  completed_at timestamp with time zone,
  notes text,
  rpe integer CHECK (rpe >= 1 AND rpe <= 10),
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT sessions_pkey PRIMARY KEY (id),
  CONSTRAINT sessions_program_day_id_fkey FOREIGN KEY (program_day_id) REFERENCES public.program_days(id),
  CONSTRAINT sessions_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id)
);
CREATE TABLE public.sessions_en_ligne (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  formation_id uuid NOT NULL,
  plateforme_id uuid NOT NULL,
  nom_session text NOT NULL,
  nombre_places integer NOT NULL DEFAULT 0,
  date_debut date NOT NULL,
  date_fin date NOT NULL,
  formateur text,
  url_session text,
  statut statut_classe NOT NULL DEFAULT 'programmee'::statut_classe,
  is_active boolean NOT NULL DEFAULT true,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT sessions_en_ligne_pkey PRIMARY KEY (id),
  CONSTRAINT sessions_en_ligne_formation_id_fkey FOREIGN KEY (formation_id) REFERENCES public.formations(id),
  CONSTRAINT sessions_en_ligne_plateforme_id_fkey FOREIGN KEY (plateforme_id) REFERENCES public.plateformes(id)
);
CREATE TABLE public.taches_projet (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  projet_id uuid NOT NULL,
  titre text NOT NULL,
  description text,
  assignee_id uuid,
  priorite priorite_tache NOT NULL DEFAULT 'normale'::priorite_tache,
  statut action_statut NOT NULL DEFAULT 'todo'::action_statut,
  date_debut date,
  date_fin_prevue date,
  date_fin_reelle date,
  estimation_heures numeric,
  heures_reelles numeric DEFAULT 0,
  progression_percent integer DEFAULT 0 CHECK (progression_percent >= 0 AND progression_percent <= 100),
  parent_tache_id uuid,
  created_by uuid NOT NULL,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT taches_projet_pkey PRIMARY KEY (id),
  CONSTRAINT taches_projet_parent_tache_id_fkey FOREIGN KEY (parent_tache_id) REFERENCES public.taches_projet(id),
  CONSTRAINT taches_projet_projet_id_fkey FOREIGN KEY (projet_id) REFERENCES public.projets(id)
);
CREATE TABLE public.templates_entretien (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  nom text NOT NULL,
  description text,
  questions jsonb NOT NULL DEFAULT '[]'::jsonb,
  criteres_evaluation jsonb DEFAULT '[]'::jsonb,
  duree_prevue integer DEFAULT 60,
  is_active boolean NOT NULL DEFAULT true,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT templates_entretien_pkey PRIMARY KEY (id)
);
CREATE TABLE public.templates_evaluation (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  nom text NOT NULL,
  description text,
  type_evaluation text NOT NULL DEFAULT 'annuelle'::text,
  criteres jsonb NOT NULL DEFAULT '[]'::jsonb,
  notation_max integer DEFAULT 5,
  is_active boolean NOT NULL DEFAULT true,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT templates_evaluation_pkey PRIMARY KEY (id)
);
CREATE TABLE public.user_profiles (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL UNIQUE,
  height numeric,
  weight numeric,
  body_shape text CHECK (body_shape = ANY (ARRAY['apple'::text, 'pear'::text, 'rectangle'::text])),
  fitness_level text CHECK (fitness_level = ANY (ARRAY['beginner'::text, 'intermediate'::text, 'advanced'::text])),
  goals ARRAY,
  created_at timestamp with time zone DEFAULT now(),
  updated_at timestamp with time zone DEFAULT now(),
  CONSTRAINT user_profiles_pkey PRIMARY KEY (id),
  CONSTRAINT user_profiles_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id)
);
CREATE TABLE public.user_roles (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL,
  role_id uuid NOT NULL,
  assigned_at timestamp with time zone NOT NULL DEFAULT now(),
  assigned_by uuid,
  is_active boolean DEFAULT true,
  created_at timestamp with time zone DEFAULT now(),
  updated_at timestamp with time zone DEFAULT now(),
  CONSTRAINT user_roles_pkey PRIMARY KEY (id),
  CONSTRAINT user_roles_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.roles(id)
);
CREATE TABLE public.ville_assignments (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL,
  ville_id uuid NOT NULL,
  assigned_by uuid NOT NULL,
  assigned_at timestamp with time zone NOT NULL DEFAULT now(),
  is_active boolean NOT NULL DEFAULT true,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT ville_assignments_pkey PRIMARY KEY (id),
  CONSTRAINT ville_assignments_ville_id_fkey FOREIGN KEY (ville_id) REFERENCES public.villes(id)
);
CREATE TABLE public.villes (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  nom_ville text NOT NULL,
  code_ville text NOT NULL UNIQUE,
  segment_id uuid NOT NULL,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT villes_pkey PRIMARY KEY (id),
  CONSTRAINT villes_segment_id_fkey FOREIGN KEY (segment_id) REFERENCES public.segments(id)
);
CREATE TABLE public.watch_later (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL,
  type USER-DEFINED NOT NULL,
  ref_id uuid NOT NULL,
  saved_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT watch_later_pkey PRIMARY KEY (id),
  CONSTRAINT watch_later_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id)
);
CREATE TABLE public.weight_entries (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL,
  weight numeric NOT NULL,
  recorded_at timestamp with time zone DEFAULT now(),
  created_at timestamp with time zone DEFAULT now(),
  CONSTRAINT weight_entries_pkey PRIMARY KEY (id),
  CONSTRAINT weight_entries_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id)
);
CREATE TABLE public.workflow_instances (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  workflow_id uuid NOT NULL,
  entite_id uuid NOT NULL,
  entite_type text NOT NULL,
  current_step integer NOT NULL DEFAULT 1,
  statut statut_workflow NOT NULL DEFAULT 'en_attente'::statut_workflow,
  initiated_by uuid NOT NULL,
  data_context jsonb DEFAULT '{}'::jsonb,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT workflow_instances_pkey PRIMARY KEY (id),
  CONSTRAINT workflow_instances_workflow_id_fkey FOREIGN KEY (workflow_id) REFERENCES public.workflows(id)
);
CREATE TABLE public.workflow_validations (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  instance_id uuid NOT NULL,
  step_number integer NOT NULL,
  validator_id uuid NOT NULL,
  statut statut_workflow NOT NULL DEFAULT 'en_attente'::statut_workflow,
  commentaire text,
  validated_at timestamp with time zone,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT workflow_validations_pkey PRIMARY KEY (id),
  CONSTRAINT workflow_validations_instance_id_fkey FOREIGN KEY (instance_id) REFERENCES public.workflow_instances(id)
);
CREATE TABLE public.workflows (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  nom text NOT NULL,
  description text,
  type_entite text NOT NULL,
  steps_config jsonb NOT NULL DEFAULT '[]'::jsonb,
  is_active boolean NOT NULL DEFAULT true,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT workflows_pkey PRIMARY KEY (id)
);