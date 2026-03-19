-- Fichier isolé pour les définitions des tables
CREATE TABLE IF NOT EXISTS public.profiles (
    id uuid PRIMARY KEY,
    name text NOT NULL
);

CREATE TABLE IF NOT EXISTS public.demandes_rh (
    id uuid PRIMARY KEY,
    type_demande statut_demande_rh NOT NULL
);

CREATE TABLE IF NOT EXISTS public.exercises (
    id uuid PRIMARY KEY,
    category text NOT NULL
);

CREATE TABLE IF NOT EXISTS public.fitshape_profiles (
    id uuid PRIMARY KEY,
    sex text NOT NULL
);

CREATE TABLE IF NOT EXISTS public.user_profiles (
    id uuid PRIMARY KEY,
    goals text[]
);
