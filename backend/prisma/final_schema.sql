-- Fichier final combinant les types ENUM, les tables et les contraintes

-- Types ENUM
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
END $$;

-- Tables
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

-- Contraintes et relations
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'profiles') THEN
        ALTER TABLE public.demandes_rh
        ADD CONSTRAINT demandes_rh_profile_id_fkey FOREIGN KEY (id) REFERENCES public.profiles(id);
    END IF;

    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'user_profiles') THEN
        ALTER TABLE public.user_profiles
        ADD CONSTRAINT user_profiles_goals_check CHECK (array_length(goals, 1) > 0);
    END IF;
END $$;
