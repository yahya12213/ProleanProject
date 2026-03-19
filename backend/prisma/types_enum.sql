-- Fichier isolé pour les types ENUM
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
