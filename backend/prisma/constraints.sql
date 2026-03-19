-- Fichier isolé pour les contraintes et relations
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
