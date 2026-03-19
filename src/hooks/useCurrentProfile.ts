
import { useQuery } from "@tanstack/react-query";

export function useCurrentProfile() {
  return useQuery({
    queryKey: ["current-profile"],
    queryFn: async () => {
      // TODO: Remplacer par appel à l'API Express locale
      try {
        // Pour l'instant, retournons un profil par défaut
        return {
          id: "1",
          user_id: "1",
          name: "Utilisateur par défaut",
          email: "user@example.com"
        };
      } catch (error) {
        console.error("Erreur lors de la récupération du profil:", error);
        return null;
      }
    },
    retry: false, // Ne pas réessayer automatiquement
  });
}
