import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
// ...existing code...
// Supabase supprimé, toute la logique doit passer par l'API Express locale
import { useToast } from "@/hooks/use-toast";

interface ProtectedRouteProps {
  children: React.ReactNode;
}

const ProtectedRoute = ({ children }: ProtectedRouteProps) => {
  const [user, setUser] = useState<User | null>(null);
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(true);
  const [profileReady, setProfileReady] = useState(false);
  const navigate = useNavigate();
  const { toast } = useToast();

  useEffect(() => {
    const subscription = (event, session) => {
      setSession(session);
      setUser(session?.user ?? null);

      if (!session?.user) {
        setLoading(false);
        setProfileReady(false);
        navigate('/auth');
        return;
      }

      if (!session.user.email_confirmed_at) {
        setLoading(false);
        setProfileReady(false);
        toast({
          title: "Confirmation requise",
          description: "Veuillez confirmer votre email avant d'accéder à l'application.",
          variant: "destructive",
        });
        navigate('/auth');
        return;
      }

      // Délai pour éviter les appels récursifs
      setTimeout(async () => {
        try {
          // Assurer que le profil existe
          // TODO: Remplacer par appel à l'API Express locale
          if (error) {
            console.error('Erreur profil:', error);
            toast({
              title: "Erreur de profil",
              description: "Problème de synchronisation. Reconnectez-vous.",
              variant: "destructive",
            });
            setLoading(false);
            setProfileReady(false);
            navigate('/auth');
            return;
          }
          
          if (data && typeof data === 'object' && 'success' in data && data.success) {
            setProfileReady(true);
          } else if (data && typeof data === 'object' && 'error' in data) {
            console.error('Erreur profil:', data.error);
            toast({
              title: "Erreur de profil",
              description: "Impossible de créer votre profil. Reconnectez-vous.",
              variant: "destructive",
            });
            setLoading(false);
            setProfileReady(false);
            navigate('/auth');
            return;
          }
        } catch (error) {
          console.error('Exception profil:', error);
          toast({
            title: "Erreur système",
            description: "Une erreur inattendue s'est produite. Reconnectez-vous.",
            variant: "destructive",
          });
          setProfileReady(false);
          navigate('/auth');
        } finally {
          setLoading(false);
        }
      }, 100);
    };

    return () => subscription.unsubscribe();
  }, [navigate, toast]);

  if (loading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary mx-auto"></div>
          <p className="mt-2 text-muted-foreground">
            {user ? "Vérification du profil..." : "Chargement..."}
          </p>
        </div>
      </div>
    );
  }

  if (!user || !session || !profileReady) {
    return null;
  }

  return <>{children}</>;
};

export default ProtectedRoute;