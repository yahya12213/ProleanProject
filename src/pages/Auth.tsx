import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useToast } from "@/hooks/use-toast";
// ...existing code...
// ...existing code...
import { isStrongPassword, getPasswordStrengthMessage, isPwned } from "@/utils/password-security";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Shield, AlertTriangle } from "lucide-react";

const Auth = () => {
  const [isLogin, setIsLogin] = useState(true);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  type AuthUser = { email?: string; token?: string } | null;
  const [user, setUser] = useState<AuthUser>(null);
  const [passwordStrength, setPasswordStrength] = useState("");
  const [passwordCompromised, setPasswordCompromised] = useState(false);
  const [checkingPwned, setCheckingPwned] = useState(false);
  const navigate = useNavigate();
  const { toast } = useToast();

  useEffect(() => {
    // Vérifie si un token existe déjà (utilisateur connecté)
    const token = localStorage.getItem('authToken');
    if (token) {
      // Optionnel : récupérer le profil utilisateur via l'API
      setUser({ token });
      navigate('/dashboard');
    }
  }, [navigate]);

  // Validation du mot de passe en temps réel pour l'inscription
  useEffect(() => {
    if (!isLogin && password) {
      setPasswordStrength(getPasswordStrengthMessage(password));
      
      // Vérifier si le mot de passe est compromis (avec debounce)
      const checkPwned = async () => {
        if (isStrongPassword(password)) {
          setCheckingPwned(true);
          const compromised = await isPwned(password);
          setPasswordCompromised(compromised);
          setCheckingPwned(false);
        } else {
          setPasswordCompromised(false);
        }
      };
      
      const timeoutId = setTimeout(checkPwned, 500); // Debounce de 500ms
      return () => clearTimeout(timeoutId);
    } else {
      setPasswordStrength("");
      setPasswordCompromised(false);
    }
  }, [password, isLogin]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);

    try {
      // Validation supplémentaire pour l'inscription
      if (!isLogin) {
        if (!isStrongPassword(password)) {
          toast({
            title: "Mot de passe trop faible",
            description: getPasswordStrengthMessage(password),
            variant: "destructive",
          });
          setLoading(false);
          return;
        }
        
        if (passwordCompromised) {
          toast({
            title: "Mot de passe compromis",
            description: "Ce mot de passe a été trouvé dans des fuites de données. Veuillez en choisir un autre.",
            variant: "destructive",
          });
          setLoading(false);
          return;
        }
      }

      if (isLogin) {
        // Appel à l'API Express pour la connexion
        const response = await import('@/services/api').then(api => api.login(email, password));
        if (response.data && response.data.token) {
          localStorage.setItem('authToken', response.data.token);
          setUser({ email });
          toast({
            title: "Connexion réussie",
            description: "Vous êtes maintenant connecté.",
          });
          navigate('/dashboard');
        } else {
          throw new Error(response.data?.message || 'Erreur de connexion');
        }
      } else {
        // Appel à l'API Express pour l'inscription
        const response = await import('@/services/api').then(api => api.register(email, password));
        if (response.data && response.data.success) {
          toast({
            title: "Inscription réussie",
            description: "Votre compte a été créé. Vous pouvez maintenant vous connecter.",
          });
          setIsLogin(true);
        } else {
          throw new Error(response.data?.message || 'Erreur lors de l’inscription');
        }
      }
  } catch (error) {
      toast({
        title: "Erreur",
        description: error.message || "Une erreur est survenue",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-background flex items-center justify-center p-4">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <CardTitle className="text-2xl font-heading">
            {isLogin ? "Connexion" : "Inscription"}
          </CardTitle>
          <CardDescription>
            {isLogin 
              ? "Connectez-vous à votre compte PROLEAN" 
              : "Créez votre compte PROLEAN"
            }
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <Input
                id="email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                placeholder="votre@email.com"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="password">Mot de passe</Label>
              <Input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                placeholder="••••••••"
              />
              
              {/* Indicateurs de sécurité pour l'inscription */}
              {!isLogin && password && (
                <div className="space-y-2">
                  <div className="text-sm">
                    <span className={`flex items-center gap-1 ${
                      isStrongPassword(password) ? 'text-green-600' : 'text-orange-600'
                    }`}>
                      <Shield className="w-3 h-3" />
                      {passwordStrength}
                    </span>
                  </div>
                  
                  {isStrongPassword(password) && (
                    <div className="text-sm">
                      {checkingPwned ? (
                        <span className="text-muted-foreground">Vérification de sécurité...</span>
                      ) : passwordCompromised ? (
                        <Alert variant="destructive" className="p-2">
                          <AlertTriangle className="w-3 h-3" />
                          <AlertDescription className="text-xs">
                            Mot de passe compromis dans des fuites de données
                          </AlertDescription>
                        </Alert>
                      ) : (
                        <span className="text-green-600 text-xs">✓ Mot de passe sécurisé</span>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
            <Button 
              type="submit" 
              className="w-full" 
              disabled={loading || (!isLogin && (!isStrongPassword(password) || passwordCompromised || checkingPwned))}
            >
              {loading 
                ? (isLogin ? "Connexion..." : "Inscription...") 
                : (isLogin ? "Se connecter" : "S'inscrire")
              }
            </Button>
          </form>
          <div className="mt-4 text-center">
            <Button
              variant="link"
              onClick={() => setIsLogin(!isLogin)}
              className="text-sm"
            >
              {isLogin 
                ? "Pas de compte ? Inscrivez-vous" 
                : "Déjà un compte ? Connectez-vous"
              }
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default Auth;