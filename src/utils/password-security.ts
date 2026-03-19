// Utilitaires de sécurité pour les mots de passe

/**
 * Convertit un string en hash SHA-1
 */
async function sha1Hash(password: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hashBuffer = await crypto.subtle.digest('SHA-1', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Vérifie si un mot de passe respecte les critères de sécurité
 */
export function isStrongPassword(password: string): boolean {
  const hasUpperCase = /[A-Z]/.test(password);
  const hasLowerCase = /[a-z]/.test(password);
  const hasNumbers = /\d/.test(password);
  const hasSpecialChar = /[@$!%*?&#]/.test(password);
  const hasMinLength = password.length >= 8;
  
  return hasUpperCase && hasLowerCase && hasNumbers && hasSpecialChar && hasMinLength;
}

/**
 * Retourne un message descriptif des critères manquants
 */
export function getPasswordStrengthMessage(password: string): string {
  const missing: string[] = [];
  
  if (password.length < 8) missing.push("8 caractères minimum");
  if (!/[A-Z]/.test(password)) missing.push("une majuscule");
  if (!/[a-z]/.test(password)) missing.push("une minuscule");
  if (!/\d/.test(password)) missing.push("un chiffre");
  if (!/[@$!%*?&#]/.test(password)) missing.push("un caractère spécial (@$!%*?&#)");
  
  if (missing.length === 0) return "Mot de passe fort ✓";
  return `Manque: ${missing.join(", ")}`;
}

/**
 * Vérifie si un mot de passe a été compromis via l'API HaveIBeenPwned
 */
export async function isPwned(password: string): Promise<boolean> {
  try {
    const sha1 = await sha1Hash(password);
    const prefix = sha1.slice(0, 5);
    const suffix = sha1.slice(5).toUpperCase();
    
    const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
    
    if (!response.ok) {
      console.warn('Impossible de vérifier le mot de passe avec HaveIBeenPwned');
      return false; // En cas d'erreur, on n'empêche pas l'inscription
    }
    
    const data = await response.text();
    return data.includes(suffix);
  } catch (error) {
    console.warn('Erreur lors de la vérification HaveIBeenPwned:', error);
    return false; // En cas d'erreur, on n'empêche pas l'inscription
  }
}