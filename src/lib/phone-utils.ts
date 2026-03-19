import { isValidPhoneNumber, parsePhoneNumber } from 'react-phone-number-input';

/**
 * Nettoie un numéro de téléphone en supprimant les espaces, tirets et autres caractères
 */
export const cleanPhoneNumber = (phone: string): string => {
  return phone.replace(/[^\d+]/g, '');
};

/**
 * Traitement intelligent d'un numéro de téléphone collé depuis WhatsApp
 */
export const smartPhoneProcessor = (input: string): string => {
  if (!input) return '';
  
  // 1. Nettoyer le numéro (garder seulement les chiffres et le +)
  const cleaned = input.replace(/[^\d+]/g, '');
  
  // 2. Si le numéro commence par un indicatif international, le garder
  if (cleaned.startsWith('+')) {
    return cleaned;
  }
  
  // 3. Détecter si c'est un numéro marocain (tous les préfixes: 05, 06, 07, 08, 076, etc.)
  if (cleaned.match(/^0(5|6|7|8|76)\d+$/)) {
    // Remplacer le 0 initial par +212
    return `+212${cleaned.substring(1)}`;
  }
  
  // 4. Si le numéro commence par 212 sans +, ajouter le +
  if (cleaned.startsWith('212') && cleaned.length >= 12) {
    return `+${cleaned}`;
  }
  
  // 5. Retourner tel quel si format non reconnu
  return cleaned;
};

/**
 * Auto-détection et formatage d'un numéro de téléphone
 */
export const autoDetectAndFormat = (input: string): { 
  formatted: string; 
  isValid: boolean; 
  country?: string;
} => {
  if (!input) return { formatted: '', isValid: false };
  
  try {
    const processed = smartPhoneProcessor(input);
    const phoneNumber = parsePhoneNumber(processed);
    
    if (phoneNumber && phoneNumber.isValid()) {
      return {
        formatted: phoneNumber.number,
        isValid: true,
        country: phoneNumber.country
      };
    }
    
    return { formatted: processed, isValid: false };
  } catch {
    return { formatted: input, isValid: false };
  }
};

/**
 * Valide un numéro de téléphone international
 */
export const validatePhoneNumber = (phone: string): boolean => {
  if (!phone) return false;
  
  try {
    return isValidPhoneNumber(phone);
  } catch {
    return false;
  }
};

/**
 * Formate un numéro de téléphone pour l'affichage
 */
export const formatPhoneNumber = (phone: string): string => {
  if (!phone) return '';
  
  try {
    const phoneNumber = parsePhoneNumber(phone);
    return phoneNumber?.formatInternational() || phone;
  } catch {
    return phone;
  }
};

/**
 * Normalise un numéro de téléphone pour la base de données
 */
export const normalizePhoneNumber = (phone: string): string => {
  if (!phone) return '';
  
  try {
    const result = autoDetectAndFormat(phone);
    return result.formatted;
  } catch {
    return cleanPhoneNumber(phone);
  }
};

/**
 * Détecte si un numéro est marocain
 */
export const isMoroccanNumber = (phone: string): boolean => {
  if (!phone) return false;
  
  try {
    const phoneNumber = parsePhoneNumber(phone);
    return phoneNumber?.country === 'MA';
  } catch {
    return false;
  }
};