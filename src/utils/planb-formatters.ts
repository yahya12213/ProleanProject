/**
 * PLAN B - Utilitaires de formatage
 * Fonctions de formatage centralisées pour l'affichage des données
 */

// ===============================================
// FORMATAGE DES DATES
// ===============================================

export function formatDate(dateString: string | Date, options?: Intl.DateTimeFormatOptions): string {
  if (!dateString) return '';
  
  const date = typeof dateString === 'string' ? new Date(dateString) : dateString;
  
  if (isNaN(date.getTime())) return '';
  
  const defaultOptions: Intl.DateTimeFormatOptions = {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    ...options
  };
  
  return date.toLocaleDateString('fr-FR', defaultOptions);
}

export function formatDateShort(dateString: string | Date): string {
  return formatDate(dateString, {
    year: '2-digit',
    month: '2-digit',
    day: '2-digit'
  });
}

export function formatDateTime(dateString: string | Date): string {
  return formatDate(dateString, {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit'
  });
}

export function formatRelativeDate(dateString: string | Date): string {
  if (!dateString) return '';
  
  const date = typeof dateString === 'string' ? new Date(dateString) : dateString;
  const now = new Date();
  const diffInMs = now.getTime() - date.getTime();
  const diffInDays = Math.floor(diffInMs / (1000 * 60 * 60 * 24));
  
  if (diffInDays === 0) return "Aujourd'hui";
  if (diffInDays === 1) return "Hier";
  if (diffInDays === -1) return "Demain";
  if (diffInDays > 1 && diffInDays <= 7) return `Il y a ${diffInDays} jours`;
  if (diffInDays < -1 && diffInDays >= -7) return `Dans ${Math.abs(diffInDays)} jours`;
  
  return formatDate(dateString);
}

// ===============================================
// FORMATAGE DES MONTANTS
// ===============================================

export function formatCurrency(
  amount: number, 
  currency = 'DH', 
  locale = 'fr-FR'
): string {
  if (typeof amount !== 'number' || isNaN(amount)) return '0 ' + currency;
  
  const formatted = amount.toLocaleString(locale, {
    minimumFractionDigits: 0,
    maximumFractionDigits: 2
  });
  
  return `${formatted} ${currency}`;
}

export function formatCurrencyCompact(amount: number, currency = 'DH'): string {
  if (typeof amount !== 'number' || isNaN(amount)) return '0' + currency;
  
  if (amount >= 1000000) {
    return `${(amount / 1000000).toFixed(1)}M ${currency}`;
  }
  if (amount >= 1000) {
    return `${(amount / 1000).toFixed(1)}K ${currency}`;
  }
  
  return formatCurrency(amount, currency);
}

// ===============================================
// FORMATAGE DES TEXTES
// ===============================================

export function formatFullName(nom: string, prenom: string): string {
  if (!nom && !prenom) return '';
  if (!nom) return prenom;
  if (!prenom) return nom;
  return `${prenom} ${nom}`;
}

export function formatInitials(nom: string, prenom: string): string {
  const nomInitial = nom ? nom.charAt(0).toUpperCase() : '';
  const prenomInitial = prenom ? prenom.charAt(0).toUpperCase() : '';
  return nomInitial + prenomInitial;
}

export function formatPhoneNumber(phone: string): string {
  if (!phone) return '';
  
  // Nettoyer le numéro
  const cleanPhone = phone.replace(/[\s\-\.]/g, '');
  
  // Format marocain
  if (cleanPhone.startsWith('212')) {
    const number = cleanPhone.substring(3);
    return `+212 ${number.substring(0, 1)} ${number.substring(1, 3)} ${number.substring(3, 5)} ${number.substring(5, 7)} ${number.substring(7)}`;
  }
  
  if (cleanPhone.startsWith('0')) {
    return `${cleanPhone.substring(0, 4)} ${cleanPhone.substring(4, 6)} ${cleanPhone.substring(6, 8)} ${cleanPhone.substring(8)}`;
  }
  
  return phone;
}

export function formatCIN(cin: string): string {
  if (!cin) return '';
  return cin.toUpperCase();
}

export function truncateText(text: string, maxLength: number): string {
  if (!text || text.length <= maxLength) return text;
  return text.substring(0, maxLength) + '...';
}

// ===============================================
// FORMATAGE DES STATUTS
// ===============================================

export function formatStatutInscription(statut: string): string {
  const statuts = {
    'en_attente': 'En attente',
    'confirmee': 'Confirmée',
    'validee': 'Validée',
    'annulee': 'Annulée',
    'terminee': 'Terminée'
  };
  
  return statuts[statut as keyof typeof statuts] || statut;
}

export function formatStatutCompte(statut: string): string {
  const statuts = {
    'valide': 'Validé',
    'non_valide': 'Non validé',
    'en_cours': 'En cours',
    'suspendu': 'Suspendu'
  };
  
  return statuts[statut as keyof typeof statuts] || statut;
}

export function formatStatutClasse(statut: string): string {
  const statuts = {
    'programmee': 'Programmée',
    'en_cours': 'En cours',
    'terminee': 'Terminée',
    'annulee': 'Annulée'
  };
  
  return statuts[statut as keyof typeof statuts] || statut;
}

// ===============================================
// FORMATAGE DES LISTES
// ===============================================

export function formatList(items: string[], separator = ', ', lastSeparator = ' et '): string {
  if (!items || items.length === 0) return '';
  if (items.length === 1) return items[0];
  if (items.length === 2) return items.join(lastSeparator);
  
  const allButLast = items.slice(0, -1);
  const last = items[items.length - 1];
  
  return allButLast.join(separator) + lastSeparator + last;
}

// ===============================================
// FORMATAGE DES POURCENTAGES
// ===============================================

export function formatPercentage(value: number, decimals = 1): string {
  if (typeof value !== 'number' || isNaN(value)) return '0%';
  return `${value.toFixed(decimals)}%`;
}

export function calculatePercentage(part: number, total: number): number {
  if (total === 0) return 0;
  return (part / total) * 100;
}

// ===============================================
// FORMATAGE DES ADRESSES
// ===============================================

export function formatAddress(adresse?: string, ville?: string, codePostal?: string): string {
  const parts = [];
  
  if (adresse) parts.push(adresse);
  if (codePostal && ville) {
    parts.push(`${codePostal} ${ville}`);
  } else if (ville) {
    parts.push(ville);
  } else if (codePostal) {
    parts.push(codePostal);
  }
  
  return parts.join(', ');
}

// ===============================================
// VALIDATION ET NETTOYAGE
// ===============================================

export function sanitizeString(str: string): string {
  if (!str) return '';
  return str.trim().replace(/\s+/g, ' ');
}

export function normalizeString(str: string): string {
  return sanitizeString(str).toLowerCase();
}

export function capitalizeFirst(str: string): string {
  if (!str) return '';
  return str.charAt(0).toUpperCase() + str.slice(1).toLowerCase();
}

export function capitalizeWords(str: string): string {
  if (!str) return '';
  return str.split(' ').map(capitalizeFirst).join(' ');
}

// ===============================================
// GÉNÉRATION D'IDENTIFIANTS
// ===============================================

export function generateStudentDisplayId(studentId: string, year?: string): string {
  if (!studentId) return '';
  
  const currentYear = year || new Date().getFullYear().toString();
  
  if (studentId.startsWith('PLANB-')) {
    return studentId;
  }
  
  return `PLANB-${currentYear}-${studentId}`;
}

export function parseStudentId(studentId: string): { year: string; number: string } | null {
  if (!studentId) return null;
  
  const match = studentId.match(/^PLANB-(\d{4})-(\d+)$/);
  if (!match) return null;
  
  return {
    year: match[1],
    number: match[2]
  };
}

// ===============================================
// CALCULS FINANCIERS
// ===============================================

export function calculateResteDu(prixFormation: number, paiements: number, avance: number = 0): number {
  return Math.max(0, prixFormation - paiements - avance);
}

export function calculateTauxPaiement(paiements: number, prixFormation: number): number {
  if (prixFormation === 0) return 100;
  return Math.min(100, (paiements / prixFormation) * 100);
}

// ===============================================
// FORMATAGE D'EXPORT
// ===============================================

export function formatForExport(value: any): string {
  if (value === null || value === undefined) return '';
  if (typeof value === 'number') return value.toString();
  if (typeof value === 'boolean') return value ? 'Oui' : 'Non';
  if (value instanceof Date) return formatDate(value);
  return String(value);
}