/**
 * Utilitaires pour la migration des tailles de police
 * Conversion des anciennes valeurs en pixels vers les nouvelles valeurs en points
 */

export interface BlocStyles {
  fontSize?: string | number;
  fontFamily?: string;
  color?: string;
  fontWeight?: string;
  fontStyle?: string;
  textAlign?: string;
  [key: string]: any;
}

/**
 * Détecte si une valeur fontSize est en pixels ou en points
 */
export function detectFontSizeUnit(fontSize: string | number): 'px' | 'pt' | 'unknown' {
  if (typeof fontSize === 'number') {
    // Si c'est un nombre sans unité, on assume que c'est en pixels (ancien système)
    return 'px';
  }
  
  if (typeof fontSize === 'string') {
    if (fontSize.endsWith('px')) return 'px';
    if (fontSize.endsWith('pt')) return 'pt';
    if (!isNaN(Number(fontSize))) return 'px'; // Nombre en string = pixels
  }
  
  return 'unknown';
}

/**
 * Convertit une taille de police en pixels vers des points
 * 1px = 0.75pt (approximation CSS standard)
 */
export function convertPixelsToPoints(pixelValue: number): number {
  return Math.round(pixelValue * 0.75);
}

/**
 * Normalise une valeur fontSize pour qu'elle soit toujours en points
 */
export function normalizeFontSizeToPoints(fontSize: string | number): number {
  if (typeof fontSize === 'number') {
    // Nombre sans unité = pixels dans l'ancien système
    return convertPixelsToPoints(fontSize);
  }
  
  if (typeof fontSize === 'string') {
    const unit = detectFontSizeUnit(fontSize);
    const numValue = parseFloat(fontSize);
    
    switch (unit) {
      case 'px':
        return convertPixelsToPoints(numValue);
      case 'pt':
        return Math.round(numValue);
      default:
        // Fallback: traiter comme pixels
        return convertPixelsToPoints(numValue || 12);
    }
  }
  
  // Fallback par défaut
  return 12;
}

/**
 * Migre les styles CSS d'un bloc pour normaliser fontSize en points
 */
export function migrateBlockStyles(cssStyles: any): any {
  if (!cssStyles || typeof cssStyles !== 'object') {
    return cssStyles;
  }
  
  const styles = { ...cssStyles };
  
  if (styles.fontSize) {
    const normalizedFontSize = normalizeFontSizeToPoints(styles.fontSize);
    styles.fontSize = normalizedFontSize; // Stocké en nombre (points)
    
    console.log(`Migration fontSize: ${cssStyles.fontSize} → ${normalizedFontSize}pt`);
  }
  
  return styles;
}

/**
 * Valide qu'un bloc a des styles correctement migrés
 */
export function validateBlockStyles(cssStyles: any): { isValid: boolean; issues: string[] } {
  const issues: string[] = [];
  
  if (!cssStyles) {
    issues.push('cssStyles is null or undefined');
    return { isValid: false, issues };
  }
  
  if (cssStyles.fontSize) {
    const unit = detectFontSizeUnit(cssStyles.fontSize);
    if (unit === 'px') {
      issues.push(`fontSize still in pixels: ${cssStyles.fontSize}`);
    } else if (unit === 'unknown') {
      issues.push(`fontSize has unknown format: ${cssStyles.fontSize}`);
    } else if (typeof cssStyles.fontSize !== 'number') {
      issues.push(`fontSize should be stored as number (points): ${cssStyles.fontSize}`);
    }
  }
  
  return {
    isValid: issues.length === 0,
    issues
  };
}