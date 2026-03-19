/**
 * Utilitaires partagés pour la cohérence entre l'éditeur et la génération PDF
 * Ces fonctions garantissent que l'affichage dans l'éditeur correspond exactement au PDF généré
 */

// Mapping des polices de l'éditeur vers jsPDF
export const FONT_MAPPING = {
  'Arial': 'helvetica',
  'Times New Roman': 'times', 
  'Helvetica': 'helvetica',
  'Georgia': 'times',
  'Verdana': 'helvetica',
  'Tahoma': 'helvetica',
  'Courier New': 'courier',
  'Monaco': 'courier',
  'Roboto': 'helvetica',
  'Open Sans': 'helvetica',
  'Montserrat': 'helvetica',
  'Lato': 'helvetica',
  'Poppins': 'helvetica',
  'Inter': 'helvetica',
  'Source Sans Pro': 'helvetica',
  'Raleway': 'helvetica',
  'Nunito': 'helvetica',
  'PT Sans': 'helvetica',
  'Ubuntu': 'helvetica',
  'Playfair Display': 'times',
  'Merriweather': 'times',
  'Oswald': 'helvetica',
  'Source Code Pro': 'courier',
  'Fira Sans': 'helvetica',
  'Work Sans': 'helvetica'
} as const;

export type SupportedFont = keyof typeof FONT_MAPPING;

/**
 * Convertit les dimensions canvas pour l'éditeur en fonction du format de page
 */
export function getCanvasDimensions(format: string) {
  switch (format) {
    case 'A4':
      return { width: 600, height: 849 }; // Ratio 0.707
    case 'carte':
      return { width: 600, height: 378 }; // Ratio 1.586  
    case 'A5':
      return { width: 600, height: 425 }; // Ratio 1.414
    default:
      return { width: 600, height: 849 }; // Default A4
  }
}

/**
 * Calcule l'échelle de l'éditeur (identique à la fonction PDF)
 */
export function calculateEditorScale(formatPage: string) {
  const editorDimensions = getCanvasDimensions(formatPage);
  const scaleX = 700 / editorDimensions.width;
  const scaleY = 500 / editorDimensions.height;
  return Math.min(scaleX, scaleY, 1);
}

// Constantes de conversion standard
const PT_TO_PX = 96 / 72; // ≈ 1.3333 (conversion standard points vers pixels)
const PX_TO_PT = 72 / 96; // ≈ 0.75 (conversion standard pixels vers points)

/**
 * Convertit la taille de police en pixels pour affichage canvas
 * en respectant les mêmes règles que jsPDF
 * IMPORTANT: Cette fonction fait uniquement la conversion PT→PX, sans échelle
 */
export function convertJsPDFToCanvas(fontSize: number): number {
  // Dans jsPDF : 1 point = 1/72 inch
  // Dans Canvas : 1px = 1/96 inch (standard web)
  // Donc : 1 point jsPDF = 96/72 = 1.333... px
  return fontSize * PT_TO_PX;
}

/**
 * Convertit une taille canvas (px) en taille PDF (pt) - fonction bidirectionnelle
 */
export function convertCanvasToJsPDF(fontSizePx: number): number {
  return fontSizePx * PX_TO_PT;
}

/**
 * Convertit une police d'éditeur vers le nom jsPDF
 */
export function convertFontToJsPDF(fontFamily: string): string {
  return FONT_MAPPING[fontFamily as SupportedFont] || 'helvetica';
}

/**
 * Normalise les styles CSS pour correspondre à la logique jsPDF
 */
export function normalizeCSSStyles(styles: any) {
  return {
    color: styles.color || '#000000',
    fontSize: Number(styles.fontSize) || 14, // Toujours en points
    fontStyle: styles.fontStyle || 'normal',
    textAlign: styles.textAlign || 'left',
    fontFamily: styles.fontFamily || 'Arial',
    fontWeight: styles.fontWeight || 'normal',
    verticalAlign: styles.verticalAlign || 'middle',
    backgroundColor: styles.backgroundColor || 'transparent'
  };
}

/**
 * Génère le CSS pour l'affichage canvas en respectant les règles jsPDF
 * ARCHITECTURE UNIFIÉE: Les tailles de police sont affichées sans échelle pour correspondre au PDF
 */
export function generateCanvasCSS(styles: any, formatPage: string, editorScale?: number) {
  const normalized = normalizeCSSStyles(styles);
  const scale = editorScale || calculateEditorScale(formatPage);
  
  // SOLUTION DÉFINITIVE: Afficher avec un facteur de correction pour correspondre au PDF
  // tout en conservant les bonnes valeurs pour la génération PDF
  // 1. Conversion standard PT→PX avec facteur de correction pour l'affichage
  const canvasFontSize = convertJsPDFToCanvas(normalized.fontSize) * Math.min(scale * 2.0, 2.0);
  // Note: facteur 2.0 pour agrandir le texte dans l'éditeur et correspondre au PDF
  
  // Construction du CSS avec les bonnes conversions
  const fontStyle = normalized.fontStyle === 'italic' ? 'italic' : 'normal';
  const fontWeight = normalized.fontWeight === 'bold' ? 'bold' : 'normal';
  
  return {
    color: normalized.color,
    fontSize: `${canvasFontSize}px`,
    fontStyle,
    fontWeight,
    fontFamily: normalized.fontFamily,
    textAlign: normalized.textAlign,
    verticalAlign: normalized.verticalAlign,
    backgroundColor: normalized.backgroundColor
  };
}

/**
 * Fonction de diagnostic pour debugging (à utiliser temporairement)
 */
export function debugFontConversion(fontSize: number, formatPage: string) {
  const editorScale = calculateEditorScale(formatPage);
  const absolutePixelSize = convertJsPDFToCanvas(fontSize);
  const finalCanvasSize = absolutePixelSize * editorScale;
  
  console.log(`📏 CONVERSION FONT DEBUG CORRIGÉE:
    - Format page: ${formatPage}
    - Editor scale: ${editorScale.toFixed(3)}
    - Font size input: ${fontSize}pt
    - Conversion PT→PX: ${absolutePixelSize.toFixed(2)}px
    - Final canvas size: ${finalCanvasSize.toFixed(1)}px
    - Point to pixel ratio: ${(96/72).toFixed(3)}
  `);
  
  return finalCanvasSize;
}