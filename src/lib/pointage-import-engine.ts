/**
 * Moteur d'importation robuste pour les pointages
 * Gère l'injection, la validation et la transformation des données
 */

export interface RawPointageData {
  [key: string]: string;
}

export interface ParsedPointageData {
  date: string;
  heure: string;
  type: string;
  lieu?: string;
  notes?: string;
  isValid: boolean;
  errors: string[];
  warnings: string[];
  originalIndex: number;
}

export interface ImportResult {
  totalLines: number;
  validEntries: ParsedPointageData[];
  invalidEntries: ParsedPointageData[];
  warnings: string[];
  errors: string[];
  metadata: {
    parsedAt: Date;
    processingTime: number;
  };
}

/**
 * Parser robuste qui ne perd jamais de données
 */
export function parseRawDataRobust(text: string): RawPointageData[] {
  console.log('🚀 IMPORT ENGINE: Début du parsing robuste');
  const startTime = Date.now();
  
  try {
    const lines = text.trim().split('\n').filter(line => line.trim().length > 0);
    console.log(`📊 IMPORT ENGINE: ${lines.length} lignes à traiter`);
    
    if (lines.length === 0) {
      console.warn('⚠️ IMPORT ENGINE: Aucune ligne à traiter');
      return [];
    }
    
    // Détection intelligente des headers vs données
    const firstLine = lines[0];
    const firstLineValues = firstLine.split('\t').map(v => v.trim());
    
    // Si la première ligne contient des dates/heures, c'est des données, pas des headers
    const containsDateTimeData = firstLineValues.some(value => {
      return /^\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{4}$/.test(value) || // Format date
             /^\d{1,2}:\d{2}(:\d{2})?$/.test(value); // Format heure
    });
    
    let headers: string[];
    let dataStartIndex: number;
    
    if (containsDateTimeData) {
      // Pas de ligne d'en-tête, utiliser des headers par défaut
      console.log('📋 IMPORT ENGINE: Données détectées dès la première ligne, utilisation headers par défaut');
      headers = ['date', 'heure', 'type', 'lieu', 'notes'];
      dataStartIndex = 0;
    } else {
      // Première ligne = headers
      headers = firstLineValues.map(h => h.trim().toLowerCase());
      console.log('📋 IMPORT ENGINE: Headers détectés:', headers);
      dataStartIndex = 1;
      
      if (lines.length < 2) {
        console.warn('⚠️ IMPORT ENGINE: Pas de données après les headers');
        return [];
      }
    }
    
    // Mapping des headers pour normalisation
    const headerMapping: { [key: string]: string } = {
      'date': 'date',
      'heure': 'heure', 
      'time': 'heure',
      'type': 'type',
      'lieu': 'lieu',
      'location': 'lieu',
      'notes': 'notes',
      'note': 'notes',
      'commentaire': 'notes',
      'comment': 'notes'
    };
    
    const normalizedHeaders = headers.map(h => headerMapping[h] || h);
    console.log('🔄 IMPORT ENGINE: Headers normalisés:', normalizedHeaders);
    
    // Traitement ligne par ligne avec gestion d'erreur individuelle
    const data: RawPointageData[] = [];
    
    for (let i = dataStartIndex; i < lines.length; i++) {
      try {
        const line = lines[i];
        const lineNumber = i + 1;
        
        console.log(`📝 IMPORT ENGINE: Traitement ligne ${lineNumber}: "${line}"`);
        
        if (!line.trim()) {
          console.log(`⏭️ IMPORT ENGINE: Ligne ${lineNumber} vide, ignorée`);
          continue;
        }
        
        const values = line.split('\t').map(v => v.trim());
        console.log(`📊 IMPORT ENGINE: Ligne ${lineNumber} - ${values.length} valeurs:`, values);
        
        const obj: RawPointageData = { originalIndex: i.toString() };
        
        normalizedHeaders.forEach((header, j) => {
          const value = values[j] || '';
          obj[header] = value;
          console.log(`  ${header}: "${value}"`);
        });
        
        data.push(obj);
        console.log(`✅ IMPORT ENGINE: Ligne ${lineNumber} ajoutée:`, obj);
        
      } catch (lineError) {
        console.error(`💥 IMPORT ENGINE: Erreur ligne ${i + 1}:`, lineError);
        // Continue le traitement même en cas d'erreur sur une ligne
        data.push({
          originalIndex: i.toString(),
          date: '',
          heure: '',
          type: '',
          error: `Erreur de parsing: ${lineError}`
        });
      }
    }
    
    const processingTime = Date.now() - startTime;
    console.log(`🎯 IMPORT ENGINE: Parsing terminé en ${processingTime}ms, ${data.length} entrées créées`);
    
    return data;
    
  } catch (error) {
    console.error('💥 IMPORT ENGINE: Erreur critique de parsing:', error);
    throw new Error(`Erreur de parsing: ${error}`);
  }
}

/**
 * Validation tolérante avec correction automatique
 */
export function validateDataTolerant(rawData: RawPointageData[]): ParsedPointageData[] {
  console.log('🔍 VALIDATION ENGINE: Début validation tolérante');
  
  return rawData.map((item, index) => {
    const result: ParsedPointageData = {
      date: '',
      heure: '',
      type: '',
      lieu: item.lieu || '',
      notes: item.notes || '',
      isValid: true,
      errors: [],
      warnings: [],
      originalIndex: parseInt(item.originalIndex) || index
    };
    
    try {
      // Validation et correction de la date
      const dateResult = sanitizeDateFormat(item.date || '');
      result.date = dateResult.corrected;
      if (dateResult.warnings.length > 0) {
        result.warnings.push(...dateResult.warnings);
      }
      if (dateResult.errors.length > 0) {
        result.errors.push(...dateResult.errors);
        result.isValid = false;
      }
      
      // Validation et correction de l'heure
      const timeResult = sanitizeTimeFormat(item.heure || '');
      result.heure = timeResult.corrected;
      if (timeResult.warnings.length > 0) {
        result.warnings.push(...timeResult.warnings);
      }
      if (timeResult.errors.length > 0) {
        result.errors.push(...timeResult.errors);
        result.isValid = false;
      }
      
      // Validation du type
      const typeResult = sanitizeTypeFormat(item.type || '');
      result.type = typeResult.corrected;
      if (typeResult.warnings.length > 0) {
        result.warnings.push(...typeResult.warnings);
      }
      if (typeResult.errors.length > 0) {
        result.errors.push(...typeResult.errors);
        result.isValid = false;
      }
      
      console.log(`✅ VALIDATION: Ligne ${result.originalIndex + 1} - Valid: ${result.isValid}`, {
        date: result.date,
        heure: result.heure,
        type: result.type,
        errors: result.errors,
        warnings: result.warnings
      });
      
    } catch (error) {
      console.error(`💥 VALIDATION: Erreur ligne ${result.originalIndex + 1}:`, error);
      result.errors.push(`Erreur de validation: ${error}`);
      result.isValid = false;
    }
    
    return result;
  });
}

/**
 * Normalisation robuste des formats de date
 */
export function sanitizeDateFormat(dateStr: string): { corrected: string; warnings: string[]; errors: string[] } {
  const warnings: string[] = [];
  const errors: string[] = [];
  
  if (!dateStr || dateStr.trim() === '') {
    errors.push('Date manquante');
    return { corrected: '', warnings, errors };
  }
  
  let cleaned = dateStr.trim();
  
  // Formats supportés: DD/MM/YYYY, DD-MM-YYYY, YYYY-MM-DD, DD.MM.YYYY
  const patterns = [
    /^(\d{1,2})[\/\-\.](\d{1,2})[\/\-\.](\d{4})$/,  // DD/MM/YYYY
    /^(\d{4})[\/\-\.](\d{1,2})[\/\-\.](\d{1,2})$/,  // YYYY-MM-DD
  ];
  
  for (const pattern of patterns) {
    const match = cleaned.match(pattern);
    if (match) {
      const [, part1, part2, part3] = match;
      
      // Déterminer le format et convertir en DD/MM/YYYY
      let day, month, year;
      
      if (part3.length === 4) {
        // Format DD/MM/YYYY ou DD-MM-YYYY
        day = part1.padStart(2, '0');
        month = part2.padStart(2, '0');
        year = part3;
      } else {
        // Format YYYY-MM-DD
        year = part1;
        month = part2.padStart(2, '0');
        day = part3.padStart(2, '0');
      }
      
      // Validation des valeurs
      const dayNum = parseInt(day);
      const monthNum = parseInt(month);
      const yearNum = parseInt(year);
      
      if (dayNum < 1 || dayNum > 31) {
        errors.push(`Jour invalide: ${dayNum}`);
        return { corrected: cleaned, warnings, errors };
      }
      
      if (monthNum < 1 || monthNum > 12) {
        errors.push(`Mois invalide: ${monthNum}`);
        return { corrected: cleaned, warnings, errors };
      }
      
      if (yearNum < 2020 || yearNum > 2030) {
        warnings.push(`Année suspecte: ${yearNum}`);
      }
      
      // CORRECTION: Valider la date en utilisant UTC pour éviter les décalages de fuseau horaire
      const testDate = new Date(Date.UTC(yearNum, monthNum - 1, dayNum, 12, 0, 0));
      if (testDate.getUTCFullYear() !== yearNum || testDate.getUTCMonth() !== monthNum - 1 || testDate.getUTCDate() !== dayNum) {
        errors.push(`Date invalide: ${day}/${month}/${year}`);
        return { corrected: cleaned, warnings, errors };
      }
      
      const corrected = `${day}/${month}/${year}`;
      if (corrected !== cleaned) {
        warnings.push(`Format de date corrigé de "${cleaned}" vers "${corrected}"`);
      }
      
      return { corrected, warnings, errors };
    }
  }
  
  errors.push(`Format de date non reconnu: "${cleaned}"`);
  return { corrected: cleaned, warnings, errors };
}

/**
 * Normalisation robuste des formats d'heure
 */
export function sanitizeTimeFormat(timeStr: string): { corrected: string; warnings: string[]; errors: string[] } {
  const warnings: string[] = [];
  const errors: string[] = [];
  
  if (!timeStr || timeStr.trim() === '') {
    errors.push('Heure manquante');
    return { corrected: '', warnings, errors };
  }
  
  let cleaned = timeStr.trim().replace(/\s+/g, '');
  
  // Formats supportés: HH:MM, HH.MM, HHMM, H:MM, H.MM
  const patterns = [
    /^(\d{1,2})[:.](\d{2})$/,  // HH:MM ou HH.MM
    /^(\d{4})$/,              // HHMM
    /^(\d{1,2})$/,            // HH (ajout de :00)
  ];
  
  for (const pattern of patterns) {
    const match = cleaned.match(pattern);
    if (match) {
      let hours, minutes;
      
      if (match[0].length === 4 && !match[0].includes(':') && !match[0].includes('.')) {
        // Format HHMM
        hours = match[1].substring(0, 2);
        minutes = match[1].substring(2, 4);
      } else if (match[2] === undefined) {
        // Format HH seulement
        hours = match[1].padStart(2, '0');
        minutes = '00';
      } else {
        // Format HH:MM ou HH.MM
        hours = match[1].padStart(2, '0');
        minutes = match[2];
      }
      
      const hoursNum = parseInt(hours);
      const minutesNum = parseInt(minutes);
      
      if (hoursNum < 0 || hoursNum > 23) {
        errors.push(`Heure invalide: ${hoursNum}`);
        return { corrected: cleaned, warnings, errors };
      }
      
      if (minutesNum < 0 || minutesNum > 59) {
        errors.push(`Minutes invalides: ${minutesNum}`);
        return { corrected: cleaned, warnings, errors };
      }
      
      const corrected = `${hours}:${minutes}`;
      if (corrected !== cleaned) {
        warnings.push(`Format d'heure corrigé de "${cleaned}" vers "${corrected}"`);
      }
      
      return { corrected, warnings, errors };
    }
  }
  
  errors.push(`Format d'heure non reconnu: "${cleaned}"`);
  return { corrected: cleaned, warnings, errors };
}

/**
 * Normalisation des types de pointage
 */
export function sanitizeTypeFormat(typeStr: string): { corrected: string; warnings: string[]; errors: string[] } {
  const warnings: string[] = [];
  const errors: string[] = [];
  
  if (!typeStr || typeStr.trim() === '') {
    errors.push('Type manquant');
    return { corrected: '', warnings, errors };
  }
  
  const cleaned = typeStr.trim().toLowerCase();
  
  // Mapping des types avec variations acceptées
  const typeMapping: { [key: string]: string } = {
    'entree': 'entree',
    'entrée': 'entree',
    'entry': 'entree',
    'in': 'entree',
    'debut': 'entree',
    'début': 'entree',
    'sortie': 'sortie',
    'exit': 'sortie',
    'out': 'sortie',
    'fin': 'sortie',
    'pause': 'pause',
    'break': 'pause',
    'reprise': 'reprise',
    'resume': 'reprise',
    'retour': 'reprise'
  };
  
  const mapped = typeMapping[cleaned];
  if (mapped) {
    if (mapped !== cleaned) {
      warnings.push(`Type corrigé de "${typeStr}" vers "${mapped}"`);
    }
    return { corrected: mapped, warnings, errors };
  }
  
  errors.push(`Type non reconnu: "${typeStr}"`);
  return { corrected: cleaned, warnings, errors };
}

/**
 * Fonction principale d'importation
 */
export function processPointageImport(text: string): ImportResult {
  const startTime = Date.now();
  
  try {
    console.log('🚀 IMPORT: Début du processus d\'importation');
    
    // Phase 1: Parsing robuste
    const rawData = parseRawDataRobust(text);
    
    // Phase 2: Validation tolérante
    const validatedData = validateDataTolerant(rawData);
    
    // Phase 3: Séparation des données valides et invalides
    const validEntries = validatedData.filter(item => item.isValid);
    const invalidEntries = validatedData.filter(item => !item.isValid);
    
    // Phase 4: Compilation des warnings et erreurs globales
    const warnings: string[] = [];
    const errors: string[] = [];
    
    validatedData.forEach(item => {
      warnings.push(...item.warnings);
      errors.push(...item.errors);
    });
    
    const processingTime = Date.now() - startTime;
    
    const result: ImportResult = {
      totalLines: rawData.length,
      validEntries,
      invalidEntries,
      warnings: [...new Set(warnings)], // Déduplication
      errors: [...new Set(errors)],     // Déduplication
      metadata: {
        parsedAt: new Date(),
        processingTime
      }
    };
    
    console.log('✅ IMPORT: Processus terminé', {
      totalLines: result.totalLines,
      validEntries: result.validEntries.length,
      invalidEntries: result.invalidEntries.length,
      processingTime: result.metadata.processingTime
    });
    
    return result;
    
  } catch (error) {
    console.error('💥 IMPORT: Erreur critique:', error);
    throw error;
  }
}