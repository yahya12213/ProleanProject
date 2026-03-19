import { useState, useRef } from "react";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Textarea } from "@/components/ui/textarea";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useToast } from "@/hooks/use-toast";
import { Upload, Download, FileX, Bug } from "lucide-react";
import * as XLSX from 'xlsx';
import { 
  processPointageImport, 
  type ParsedPointageData, 
  type ImportResult 
} from "@/lib/pointage-import-engine";

interface PointageImport {
  date: string;
  heure: string;
  type: string;
  localisation?: string;
  notes?: string;
  isValid: boolean;
  errors: string[];
}

interface PointageImportModalProps {
  isOpen: boolean;
  onClose: () => void;
  onImport: (pointages: ParsedPointageData[]) => void;
  profileId: string;
}

export function PointageImportModal({ isOpen, onClose, onImport, profileId }: PointageImportModalProps) {
  const [previewData, setPreviewData] = useState<ParsedPointageData[]>([]);
  const [importResult, setImportResult] = useState<ImportResult | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [importMode, setImportMode] = useState<'file' | 'paste'>('file');
  const [pasteData, setPasteData] = useState('');
  const [debugMode, setDebugMode] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const { toast } = useToast();

  // Fonction pour normaliser les types avec intelligence
  const smartTypeNormalization = (type: string): string => {
    if (!type) return '';
    
    const cleaned = type.toLowerCase().trim().replace(/[éèê]/g, 'e').replace(/[àâ]/g, 'a');
    
    // Détection intelligente des types
    if (cleaned.includes('entr') || cleaned.includes('arriv') || cleaned.includes('debut')) {
      return 'entree';
    }
    if (cleaned.includes('sort') || cleaned.includes('depart') || cleaned.includes('fin')) {
      return 'sortie';
    }
    if (cleaned.includes('pause') && (cleaned.includes('debut') || cleaned.includes('start') || cleaned.includes('comm'))) {
      return 'pause_debut';
    }
    if (cleaned.includes('pause') && (cleaned.includes('fin') || cleaned.includes('end') || cleaned.includes('reprise'))) {
      return 'pause_fin';
    }
    
    // Fallback sur l'ancienne méthode
    const typeMap: { [key: string]: string } = {
      'entree': 'entree',
      'sortie': 'sortie',
      'pause_debut': 'pause_debut',
      'pause debut': 'pause_debut',
      'pause_fin': 'pause_fin',
      'pause fin': 'pause_fin'
    };
    
    return typeMap[cleaned] || cleaned;
  };

  // Fonction de formatage intelligent des heures
  const smartTimeFormat = (timeStr: string): string => {
    if (!timeStr) return '';
    
    const cleanStr = timeStr.toString().trim();
    
    // Extraire tous les chiffres et les deux points
    const numbersAndColons = cleanStr.replace(/[^\d:]/g, '');
    
    // Si on a des chiffres séparés par :
    if (numbersAndColons.includes(':')) {
      const parts = numbersAndColons.split(':').filter(p => p.length > 0);
      
      if (parts.length >= 2) {
        const hours = parts[0].padStart(2, '0');
        const minutes = parts[1].padStart(2, '0');
        
        // Valider que les heures et minutes sont dans les bonnes plages
        const h = parseInt(hours);
        const m = parseInt(minutes);
        
        if (h >= 0 && h <= 23 && m >= 0 && m <= 59) {
          return `${hours}:${minutes}`;
        }
      }
    }
    
    // Si on a juste des chiffres (ex: 1030 pour 10:30)
    if (/^\d{3,4}$/.test(numbersAndColons)) {
      if (numbersAndColons.length === 3) {
        // 930 -> 09:30
        const h = numbersAndColons.substring(0, 1).padStart(2, '0');
        const m = numbersAndColons.substring(1, 3);
        return `${h}:${m}`;
      } else if (numbersAndColons.length === 4) {
        // 1030 -> 10:30
        const h = numbersAndColons.substring(0, 2);
        const m = numbersAndColons.substring(2, 4);
        return `${h}:${m}`;
      }
    }
    
    return cleanStr; // Retourner tel quel si aucun format reconnu
  };

  const validatePointageData = (data: any[]): ParsedPointageData[] => {
    console.log('🔍 VALIDATION: Début validation de', data.length, 'lignes');
    
    try {
      return data.map((row, index) => {
        console.log(`🔍 VALIDATION ligne ${index + 1}:`, row);
        const errors: string[] = [];
        let isValid = true;

        // Validation de la date avec formatage intelligent
        const dateStr = row.date || row.Date || row.DATE;
        console.log(`🔍 VALIDATION ligne ${index + 1} - dateStr:`, dateStr);
        let formattedDate = '';
        
        if (!dateStr) {
          errors.push("Date manquante");
          isValid = false;
          console.log(`❌ VALIDATION ligne ${index + 1} - Date manquante`);
        } else {
          try {
            let date: Date;
            const cleanDateStr = dateStr.toString().trim();
            console.log(`🔍 VALIDATION ligne ${index + 1} - cleanDateStr:`, cleanDateStr);
            
            // Détecter spécifiquement le format DD/MM/YYYY pour éviter les erreurs
            if (/^\d{1,2}\/\d{1,2}\/\d{4}$/.test(cleanDateStr)) {
              console.log(`✅ VALIDATION ligne ${index + 1} - Format DD/MM/YYYY détecté`);
              // Format DD/MM/YYYY confirmé
              const parts = cleanDateStr.split('/');
              const day = parseInt(parts[0]);
              const month = parseInt(parts[1]);
              const year = parseInt(parts[2]);
              
              console.log(`🔍 VALIDATION ligne ${index + 1} - Parsing: jour=${day}, mois=${month}, année=${year}`);
              
              // Validation des valeurs et construction robuste de la date
              if (day >= 1 && day <= 31 && month >= 1 && month <= 12 && year >= 1900 && year <= 3000) {
                // CORRECTION: Utiliser UTC pour éviter les décalages de fuseau horaire
                date = new Date(Date.UTC(year, month - 1, day, 12, 0, 0));
                console.log(`✅ VALIDATION ligne ${index + 1} - Date créée (UTC):`, date);
              } else {
                errors.push(`Date invalide: ${cleanDateStr} (jour=${day}, mois=${month}, année=${year})`);
                isValid = false;
                date = new Date(NaN); // Date invalide
                console.log(`❌ VALIDATION ligne ${index + 1} - Valeurs de date invalides`);
              }
            } else if (/^\d{8}$/.test(cleanDateStr.replace(/[^\d]/g, ''))) {
              // Format YYYYMMDD
              const dateNumbers = cleanDateStr.replace(/[^\d]/g, '');
              const year = parseInt(dateNumbers.substring(0, 4));
              const month = parseInt(dateNumbers.substring(4, 6));
              const day = parseInt(dateNumbers.substring(6, 8));
              
              if (day >= 1 && day <= 31 && month >= 1 && month <= 12 && year >= 1900 && year <= 3000) {
                // CORRECTION: Utiliser UTC pour éviter les décalages de fuseau horaire
                date = new Date(Date.UTC(year, month - 1, day, 12, 0, 0));
                console.log(`✅ VALIDATION ligne ${index + 1} - Format YYYYMMDD créé (UTC):`, date);
              } else {
                errors.push(`Date invalide: ${cleanDateStr}`);
                isValid = false;
                date = new Date(NaN);
                console.log(`❌ VALIDATION ligne ${index + 1} - Format YYYYMMDD invalide`);
              }
            } else {
              // Autres formats - parsing standard
              date = new Date(cleanDateStr);
              console.log(`🔍 VALIDATION ligne ${index + 1} - Parsing standard:`, date);
            }
            
            if (isNaN(date.getTime())) {
              errors.push(`Format de date invalide: "${cleanDateStr}"`);
              isValid = false;
              console.log(`❌ VALIDATION ligne ${index + 1} - Date NaN`);
            } else {
              // CORRECTION: Utiliser UTC pour les dates créées en UTC
              const year = date.getUTCFullYear();
              const month = (date.getUTCMonth() + 1).toString().padStart(2, '0');
              const day = date.getUTCDate().toString().padStart(2, '0');
              formattedDate = `${year}-${month}-${day}`;
              console.log(`✅ VALIDATION ligne ${index + 1} - Date formatée (UTC consistant):`, formattedDate);
            }
          } catch (dateError) {
            console.error(`💥 VALIDATION ligne ${index + 1} - Erreur date:`, dateError);
            errors.push(`Erreur de traitement de date: ${dateError}`);
            isValid = false;
          }
        }

        // Validation de l'heure
        const heureStr = row.heure || row.Heure || row.HEURE;
        let formattedTime = '';
        
        if (!heureStr) {
          errors.push("Heure manquante");
          isValid = false;
          console.log(`❌ VALIDATION ligne ${index + 1} - Heure manquante`);
        } else {
          try {
            formattedTime = smartTimeFormat(heureStr.toString());
            console.log(`🔍 VALIDATION ligne ${index + 1} - Heure formatée: "${heureStr}" -> "${formattedTime}"`);
            
            // Validation plus tolérante - accepter tout format d'heure valide
            const timeRegex = /^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/;
            const originalTimeRegex = /^([0-1]?[0-9]|2[0-3]):[0-5][0-9](:[0-5][0-9])?$/;
            
            // Accepter si le format final est valide OU si l'original était déjà valide
            if (!timeRegex.test(formattedTime) && !originalTimeRegex.test(heureStr.toString().trim())) {
              errors.push(`Format d'heure non reconnu: "${heureStr}"`);
              isValid = false;
              console.log(`❌ VALIDATION ligne ${index + 1} - Format heure invalide`);
            } else {
              console.log(`✅ VALIDATION ligne ${index + 1} - Heure valide`);
            }
          } catch (timeError) {
            console.error(`💥 VALIDATION ligne ${index + 1} - Erreur heure:`, timeError);
            errors.push(`Erreur de traitement d'heure: ${timeError}`);
            isValid = false;
          }
        }

        // Validation du type
        const typeStr = row.type || row.Type || row.TYPE;
        const validTypes = ['entree', 'sortie', 'pause_debut', 'pause_fin'];
        let normalizedType = '';
        
        if (!typeStr) {
          errors.push("Type manquant");
          isValid = false;
          console.log(`❌ VALIDATION ligne ${index + 1} - Type manquant`);
        } else {
          try {
            normalizedType = smartTypeNormalization(typeStr.toString());
            console.log(`🔍 VALIDATION ligne ${index + 1} - Type normalisé: "${typeStr}" -> "${normalizedType}"`);
            if (!validTypes.includes(normalizedType)) {
              errors.push(`Type invalide: "${typeStr}" → "${normalizedType}". Valeurs acceptées: ${validTypes.join(', ')}`);
              isValid = false;
              console.log(`❌ VALIDATION ligne ${index + 1} - Type invalide`);
            } else {
              console.log(`✅ VALIDATION ligne ${index + 1} - Type valide`);
            }
          } catch (typeError) {
            console.error(`💥 VALIDATION ligne ${index + 1} - Erreur type:`, typeError);
            errors.push(`Erreur de traitement de type: ${typeError}`);
            isValid = false;
          }
        }

        const result: ParsedPointageData = {
          date: formattedDate || dateStr,
          heure: formattedTime || heureStr,
          type: normalizedType,
          lieu: row.localisation || row.Localisation || '',
          notes: row.notes || row.Notes || '',
          isValid,
          errors,
          warnings: [],
          originalIndex: index
        };
        
        console.log(`🎯 VALIDATION ligne ${index + 1} - résultat final:`, result);
        return result;
      });
    } catch (globalError) {
      console.error('💥 VALIDATION: Erreur globale:', globalError);
      return [];
    }
  };

  const parseRawTextData = (text: string): any[] => {
    console.log('🚀 PARSE: Démarrage parsing avec nouveau moteur');
    
    try {
      const result = processPointageImport(text);
      setImportResult(result);
      
      // Convertir les résultats vers l'ancien format pour compatibilité
      const allEntries = [...result.validEntries, ...result.invalidEntries];
      return allEntries.map(entry => ({
        date: entry.date,
        heure: entry.heure,
        type: entry.type,
        lieu: entry.lieu || '',
        notes: entry.notes || ''
      }));
      
    } catch (error) {
      console.error('💥 PARSE: Erreur moteur:', error);
      toast({
        title: "Erreur",
        description: `Erreur de parsing: ${error}`,
        variant: "destructive"
      });
      return [];
    }
  };

  const handlePasteAnalysis = () => {
    if (!pasteData.trim()) {
      toast({
        title: "Erreur",
        description: "Veuillez coller des données à analyser",
        variant: "destructive"
      });
      return;
    }

    setIsLoading(true);
    try {
      console.log('ANALYSE: Début de l\'analyse des données collées');
      // Phase 1: Parser le texte brut sans validation
      const rawData = parseRawTextData(pasteData);
      console.log('ANALYSE: Données brutes parsées:', rawData);
      
      // Phase 2: Valider et transformer les données
      const validatedData = validatePointageData(rawData);
      console.log('ANALYSE: Données validées:', validatedData);
      
      setPreviewData(validatedData);
      
      toast({
        title: "Données analysées",
        description: `${validatedData.length} lignes trouvées, ${validatedData.filter(d => d.isValid).length} valides`
      });
    } catch (error) {
      console.error('ANALYSE: Erreur lors de l\'analyse:', error);
      toast({
        title: "Erreur",
        description: "Impossible d'analyser les données collées",
        variant: "destructive"
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    setIsLoading(true);
    try {
      console.log('INJECTION FICHIER: Lecture du fichier', file.name);
      
      const reader = new FileReader();
      reader.onload = (e) => {
        try {
          let rawData: any[] = [];
          
          if (file.name.endsWith('.csv')) {
            const text = e.target?.result as string;
            const lines = text.split('\n');
            const headers = lines[0].split(',').map(h => h.trim());
            console.log('INJECTION FICHIER CSV: Headers détectés:', headers);
            
            // Conservation de TOUTES les lignes sans filtrage
            rawData = lines.slice(1).map((line, index) => {
              console.log(`INJECTION FICHIER CSV ligne ${index + 2}: "${line}"`);
              const values = line.split(',').map(v => v.trim());
              const obj: any = {};
              headers.forEach((header, i) => {
                obj[header] = values[i] || '';
              });
              console.log(`INJECTION FICHIER CSV ligne ${index + 2} conservée:`, obj);
              return obj;
            });
          } else {
            const workbook = XLSX.read(e.target?.result, { type: 'array' });
            const sheetName = workbook.SheetNames[0];
            const worksheet = workbook.Sheets[sheetName];
            const excelData = XLSX.utils.sheet_to_json(worksheet, { header: 1 });
            
            console.log('INJECTION FICHIER Excel: Données brutes:', excelData);
            
            // Convertir en format objet avec headers
            if (excelData.length > 0) {
              const headers = excelData[0] as string[];
              console.log('INJECTION FICHIER Excel: Headers détectés:', headers);
              const dataRows = excelData.slice(1);
              
              rawData = dataRows.map((row: any[], index) => {
                console.log(`INJECTION FICHIER Excel ligne ${index + 2}:`, row);
                const obj: any = {};
                headers.forEach((header, i) => {
                  obj[header] = row[i] || '';
                });
                console.log(`INJECTION FICHIER Excel ligne ${index + 2} conservée:`, obj);
                return obj;
              });
            }
          }

          console.log('INJECTION FICHIER: Toutes les données conservées:', rawData);
          
          // Validation des données pour l'affichage
          const validatedData = validatePointageData(rawData);
          setPreviewData(validatedData);
          
          toast({
            title: "Fichier chargé",
            description: `${rawData.length} lignes détectées dans le fichier`
          });
        } catch (error) {
          console.error('INJECTION FICHIER: Erreur lors du parsing:', error);
          toast({
            title: "Erreur",
            description: "Impossible de lire le fichier",
            variant: "destructive"
          });
        }
      };

      if (file.name.endsWith('.csv')) {
        reader.readAsText(file);
      } else {
        reader.readAsArrayBuffer(file);
      }
    } catch (error) {
      console.error('INJECTION FICHIER: Erreur générale:', error);
      toast({
        title: "Erreur",
        description: "Erreur lors de la lecture du fichier",
        variant: "destructive"
      });
    } finally {
      setIsLoading(false);
    }
  };

  const downloadTemplate = () => {
    const template = [
      {
        date: "2024-01-15",
        heure: "09:00",
        type: "entree",
        localisation: "Bureau",
        notes: "Arrivée normale"
      },
      {
        date: "2024-01-15",
        heure: "17:30", 
        type: "sortie",
        localisation: "Bureau",
        notes: "Fin de journée"
      },
      {
        date: "2024-01-16",
        heure: "9:00:00 AM",
        type: "Entrée",
        localisation: "Télétravail",
        notes: "Format AM/PM supporté"
      },
      {
        date: "2024-01-16",
        heure: "5:30:00 PM",
        type: "Sortie", 
        localisation: "Télétravail",
        notes: "Accents supportés"
      }
    ];

    const ws = XLSX.utils.json_to_sheet(template);
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, "Template");
    XLSX.writeFile(wb, "template_pointages.xlsx");
  };

  const handleImport = () => {
    const validData = previewData.filter(d => d.isValid);
    if (validData.length === 0) {
      toast({
        title: "Erreur",
        description: "Aucune donnée valide à importer",
        variant: "destructive"
      });
      return;
    }

    onImport(validData);
    setPreviewData([]);
    onClose();
  };

  const resetForm = () => {
    setPreviewData([]);
    setPasteData('');
    setImportMode('file');
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  return (
    <Dialog open={isOpen} onOpenChange={(open) => {
      if (!open) {
        resetForm();
        onClose();
      }
    }}>
      <DialogContent className="max-w-4xl max-h-[80vh] overflow-hidden flex flex-col">
        <DialogHeader>
          <DialogTitle>Importer des pointages</DialogTitle>
          <DialogDescription>
            Importez vos pointages depuis un fichier Excel/CSV ou par copier-coller. 
            Formats supportés: dates (2025-07-18 ou 18/07/2025), heures (10:00, 10:00:00 ou 9:00 AM), types avec accents.
          </DialogDescription>
        </DialogHeader>

        <div className="flex-1 overflow-auto space-y-4">
          {/* Sélecteur de mode */}
          <div className="flex gap-2 border-b">
            <button
              className={`px-4 py-2 border-b-2 ${importMode === 'file' ? 'border-primary text-primary' : 'border-transparent'}`}
              onClick={() => setImportMode('file')}
            >
              Fichier Excel/CSV
            </button>
            <button
              className={`px-4 py-2 border-b-2 ${importMode === 'paste' ? 'border-primary text-primary' : 'border-transparent'}`}
              onClick={() => setImportMode('paste')}
            >
              Copier-Coller
            </button>
          </div>

          {importMode === 'file' ? (
            <div className="flex gap-2">
              <div className="flex-1">
                <Label htmlFor="file-upload">Sélectionner un fichier</Label>
                <Input
                  ref={fileInputRef}
                  id="file-upload"
                  type="file"
                  accept=".xlsx,.xls,.csv"
                  onChange={handleFileUpload}
                  disabled={isLoading}
                />
              </div>
              <Button variant="outline" onClick={downloadTemplate} className="mt-6">
                <Download className="h-4 w-4 mr-2" />
                Template
              </Button>
            </div>
          ) : (
            <div className="space-y-2">
              <Label htmlFor="paste-data">Injectez vos données (texte brut)</Label>
              <div className="text-sm text-muted-foreground mb-2">
                <strong>Phase 1 - Injection :</strong> Collez vos données telles quelles depuis Excel/Sheets<br/>
                <strong>Phase 2 - Analyse :</strong> Cliquez sur "Analyser" pour transformer le texte en données validées
              </div>
              <textarea
                id="paste-data"
                className="w-full h-32 p-3 border rounded-md resize-none font-mono text-sm"
                placeholder="date	heure	type	localisation	notes
25/07/2025	10:00:00	Entrée	Bureau	Arrivée normale
25/07/2025	17:30:00	Sortie	Bureau	Fin de journée"
                value={pasteData}
                onChange={(e) => setPasteData(e.target.value)}
                disabled={isLoading}
              />
              <Button 
                onClick={handlePasteAnalysis}
                disabled={!pasteData.trim() || isLoading}
                className="w-full"
              >
                📊 Analyser les données injectées
              </Button>
            </div>
          )}

          {previewData.length > 0 && (
            <div>
              <div className="flex items-center justify-between mb-2">
                <h3 className="font-medium">Aperçu des données</h3>
                <div className="flex gap-2 text-sm">
                  <Badge variant="outline" className="bg-green-50">
                    {previewData.filter(d => d.isValid).length} valides
                  </Badge>
                  <Badge variant="destructive">
                    {previewData.filter(d => !d.isValid).length} erreurs
                  </Badge>
                </div>
              </div>
              
              <div className="border rounded-md max-h-60 overflow-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Status</TableHead>
                      <TableHead>Date</TableHead>
                      <TableHead>Heure</TableHead>
                      <TableHead>Type</TableHead>
                      <TableHead>Localisation</TableHead>
                      <TableHead>Notes</TableHead>
                      <TableHead>Erreurs</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {previewData.map((row, index) => (
                      <TableRow key={index} className={!row.isValid ? "bg-red-50" : ""}>
                        <TableCell>
                          {row.isValid ? (
                            <Badge className="bg-green-100 text-green-800">✓</Badge>
                          ) : (
                            <Badge variant="destructive">✗</Badge>
                          )}
                        </TableCell>
                        <TableCell>{row.date}</TableCell>
                        <TableCell>{row.heure}</TableCell>
                        <TableCell>{row.type}</TableCell>
                        <TableCell>{row.lieu}</TableCell>
                        <TableCell>{row.notes}</TableCell>
                        <TableCell>
                          {row.errors.length > 0 && (
                            <div className="text-xs text-red-600">
                              {row.errors.join(', ')}
                            </div>
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            </div>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onClose()}>
            Annuler
          </Button>
          <Button 
            onClick={handleImport}
            disabled={previewData.filter(d => d.isValid).length === 0}
          >
            <Upload className="h-4 w-4 mr-2" />
            Importer {previewData.filter(d => d.isValid).length} pointage(s)
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}