import { useState, useRef, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger } from "@/components/ui/alert-dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useToast } from "@/hooks/use-toast";
import { MapPin, Plus, Edit, Trash2, Upload, FileSpreadsheet, Download, AlertCircle, CheckCircle } from "lucide-react";
import * as XLSX from 'xlsx';
import { supabase } from "@/integrations/supabase/client";

interface Ville {
  id: string;
  nom_ville: string;
  code_ville: string;
  segment_id: string;
  created_at: string;
  updated_at?: string;
}

interface VilleManagementProps {
  segment: {
    id: string;
    nom: string;
    couleur: string;
  };
  isOpen: boolean;
  onClose: () => void;
}

interface ImportReport {
  success: number;
  errors: Array<{ line: number; error: string; data?: any }>;
}

const VilleManagement = ({ segment, isOpen, onClose }: VilleManagementProps) => {
  const [villes, setVilles] = useState<Ville[]>([]);
  const [loading, setLoading] = useState(false);
  const [isVilleDialogOpen, setIsVilleDialogOpen] = useState(false);
  const [editingVille, setEditingVille] = useState<Ville | null>(null);
  const [importReport, setImportReport] = useState<ImportReport | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const { toast } = useToast();

  // Form states
  const [villeFormData, setVilleFormData] = useState({
    nom_ville: "",
    code_ville: "",
    segment_id: segment.id
  });

  useEffect(() => {
    loadVilles();
  }, [segment.id]);

  const loadVilles = async () => {
    try {
      setLoading(true);
      
      const { data: villesData, error } = await supabase
        .from('villes')
        .select('*')
        .eq('segment_id', segment.id)
        .order('created_at', { ascending: false });

      if (error) throw error;

      setVilles(villesData || []);

    } catch (error) {
      console.error('Error loading villes:', error);
      toast({
        title: "Erreur",
        description: "Impossible de charger les villes",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const checkDuplicates = async (newVille: { nom_ville: string; code_ville: string; segment_id: string }) => {
    // Check if code_ville exists globally (across all segments)
    const { data: globalCodeCheck, error: codeError } = await supabase
      .from('villes')
      .select('id')
      .eq('code_ville', newVille.code_ville);

    if (codeError) throw codeError;
    
    // Check if nom_ville exists in the same segment
    const { data: nameCheck, error: nameError } = await supabase
      .from('villes')
      .select('id')
      .eq('nom_ville', newVille.nom_ville)
      .eq('segment_id', newVille.segment_id);

    if (nameError) throw nameError;

    return { 
      codeExists: (globalCodeCheck && globalCodeCheck.length > 0),
      nameExistsInSegment: (nameCheck && nameCheck.length > 0)
    };
  };

  const handleVilleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    try {
      if (!editingVille) {
        const { codeExists, nameExistsInSegment } = await checkDuplicates(villeFormData);

        if (codeExists) {
          toast({
            title: "Erreur de validation",
            description: `Le code ville "${villeFormData.code_ville}" existe déjà dans la base de données.`,
            variant: "destructive"
          });
          return;
        }

        if (nameExistsInSegment) {
          toast({
            title: "Erreur de validation", 
            description: `La ville "${villeFormData.nom_ville}" existe déjà dans le segment "${segment.nom}".`,
            variant: "destructive"
          });
          return;
        }
      }

      if (editingVille) {
        // Update ville in Supabase
        const { error } = await supabase
          .from('villes')
          .update({
            nom_ville: villeFormData.nom_ville,
            code_ville: villeFormData.code_ville
          })
          .eq('id', editingVille.id);

        if (error) throw error;

        toast({
          title: "Succès",
          description: "Ville modifiée avec succès"
        });
      } else {
        // Create new ville in Supabase
        const { error } = await supabase
          .from('villes')
          .insert({
            nom_ville: villeFormData.nom_ville,
            code_ville: villeFormData.code_ville,
            segment_id: villeFormData.segment_id
          });

        if (error) throw error;
        
        toast({
          title: "Succès",
          description: "Ville créée avec succès"
        });
      }

      setIsVilleDialogOpen(false);
      resetVilleForm();
      loadVilles(); // Refresh data

    } catch (error) {
      console.error('Error saving ville:', error);
      toast({
        title: "Erreur",
        description: "Impossible de sauvegarder la ville",
        variant: "destructive"
      });
    }
  };

  const handleDeleteVille = async (villeId: string) => {
    try {
      const { error } = await supabase
        .from('villes')
        .delete()
        .eq('id', villeId);

      if (error) throw error;

      toast({
        title: "Succès",
        description: "Ville supprimée avec succès"
      });
      
      loadVilles(); // Refresh data
      
    } catch (error) {
      console.error('Error deleting ville:', error);
      toast({
        title: "Erreur",
        description: "Impossible de supprimer la ville",
        variant: "destructive"
      });
    }
  };

  const resetVilleForm = () => {
    setVilleFormData({
      nom_ville: "",
      code_ville: "",
      segment_id: segment.id
    });
    setEditingVille(null);
  };

  const openEditVilleDialog = (ville: Ville) => {
    setEditingVille(ville);
    setVilleFormData({
      nom_ville: ville.nom_ville,
      code_ville: ville.code_ville,
      segment_id: ville.segment_id
    });
    setIsVilleDialogOpen(true);
  };

  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    // Reset input
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }

    try {
      setLoading(true);
      setImportReport(null); // Clear previous report
      
      // Read Excel file
      const data = await file.arrayBuffer();
      const workbook = XLSX.read(data, { type: 'array' });
      const sheetName = workbook.SheetNames[0];
      const worksheet = workbook.Sheets[sheetName];
      
      // Convert to JSON with first row as headers
      const jsonData = XLSX.utils.sheet_to_json(worksheet, { 
        header: 1,
        defval: "",
        blankrows: false
      });

      console.log('Raw Excel data:', jsonData);

      // Get headers from first row
      const headers = jsonData[0] as string[];
      console.log('Headers found:', headers);
      
      // Find column indices for "Ville" and "code" (case insensitive)
      const villeColumnIndex = headers.findIndex(h => 
        h && h.toString().toLowerCase().includes('ville')
      );
      const codeColumnIndex = headers.findIndex(h => 
        h && h.toString().toLowerCase().includes('code')
      );

      console.log('Column indices - Ville:', villeColumnIndex, 'Code:', codeColumnIndex);

      if (villeColumnIndex === -1 || codeColumnIndex === -1) {
        toast({
          title: "Format incorrect",
          description: "Les colonnes 'Ville' et 'code' sont requises dans votre fichier Excel.",
          variant: "destructive"
        });
        return;
      }

      // Process data rows (skip header)
      const dataRows = jsonData.slice(1).filter((row: any) => 
        row && row[villeColumnIndex] && row[codeColumnIndex]
      );

       console.log('Processed rows:', dataRows);

      if (dataRows.length === 0) {
        toast({
          title: "Fichier vide",
          description: "Aucune donnée valide trouvée dans le fichier. Vérifiez le format (Ville, code).",
          variant: "destructive"
        });
        return;
      }

      const report: ImportReport = {
        success: 0,
        errors: []
      };

      const newVilles: Array<{nom_ville: string, code_ville: string, segment_id: string}> = [];

      for (let index = 0; index < dataRows.length; index++) {
        const row = dataRows[index];
        const lineNumber = index + 2; // Excel line number (header + 1 + current index)
        
        const ville = String(row[villeColumnIndex] || "").trim();
        const code = String(row[codeColumnIndex] || "").trim();
        
        // Validate required fields
        if (!ville || !code) {
          report.errors.push({
            line: lineNumber,
            error: "Ville ou code manquant",
            data: { Ville: ville, code: code }
          });
          continue;
        }
        
        try {
          // Check duplicates against database
          const { codeExists, nameExistsInSegment } = await checkDuplicates({
            nom_ville: ville,
            code_ville: code,
            segment_id: segment.id
          });

          if (codeExists) {
            report.errors.push({
              line: lineNumber,
              error: `code_ville '${code}' déjà existant`,
              data: { Ville: ville, code: code }
            });
            continue;
          }

          if (nameExistsInSegment) {
            report.errors.push({
              line: lineNumber,
              error: `nom_ville '${ville}' déjà existant dans le segment '${segment.nom}'`,
              data: { Ville: ville, code: code }
            });
            continue;
          }

          // Add to batch for insertion
          newVilles.push({
            nom_ville: ville,
            code_ville: code,
            segment_id: segment.id
          });
          
          report.success++;
        } catch (error) {
          console.error('Error validating row:', error);
          report.errors.push({
            line: lineNumber,
            error: `Erreur lors de la validation: ${error}`,
            data: { Ville: ville, code: code }
          });
        }
      }

      console.log('New villes to insert:', newVilles);

      // Insert new villes in batch
      if (newVilles.length > 0) {
        const { error: insertError } = await supabase
          .from('villes')
          .insert(newVilles);

        if (insertError) {
          console.error('Insert error:', insertError);
          throw insertError;
        }
      }
      
      setImportReport(report);
      loadVilles(); // Refresh data

      toast({
        title: "Import terminé",
        description: `${report.success} ville(s) importée(s) avec succès. ${report.errors.length} erreur(s).`
      });

    } catch (error) {
      console.error('Error processing file:', error);
      toast({
        title: "Erreur d'import",
        description: `Impossible de traiter le fichier Excel: ${error instanceof Error ? error.message : 'Erreur inconnue'}`,
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const downloadTemplate = () => {
    // Create Excel template instead of CSV
    const workbook = XLSX.utils.book_new();
    const worksheetData = [
      ['Ville', 'code'], // Headers
      ['Berkane', 'A1P01'],
      ['Errachidia', 'A1P02'],
      ['El jadida', 'A1P03']
    ];
    
    const worksheet = XLSX.utils.aoa_to_sheet(worksheetData);
    XLSX.utils.book_append_sheet(workbook, worksheet, 'Modele_Villes');
    
    // Download as Excel file
    XLSX.writeFile(workbook, `template_villes_${segment.nom}.xlsx`);
    
    toast({
      title: "Modèle téléchargé",
      description: "Le modèle Excel a été téléchargé avec succès"
    });
  };

  const downloadExistingVilles = () => {
    if (villes.length === 0) {
      toast({
        title: "Aucune ville",
        description: "Il n'y a aucune ville à télécharger pour ce segment.",
        variant: "destructive"
      });
      return;
    }

    // Create Excel workbook with existing villes
    const workbook = XLSX.utils.book_new();
    const worksheetData = [
      ['Ville', 'code'], // Headers
      ...villes.map(ville => [ville.nom_ville, ville.code_ville])
    ];
    
    const worksheet = XLSX.utils.aoa_to_sheet(worksheetData);
    XLSX.utils.book_append_sheet(workbook, worksheet, 'Villes');
    
    // Download as Excel file
    XLSX.writeFile(workbook, `villes_${segment.nom}_${new Date().toISOString().split('T')[0]}.xlsx`);
    
    toast({
      title: "Téléchargement réussi",
      description: `${villes.length} ville(s) téléchargée(s) pour le segment ${segment.nom}`
    });
  };

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="max-w-4xl max-h-[90vh] overflow-hidden flex flex-col">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-3">
            <div 
              className="w-4 h-4 rounded-full" 
              style={{ backgroundColor: segment.couleur }}
            />
            Gestion des Villes - {segment.nom}
          </DialogTitle>
          <DialogDescription>
            Gérez les villes associées à ce segment avec validation automatique
          </DialogDescription>
        </DialogHeader>

        <div className="flex-1 overflow-hidden">
          <Tabs defaultValue="villes" className="h-full flex flex-col">
            <TabsList className="grid w-full grid-cols-2">
              <TabsTrigger value="villes">Gestion des Villes</TabsTrigger>
              <TabsTrigger value="import">Import en Masse</TabsTrigger>
            </TabsList>

            <TabsContent value="villes" className="flex-1 overflow-hidden mt-4">
              <div className="space-y-4 h-full flex flex-col">
                <div className="flex justify-between items-center">
                  <div className="flex items-center gap-2">
                    <Badge variant="secondary">{villes.length} ville(s)</Badge>
                  </div>
                  
                  <div className="flex gap-2">
                    <Button 
                      variant="outline" 
                      onClick={downloadExistingVilles}
                      className="gap-2"
                      disabled={villes.length === 0}
                    >
                      <Download className="h-4 w-4" />
                      Télécharger
                    </Button>
                    <Button onClick={() => { resetVilleForm(); setIsVilleDialogOpen(true); }} className="gap-2">
                      <Plus className="h-4 w-4" />
                      Ajouter une ville
                    </Button>
                  </div>
                </div>

                <Card className="flex-1 overflow-hidden">
                  <CardContent className="p-0 h-full">
                    <div className="overflow-auto max-h-[400px]">
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead>Ville</TableHead>
                            <TableHead>Code Ville</TableHead>
                            <TableHead>Segment</TableHead>
                            <TableHead className="text-right">Actions</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {villes.map((ville) => (
                            <TableRow key={ville.id}>
                              <TableCell>
                                <div className="flex items-center gap-3">
                                  <MapPin className="h-4 w-4 text-muted-foreground" />
                                  <div className="font-medium">{ville.nom_ville}</div>
                                </div>
                              </TableCell>
                              <TableCell>
                                <code className="bg-muted px-2 py-1 rounded text-sm">
                                  {ville.code_ville}
                                </code>
                              </TableCell>
                              <TableCell>
                                <div className="flex items-center gap-2">
                                  <div 
                                    className="w-3 h-3 rounded-full" 
                                    style={{ backgroundColor: segment.couleur }}
                                  />
                                  {segment.nom}
                                </div>
                              </TableCell>
                              <TableCell className="text-right">
                                <div className="flex gap-2 justify-end">
                                  <Button
                                    variant="outline"
                                    size="sm"
                                    onClick={() => openEditVilleDialog(ville)}
                                  >
                                    <Edit className="h-4 w-4" />
                                  </Button>
                                  
                                  <AlertDialog>
                                    <AlertDialogTrigger asChild>
                                      <Button variant="outline" size="sm">
                                        <Trash2 className="h-4 w-4" />
                                      </Button>
                                    </AlertDialogTrigger>
                                    <AlertDialogContent>
                                      <AlertDialogHeader>
                                        <AlertDialogTitle>Confirmer la suppression</AlertDialogTitle>
                                      <AlertDialogDescription>
                                        Êtes-vous sûr de vouloir supprimer la ville "{ville.nom_ville}" ? 
                                        Cette action est irréversible.
                                      </AlertDialogDescription>
                                    </AlertDialogHeader>
                                    <AlertDialogFooter>
                                      <AlertDialogCancel>Annuler</AlertDialogCancel>
                                      <AlertDialogAction 
                                        onClick={() => handleDeleteVille(ville.id)}
                                        className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                                      >
                                        Supprimer
                                        </AlertDialogAction>
                                      </AlertDialogFooter>
                                    </AlertDialogContent>
                                  </AlertDialog>
                                </div>
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </div>
                  </CardContent>
                </Card>
              </div>
            </TabsContent>

            <TabsContent value="import" className="flex-1 overflow-hidden mt-4">
              <div className="space-y-4 h-full flex flex-col">
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <FileSpreadsheet className="h-5 w-5" />
                      Import en Masse via Excel
                    </CardTitle>
                    <CardDescription>
                      Importez plusieurs villes simultanément via un fichier Excel ou CSV
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="flex gap-3">
                      <Button
                        variant="outline"
                        onClick={downloadTemplate}
                        className="gap-2"
                      >
                        <Download className="h-4 w-4" />
                        Télécharger le modèle
                      </Button>
                      
                      <div className="flex-1">
                        <input
                          ref={fileInputRef}
                          type="file"
                          accept=".xlsx,.xls,.csv"
                          onChange={handleFileUpload}
                          className="hidden"
                        />
                        <Button
                          onClick={() => fileInputRef.current?.click()}
                          disabled={loading}
                          className="gap-2 w-full"
                        >
                          <Upload className="h-4 w-4" />
                          {loading ? "Traitement en cours..." : "Importer un fichier"}
                        </Button>
                      </div>
                    </div>

                    {importReport && (
                      <Card>
                        <CardHeader>
                          <CardTitle className="text-base flex items-center gap-2">
                            <CheckCircle className="h-4 w-4 text-green-600" />
                            Rapport d'Import
                          </CardTitle>
                        </CardHeader>
                        <CardContent className="space-y-3">
                          <div className="flex items-center gap-4">
                            <Badge variant="default" className="bg-green-100 text-green-800">
                              {importReport.success} succès
                            </Badge>
                            {importReport.errors.length > 0 && (
                              <Badge variant="destructive">
                                {importReport.errors.length} erreur(s)
                              </Badge>
                            )}
                          </div>

                          {importReport.errors.length > 0 && (
                            <div className="space-y-2">
                              <h4 className="font-medium flex items-center gap-2">
                                <AlertCircle className="h-4 w-4 text-destructive" />
                                Lignes rejetées :
                              </h4>
                              <div className="max-h-32 overflow-auto bg-muted/50 rounded p-3">
                                {importReport.errors.map((error, index) => (
                                  <div key={index} className="text-sm text-muted-foreground">
                                    Ligne {error.line}: {error.error}
                                    {error.data && ` (${error.data.Ville} - ${error.data.code})`}
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}
                        </CardContent>
                      </Card>
                    )}
                  </CardContent>
                </Card>
              </div>
            </TabsContent>
          </Tabs>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            Fermer
          </Button>
        </DialogFooter>

        {/* Add/Edit Ville Dialog */}
        <Dialog open={isVilleDialogOpen} onOpenChange={setIsVilleDialogOpen}>
          <DialogContent className="max-w-md">
            <form onSubmit={handleVilleSubmit}>
              <DialogHeader>
                <DialogTitle>
                  {editingVille ? "Modifier la ville" : "Nouvelle ville"}
                </DialogTitle>
                <DialogDescription>
                  {editingVille ? "Modifiez les informations de la ville" : "Ajoutez une nouvelle ville au segment"}
                </DialogDescription>
              </DialogHeader>

                <div className="grid gap-4 py-4">
                  <div>
                    <Label htmlFor="ville-nom">Nom de la ville *</Label>
                    <Input
                      id="ville-nom"
                      value={villeFormData.nom_ville}
                      onChange={(e) => setVilleFormData({...villeFormData, nom_ville: e.target.value})}
                      required
                    />
                  </div>

                  <div>
                    <Label htmlFor="ville-code">Code ville *</Label>
                    <Input
                      id="ville-code"
                      value={villeFormData.code_ville}
                      onChange={(e) => setVilleFormData({...villeFormData, code_ville: e.target.value})}
                      placeholder="A1P01"
                      required
                    />
                    <p className="text-xs text-muted-foreground mt-1">
                      Le code doit être unique dans toute la base de données
                    </p>
                  </div>

                  <div>
                    <Label htmlFor="ville-segment">Segment</Label>
                    <Input
                      id="ville-segment"
                      value={segment.nom}
                      disabled
                      className="bg-muted"
                    />
                  </div>
                </div>

              <DialogFooter>
                <Button type="button" variant="outline" onClick={() => setIsVilleDialogOpen(false)}>
                  Annuler
                </Button>
                <Button type="submit">
                  {editingVille ? "Modifier" : "Créer"}
                </Button>
              </DialogFooter>
            </form>
          </DialogContent>
        </Dialog>
      </DialogContent>
    </Dialog>
  );
};

export default VilleManagement;