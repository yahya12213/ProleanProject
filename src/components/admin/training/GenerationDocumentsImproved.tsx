import React, { useState, useEffect } from 'react';
import { EnhancedCard } from '@/components/ui/enhanced-card';
import { DocumentGenerationLogs } from "./DocumentGenerationLogs";
import TestGenerationDocuments from './TestGenerationDocuments';
import { EnhancedButton } from '@/components/ui/enhanced-button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Badge } from '@/components/ui/badge';
import { useToast } from '@/hooks/use-toast';
import { supabase } from '@/integrations/supabase/client';
import { Download, FileText, Loader2, User, CheckCircle, AlertCircle, BookOpen, FolderOpen, FileCheck } from 'lucide-react';

interface StudentValidation {
  is_eligible: boolean;
  formation_id: string;
  formation_titre: string;
  corps_formation_nom: string;
  statut_compte: string;
  error_message?: string;
}

interface Etudiant {
  id: string;
  nom: string;
  prenom: string;
  email?: string;
  cin?: string;
}

interface Formation {
  id: string;
  titre: string;
  corps_formation_nom: string;
}

interface ModeleDocument {
  modele_id: string;
  nom_modele: string;
  famille: string;
  type_document: string;
  format_page: string;
  orientation: string;
  image_recto_url?: string;
  image_verso_url?: string;
  famille_context_nom: string;
}

interface FamilleGroup {
  famille: string;
  modeles: ModeleDocument[];
  count: number;
}

const GenerationDocumentsImproved = () => {
  const [etudiants, setEtudiants] = useState<Etudiant[]>([]);
  const [selectedEtudiant, setSelectedEtudiant] = useState<string>('');
  const [studentValidation, setStudentValidation] = useState<StudentValidation | null>(null);
  const [selectedFormation, setSelectedFormation] = useState<Formation | null>(null);
  const [familles, setFamilles] = useState<FamilleGroup[]>([]);
  const [selectedFamille, setSelectedFamille] = useState<string>('');
  const [selectedModeles, setSelectedModeles] = useState<string[]>([]);
  const [isGenerating, setIsGenerating] = useState(false);
  const [loading, setLoading] = useState(true);
  const { toast } = useToast();

  useEffect(() => {
    loadEtudiants();
  }, []);

  const loadEtudiants = async () => {
    try {
      setLoading(true);
      const { data, error } = await supabase
        .from('etudiants')
        .select('id, nom, prenom, email, cin')
        .order('nom', { ascending: true });

      if (error) throw error;
      setEtudiants(data || []);
    } catch (error: any) {
      toast({
        title: "Erreur de chargement",
        description: error.message,
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const validateStudent = async (etudiantId: string) => {
    try {
      const { data, error } = await supabase
        .rpc('validate_student_for_document_generation', {
          p_etudiant_id: etudiantId
        });

      if (error) throw error;

      const validation = data?.[0];
      if (validation) {
        setStudentValidation(validation);
        
        if (validation.is_eligible && validation.formation_id) {
          setSelectedFormation({
            id: validation.formation_id,
            titre: validation.formation_titre,
            corps_formation_nom: validation.corps_formation_nom
          });
          await loadFormationModeles(validation.formation_id);
        } else {
          setSelectedFormation(null);
          setFamilles([]);
          setSelectedFamille('');
          setSelectedModeles([]);
        }
      }
    } catch (error: any) {
      console.error('Erreur validation étudiant:', error);
      setStudentValidation(null);
      setSelectedFormation(null);
      setFamilles([]);
    }
  };

  const loadFormationModeles = async (formationId: string) => {
    try {
      const { data, error } = await supabase
        .rpc('get_formation_modeles_by_famille', {
          p_formation_id: formationId
        });

      if (error) throw error;

      // Grouper par famille
      const famillesMap = new Map<string, ModeleDocument[]>();
      data?.forEach((modele: ModeleDocument) => {
        const famille = modele.famille_context_nom || modele.famille || 'Général';
        if (!famillesMap.has(famille)) {
          famillesMap.set(famille, []);
        }
        famillesMap.get(famille)!.push(modele);
      });

      const famillesArray = Array.from(famillesMap.entries()).map(([famille, modeles]) => ({
        famille,
        modeles,
        count: modeles.length
      }));

      setFamilles(famillesArray);
    } catch (error: any) {
      console.error('Erreur chargement modèles:', error);
      setFamilles([]);
    }
  };

  const generateDocuments = async () => {
    if (!selectedEtudiant || !selectedFamille || !studentValidation?.is_eligible) {
      toast({
        title: "Sélection incomplète",
        description: "Veuillez sélectionner un étudiant éligible et une famille de documents",
        variant: "destructive"
      });
      return;
    }

    try {
      setIsGenerating(true);

      const body: any = {
        etudiant_id: selectedEtudiant,
        famille: selectedFamille
      };

      if (selectedModeles.length > 0) {
        body.modele_ids = selectedModeles;
      }

      const { data, error } = await supabase.functions.invoke('generate-family-documents', { body });

      if (error) {
        console.error('Erreur Edge Function:', error);
        throw error;
      }

      if (data?.success) {
        const { results } = data;
        const successCount = results.successful.length;
        const totalCount = results.total;
        
        toast({
          title: "Documents générés",
          description: `${successCount}/${totalCount} documents générés avec succès pour la famille "${selectedFamille}"`
        });
        
        // Télécharger le PDF combiné ou les documents individuels
        if (results?.combined?.filePath) {
          await downloadDocument(results.combined.filePath, results.combined.fileName);
        } else {
          for (const result of results.successful) {
            await downloadDocument(result.filePath, result.fileName);
          }
        }
        
        if (results.failed.length > 0) {
          console.warn('Échecs de génération:', results.failed);
          toast({
            title: "Attention",
            description: `${results.failed.length} document(s) n'ont pas pu être générés`,
            variant: "destructive"
          });
        }

        // Reset des sélections
        resetSelections();
      } else {
        // Gestion spéciale pour "Pas de modèle lié"
        if (data?.error === "Pas de modèle lié") {
          toast({
            title: "Pas de modèle lié",
            description: data.message || `Aucun modèle de type "${selectedFamille}" n'est configuré pour cette formation`,
            variant: "destructive"
          });
        } else {
          throw new Error(data?.error || "Erreur de génération");
        }
      }
    } catch (error: any) {
      console.error('Erreur génération:', error);
      
      // Message spécialisé selon le type d'erreur
      let errorMessage = error.message;
      if (errorMessage.includes("Pas de modèle lié") || errorMessage.includes("Aucun modèle")) {
        errorMessage = `Pas de modèle lié pour le type "${selectedFamille}"`;
      }
      
      toast({
        title: "Erreur de génération",
        description: errorMessage,
        variant: "destructive"
      });
    } finally {
      setIsGenerating(false);
    }
  };

  const downloadDocument = async (filePath: string, fileName?: string) => {
    try {
      const { data, error } = await supabase.storage
        .from('generated-documents')
        .download(filePath);

      if (error) throw error;

      const url = URL.createObjectURL(data);
      const link = document.createElement('a');
      link.href = url;
      link.download = fileName || 'document.pdf';
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
    } catch (error: any) {
      toast({
        title: "Erreur de téléchargement",
        description: error.message,
        variant: "destructive"
      });
    }
  };

  const resetSelections = () => {
    setSelectedEtudiant('');
    setStudentValidation(null);
    setSelectedFormation(null);
    setFamilles([]);
    setSelectedFamille('');
    setSelectedModeles([]);
  };

  const getEtudiantFullName = (etudiant: Etudiant) => {
    return `${etudiant.prenom} ${etudiant.nom}`;
  };

  const selectedFamilleData = familles.find(f => f.famille === selectedFamille);

  if (loading) {
    return (
      <div className="flex justify-center items-center p-8">
        <Loader2 className="h-8 w-8 animate-spin" />
        <span className="ml-2">Chargement...</span>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-bold">Génération de Documents PDF - Système Amélioré</h2>
        <Badge variant="outline" className="bg-primary/10">
          Statut: Optimisé
        </Badge>
      </div>

      {/* Interface de génération */}
      <EnhancedCard variant="gradient" className="p-6">
        <div className="flex items-center gap-2 mb-6">
          <FileText className="h-5 w-5" />
          <h3 className="text-xl font-semibold">Générer des documents par famille</h3>
        </div>

        <div className="space-y-6">
          {/* Sélection étudiant */}
          <div>
            <label className="text-sm font-medium mb-2 block">1. Sélectionner un étudiant</label>
            <Select value={selectedEtudiant} onValueChange={(value) => {
              setSelectedEtudiant(value);
              if (value) {
                validateStudent(value);
              } else {
                resetSelections();
              }
            }}>
              <SelectTrigger>
                <SelectValue placeholder="Choisir un étudiant">
                  {selectedEtudiant && (
                    <div className="flex items-center gap-2">
                      <User className="h-4 w-4" />
                      {getEtudiantFullName(etudiants.find(e => e.id === selectedEtudiant)!)}
                    </div>
                  )}
                </SelectValue>
              </SelectTrigger>
              <SelectContent>
                {etudiants.map((etudiant) => (
                  <SelectItem key={etudiant.id} value={etudiant.id}>
                    <div className="flex items-center gap-2">
                      <User className="h-4 w-4" />
                      {getEtudiantFullName(etudiant)}
                      {etudiant.cin && (
                        <Badge variant="outline" className="text-xs">
                          {etudiant.cin}
                        </Badge>
                      )}
                    </div>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {/* Validation de l'étudiant */}
          {studentValidation && (
            <div className={`p-4 rounded-lg border ${
              studentValidation.is_eligible 
                ? 'bg-green-50 border-green-200' 
                : 'bg-red-50 border-red-200'
            }`}>
              <div className="flex items-center gap-2 mb-2">
                {studentValidation.is_eligible ? (
                  <CheckCircle className="h-5 w-5 text-green-600" />
                ) : (
                  <AlertCircle className="h-5 w-5 text-red-600" />
                )}
                <span className="font-medium">
                  {studentValidation.is_eligible ? 'Étudiant éligible' : 'Étudiant non éligible'}
                </span>
              </div>
              {studentValidation.is_eligible ? (
                <div className="space-y-1 text-sm">
                  <div><strong>Formation:</strong> {studentValidation.formation_titre}</div>
                  <div><strong>Corps de formation:</strong> {studentValidation.corps_formation_nom}</div>
                  <div><strong>Statut:</strong> {studentValidation.statut_compte}</div>
                </div>
              ) : (
                <div className="text-red-600 text-sm">
                  {studentValidation.error_message}
                </div>
              )}
            </div>
          )}

          {/* Sélection formation (affichage seulement) */}
          {selectedFormation && (
            <div className="p-4 bg-blue-50 border border-blue-200 rounded-lg">
              <div className="flex items-center gap-2 mb-2">
                <BookOpen className="h-5 w-5 text-blue-600" />
                <span className="font-medium">Formation détectée</span>
              </div>
              <div className="space-y-1 text-sm">
                <div><strong>Titre:</strong> {selectedFormation.titre}</div>
                <div><strong>Corps de formation:</strong> {selectedFormation.corps_formation_nom}</div>
              </div>
            </div>
          )}

          {/* Sélection famille */}
          {familles.length > 0 && (
            <div>
              <label className="text-sm font-medium mb-2 block">2. Sélectionner une famille de documents</label>
              <Select value={selectedFamille} onValueChange={(value) => {
                setSelectedFamille(value);
                setSelectedModeles([]);
              }}>
                <SelectTrigger>
                  <SelectValue placeholder="Choisir une famille">
                    {selectedFamille && (
                      <div className="flex items-center gap-2">
                        <FolderOpen className="h-4 w-4" />
                        {selectedFamille}
                        <Badge variant="secondary">
                          {selectedFamilleData?.count} modèle(s)
                        </Badge>
                      </div>
                    )}
                  </SelectValue>
                </SelectTrigger>
                <SelectContent>
                  {familles.map((famille) => (
                    <SelectItem key={famille.famille} value={famille.famille}>
                      <div className="flex items-center gap-2">
                        <FolderOpen className="h-4 w-4" />
                        {famille.famille}
                        <Badge variant="secondary" className="text-xs">
                          {famille.count} modèle(s)
                        </Badge>
                      </div>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
        
        {/* Section Logs de génération */}
        <div className="mt-8">
          <DocumentGenerationLogs />
        </div>
      </div>
          )}

          {/* Modèles disponibles */}
          {selectedFamilleData && (
            <div>
              <label className="text-sm font-medium mb-2 block">
                3. Modèles disponibles (optionnel - tous par défaut)
              </label>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {selectedFamilleData.modeles.map((modele) => (
                  <div
                    key={modele.modele_id}
                    className={`p-3 border rounded-lg cursor-pointer transition-colors ${
                      selectedModeles.includes(modele.modele_id)
                        ? 'border-primary bg-primary/10'
                        : 'border-gray-200 hover:border-gray-300'
                    }`}
                    onClick={() => {
                      if (selectedModeles.includes(modele.modele_id)) {
                        setSelectedModeles(prev => prev.filter(id => id !== modele.modele_id));
                      } else {
                        setSelectedModeles(prev => [...prev, modele.modele_id]);
                      }
                    }}
                  >
                    <div className="flex items-center gap-2">
                      <FileCheck className="h-4 w-4" />
                      <span className="font-medium">{modele.nom_modele}</span>
                    </div>
                    <div className="text-xs text-muted-foreground mt-1">
                      {modele.type_document} • {modele.format_page} • {modele.orientation}
                    </div>
                  </div>
                ))}
              </div>
              {selectedModeles.length > 0 && (
                <div className="mt-2 text-sm text-muted-foreground">
                  {selectedModeles.length} modèle(s) sélectionné(s)
                </div>
              )}
            </div>
          )}

          {/* Bouton de génération */}
          <div className="flex justify-end">
            <EnhancedButton
              onClick={generateDocuments}
              disabled={!studentValidation?.is_eligible || !selectedFamille || isGenerating}
              loading={isGenerating}
              variant="default"
              size="lg"
              className="w-full md:w-auto"
            >
              <FileText className="h-4 w-4 mr-2" />
              {isGenerating ? 'Génération en cours...' : 'Générer les documents'}
            </EnhancedButton>
          </div>
        </div>
      </EnhancedCard>

      {/* Test de génération */}
      <TestGenerationDocuments />

      {/* Instructions */}
      <EnhancedCard className="p-4">
        <h4 className="font-semibold mb-2">Instructions d'utilisation</h4>
        <ul className="text-sm text-muted-foreground space-y-1">
          <li>• Sélectionnez un étudiant avec un statut "valide"</li>
          <li>• Le système détecte automatiquement sa formation et les modèles disponibles</li>
          <li>• Choisissez une famille de documents (badge, certificat, ATT...)</li>
          <li>• Optionnellement, sélectionnez des modèles spécifiques</li>
          <li>• Les documents seront générés et combinés automatiquement</li>
        </ul>
      </EnhancedCard>
    </div>
  );
};

export default GenerationDocumentsImproved;