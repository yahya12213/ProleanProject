import React, { useState, useEffect } from 'react';
import { EnhancedCard } from '@/components/ui/enhanced-card';
import { EnhancedButton } from '@/components/ui/enhanced-button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Badge } from '@/components/ui/badge';
import { useToast } from '@/hooks/use-toast';
import { supabase } from '@/integrations/supabase/client';
import { Download, FileText, Loader2, User, CheckCircle, AlertCircle, PlayCircle, ClipboardCheck } from 'lucide-react';

interface TestResult {
  success: boolean;
  function: string;
  message: string;
  details?: any;
  error?: string;
}

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

const TestDocumentGeneration = () => {
  const [etudiants, setEtudiants] = useState<Etudiant[]>([]);
  const [selectedEtudiant, setSelectedEtudiant] = useState<string>('');
  const [studentValidation, setStudentValidation] = useState<StudentValidation | null>(null);
  const [testResults, setTestResults] = useState<TestResult[]>([]);
  const [isRunningTests, setIsRunningTests] = useState(false);
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
      }
    } catch (error: any) {
      console.error('Erreur validation étudiant:', error);
      setStudentValidation(null);
    }
  };

  const runComprehensiveTests = async () => {
    if (!selectedEtudiant || !studentValidation?.is_eligible) {
      toast({
        title: "Test impossible",
        description: "Veuillez sélectionner un étudiant éligible",
        variant: "destructive"
      });
      return;
    }

    setIsRunningTests(true);
    setTestResults([]);
    const results: TestResult[] = [];

    try {
      // Test 1: Validation de l'étudiant
      try {
        const { data, error } = await supabase
          .rpc('validate_student_for_document_generation', {
            p_etudiant_id: selectedEtudiant
          });

        if (error) throw error;

        results.push({
          success: true,
          function: 'validate_student_for_document_generation',
          message: 'Validation étudiant réussie',
          details: data?.[0]
        });
      } catch (error: any) {
        results.push({
          success: false,
          function: 'validate_student_for_document_generation',
          message: 'Échec validation étudiant',
          error: error.message
        });
      }

      // Test 2: Récupération des modèles par famille
      try {
        const { data, error } = await supabase
          .rpc('get_formation_modeles_by_famille', {
            p_formation_id: studentValidation.formation_id,
            p_famille_nom: 'badge'
          });

        if (error) throw error;

        results.push({
          success: true,
          function: 'get_formation_modeles_by_famille',
          message: `${data?.length || 0} modèles badge trouvés`,
          details: data
        });
      } catch (error: any) {
        results.push({
          success: false,
          function: 'get_formation_modeles_by_famille',
          message: 'Échec récupération modèles',
          error: error.message
        });
      }

      // Test 3: Génération simple (1 étudiant, famille badge)
      try {
        const { data, error } = await supabase.functions.invoke('generate-family-documents', {
          body: {
            etudiant_id: selectedEtudiant,
            famille: 'badge'
          }
        });

        if (error) throw error;

        results.push({
          success: data?.success || false,
          function: 'generate-family-documents',
          message: data?.message || 'Génération simple',
          details: data?.results
        });
      } catch (error: any) {
        results.push({
          success: false,
          function: 'generate-family-documents',
          message: 'Échec génération simple',
          error: error.message
        });
      }

      // Test 4: Génération batch (même étudiant, famille badge)
      try {
        const { data, error } = await supabase.functions.invoke('generate-family-documents-batch', {
          body: {
            etudiant_ids: [selectedEtudiant],
            famille: 'badge'
          }
        });

        if (error) throw error;

        results.push({
          success: data?.success || false,
          function: 'generate-family-documents-batch',
          message: data?.message || 'Génération batch',
          details: data?.results
        });
      } catch (error: any) {
        results.push({
          success: false,
          function: 'generate-family-documents-batch',
          message: 'Échec génération batch',
          error: error.message
        });
      }

      setTestResults(results);

      const successCount = results.filter(r => r.success).length;
      const totalCount = results.length;

      toast({
        title: "Tests terminés",
        description: `${successCount}/${totalCount} tests réussis`,
        variant: successCount === totalCount ? "default" : "destructive"
      });

    } catch (error: any) {
      toast({
        title: "Erreur lors des tests",
        description: error.message,
        variant: "destructive"
      });
    } finally {
      setIsRunningTests(false);
    }
  };

  const getEtudiantFullName = (etudiant: Etudiant) => {
    return `${etudiant.prenom} ${etudiant.nom}`;
  };

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
        <h2 className="text-2xl font-bold">Tests Complets du Système</h2>
        <Badge variant="outline" className="bg-primary/10">
          Tests Automatisés
        </Badge>
      </div>

      <EnhancedCard variant="gradient" className="p-6">
        <div className="flex items-center gap-2 mb-6">
          <ClipboardCheck className="h-5 w-5" />
          <h3 className="text-xl font-semibold">Configuration des tests</h3>
        </div>

        <div className="space-y-6">
          {/* Sélection étudiant */}
          <div>
            <label className="text-sm font-medium mb-2 block">Sélectionner un étudiant pour les tests</label>
            <Select value={selectedEtudiant} onValueChange={(value) => {
              setSelectedEtudiant(value);
              setTestResults([]);
              if (value) {
                validateStudent(value);
              } else {
                setStudentValidation(null);
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

          {/* Bouton de test */}
          <div className="flex justify-end">
            <EnhancedButton
              onClick={runComprehensiveTests}
              disabled={!studentValidation?.is_eligible || isRunningTests}
              loading={isRunningTests}
              variant="default"
              size="lg"
              className="w-full md:w-auto"
            >
              <PlayCircle className="h-4 w-4 mr-2" />
              {isRunningTests ? 'Tests en cours...' : 'Lancer tous les tests'}
            </EnhancedButton>
          </div>
        </div>
      </EnhancedCard>

      {/* Résultats des tests */}
      {testResults.length > 0 && (
        <EnhancedCard className="p-6">
          <h3 className="text-xl font-semibold mb-4">Résultats des tests</h3>
          <div className="space-y-4">
            {testResults.map((result, index) => (
              <div
                key={index}
                className={`p-4 rounded-lg border ${
                  result.success 
                    ? 'bg-green-50 border-green-200' 
                    : 'bg-red-50 border-red-200'
                }`}
              >
                <div className="flex items-center gap-2 mb-2">
                  {result.success ? (
                    <CheckCircle className="h-5 w-5 text-green-600" />
                  ) : (
                    <AlertCircle className="h-5 w-5 text-red-600" />
                  )}
                  <span className="font-medium">{result.function}</span>
                  <Badge variant={result.success ? "default" : "destructive"}>
                    {result.success ? "SUCCÈS" : "ÉCHEC"}
                  </Badge>
                </div>
                <div className="text-sm">
                  <div className="mb-1">{result.message}</div>
                  {result.error && (
                    <div className="text-red-600 font-mono text-xs">
                      Erreur: {result.error}
                    </div>
                  )}
                  {result.details && (
                    <details className="mt-2">
                      <summary className="cursor-pointer text-xs text-muted-foreground">
                        Voir les détails
                      </summary>
                      <pre className="mt-1 text-xs bg-white/50 p-2 rounded overflow-auto">
                        {JSON.stringify(result.details, null, 2)}
                      </pre>
                    </details>
                  )}
                </div>
              </div>
            ))}
          </div>
        </EnhancedCard>
      )}

      {/* Instructions */}
      <EnhancedCard className="p-4">
        <h4 className="font-semibold mb-2">Tests effectués</h4>
        <ul className="text-sm text-muted-foreground space-y-1">
          <li><strong>Test 1:</strong> Validation de l'étudiant (fonction DB)</li>
          <li><strong>Test 2:</strong> Récupération des modèles par famille (fonction DB)</li>
          <li><strong>Test 3:</strong> Génération simple d'un document (edge function)</li>
          <li><strong>Test 4:</strong> Génération batch de documents (edge function)</li>
        </ul>
      </EnhancedCard>
    </div>
  );
};

export default TestDocumentGeneration;