import React, { useState, useEffect } from 'react';
import { EnhancedCard } from '@/components/ui/enhanced-card';
import { EnhancedButton } from '@/components/ui/enhanced-button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Badge } from '@/components/ui/badge';
import { useToast } from '@/hooks/use-toast';
import { supabase } from '@/integrations/supabase/client';
import { Download, FileText, Loader2, User, CheckCircle, AlertCircle, BookOpen } from 'lucide-react';

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

const GenerationDocumentsTest = () => {
  const [etudiants, setEtudiants] = useState<Etudiant[]>([]);
  const [selectedEtudiant, setSelectedEtudiant] = useState<string>('');
  const [studentValidation, setStudentValidation] = useState<StudentValidation | null>(null);
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
          // Tester la fonction get_formation_modeles_by_famille
          const { data: modelesData, error: modelesError } = await supabase
            .rpc('get_formation_modeles_by_famille', {
              p_formation_id: validation.formation_id
            });

          if (modelesError) {
            console.error('Erreur chargement modèles:', modelesError);
          } else {
            console.log('Modèles disponibles:', modelesData);
            toast({
              title: "Modèles chargés",
              description: `${modelesData?.length || 0} modèles trouvés pour cette formation`
            });
          }
        }
      }
    } catch (error: any) {
      console.error('Erreur validation étudiant:', error);
      setStudentValidation(null);
    }
  };

  const generateTestDocument = async () => {
    if (!selectedEtudiant || !studentValidation?.is_eligible) {
      toast({
        title: "Test impossible",
        description: "Veuillez sélectionner un étudiant éligible",
        variant: "destructive"
      });
      return;
    }

    try {
      setIsGenerating(true);

      // Test avec la famille badge
      const { data, error } = await supabase.functions.invoke('generate-family-documents', {
        body: {
          etudiant_id: selectedEtudiant,
          famille: 'badge'
        }
      });

      if (error) throw error;

      if (data?.success) {
        toast({
          title: "Test réussi !",
          description: "Le nouveau système fonctionne correctement"
        });
        console.log('Résultat du test:', data);
      } else {
        throw new Error(data?.error || "Erreur de test");
      }
    } catch (error: any) {
      toast({
        title: "Erreur de test",
        description: error.message,
        variant: "destructive"
      });
    } finally {
      setIsGenerating(false);
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
        <h2 className="text-2xl font-bold">Test du Système Amélioré</h2>
        <Badge variant="outline" className="bg-primary/10">
          Version Test
        </Badge>
      </div>

      <EnhancedCard variant="gradient" className="p-6">
        <div className="flex items-center gap-2 mb-6">
          <FileText className="h-5 w-5" />
          <h3 className="text-xl font-semibold">Test de validation et génération</h3>
        </div>

        <div className="space-y-6">
          {/* Sélection étudiant */}
          <div>
            <label className="text-sm font-medium mb-2 block">Sélectionner un étudiant</label>
            <Select value={selectedEtudiant} onValueChange={(value) => {
              setSelectedEtudiant(value);
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
              onClick={generateTestDocument}
              disabled={!studentValidation?.is_eligible || isGenerating}
              loading={isGenerating}
              variant="default"
              size="lg"
              className="w-full md:w-auto"
            >
              <FileText className="h-4 w-4 mr-2" />
              {isGenerating ? 'Test en cours...' : 'Tester la génération (Badge)'}
            </EnhancedButton>
          </div>
        </div>
      </EnhancedCard>

      {/* Instructions */}
      <EnhancedCard className="p-4">
        <h4 className="font-semibold mb-2">Résultats du test</h4>
        <ul className="text-sm text-muted-foreground space-y-1">
          <li>✅ Fonction de validation d'étudiant créée</li>
          <li>✅ Fonction de récupération des modèles par famille créée</li>
          <li>✅ Correction des doublons de badges CAF</li>
          <li>✅ Edge function mise à jour pour utiliser les nouvelles fonctions</li>
          <li>✅ Interface utilisateur améliorée</li>
        </ul>
      </EnhancedCard>
    </div>
  );
};

export default GenerationDocumentsTest;