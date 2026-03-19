import React, { useState } from 'react';
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { supabase } from "@/integrations/supabase/client";
import { Loader2, TestTube, Download, AlertCircle, CheckCircle } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

const TestGenerationDocuments = () => {
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<any>(null);
  const { toast } = useToast();

  const testCAFGeneration = async () => {
    setLoading(true);
    setResults(null);
    
    try {
      console.log('🧪 Test génération badge CAF pour étudiant HJJHJ...');
      
      // Données de test
      const testData = {
        etudiant_id: '7817d89f-858e-4c12-96bf-5c56d162656d',
        modele_id: '7c263f37-99f2-4f76-8b2e-195c362d7d31'
      };
      
      console.log('📄 Appel fonction generate-pdf...');
      
      const { data, error } = await supabase.functions.invoke('generate-pdf', {
        body: testData
      });
      
      console.log('📊 Résultat fonction:', { data, error });
      
      if (error) {
        console.error('❌ Erreur lors de l\'invocation:', error);
        throw new Error(error.message || 'Erreur lors de l\'invocation de la fonction');
      }
      
      if (data?.success) {
        setResults({
          success: true,
          data: data,
          timestamp: new Date().toISOString()
        });
        
        toast({
          title: "Test réussi",
          description: `PDF généré: ${data.file_name}`,
          variant: "default"
        });
      } else {
        throw new Error(data?.error || 'Erreur inconnue lors de la génération');
      }
      
    } catch (error: any) {
      console.error('❌ Erreur test:', error);
      setResults({
        success: false,
        error: error.message,
        timestamp: new Date().toISOString()
      });
      
      toast({
        title: "Test échoué",
        description: error.message,
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const downloadGeneratedPDF = async () => {
    if (!results?.success || !results.data?.file_path) return;
    
    try {
      console.log('📥 Téléchargement du PDF généré...');
      
      const { data, error } = await supabase.storage
        .from('generated-documents')
        .download(results.data.file_path);
        
      if (error) throw error;
      
      // Créer et télécharger le fichier
      const url = URL.createObjectURL(data);
      const link = document.createElement('a');
      link.href = url;
      link.download = results.data.file_name;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
      
      toast({
        title: "Téléchargement réussi",
        description: "Le PDF a été téléchargé avec succès",
        variant: "default"
      });
      
    } catch (error: any) {
      console.error('❌ Erreur téléchargement:', error);
      toast({
        title: "Erreur téléchargement",
        description: error.message,
        variant: "destructive"
      });
    }
  };

  return (
    <Card className="w-full">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <TestTube className="h-5 w-5" />
          Test de Génération de Documents
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        
        {/* Test CAF Badge */}
        <div className="space-y-2">
          <h3 className="font-semibold">Test Badge CAF - Étudiant HJJHJ</h3>
          <p className="text-sm text-muted-foreground">
            Test de génération pour l'étudiant HJJHJ (ID: 7817d89f-858e-4c12-96bf-5c56d162656d)
            avec le modèle BADGE CAF (ID: 7c263f37-99f2-4f76-8b2e-195c362d7d31)
          </p>
          
          <Button 
            onClick={testCAFGeneration} 
            disabled={loading}
            className="w-full"
          >
            {loading ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin mr-2" />
                Génération en cours...
              </>
            ) : (
              <>
                <TestTube className="h-4 w-4 mr-2" />
                Lancer le test
              </>
            )}
          </Button>
        </div>

        {/* Résultats */}
        {results && (
          <div className="space-y-3 mt-6">
            <div className="flex items-center gap-2">
              {results.success ? (
                <CheckCircle className="h-5 w-5 text-green-500" />
              ) : (
                <AlertCircle className="h-5 w-5 text-red-500" />
              )}
              <h4 className="font-semibold">
                Résultats du test
              </h4>
              <Badge variant={results.success ? "default" : "destructive"}>
                {results.success ? "Succès" : "Échec"}
              </Badge>
            </div>
            
            <div className="bg-muted p-3 rounded-md">
              <pre className="text-xs overflow-auto">
                {JSON.stringify(results, null, 2)}
              </pre>
            </div>
            
            {results.success && results.data?.file_path && (
              <Button 
                onClick={downloadGeneratedPDF}
                variant="outline"
                className="w-full"
              >
                <Download className="h-4 w-4 mr-2" />
                Télécharger le PDF généré
              </Button>
            )}
          </div>
        )}

        {/* Informations système */}
        <div className="mt-6 p-3 bg-blue-50 rounded-md">
          <h4 className="font-semibold text-sm mb-2">ℹ️ Informations système</h4>
          <ul className="text-xs space-y-1 text-muted-foreground">
            <li>• Politiques RLS mises à jour pour Edge Functions</li>
            <li>• Doublons formation_modeles nettoyés</li>
            <li>• Fonction generate-pdf améliorée avec logs détaillés</li>
            <li>• Seul modèle CAF actif: BADGE CAF avec famille_context "badge"</li>
          </ul>
        </div>
      </CardContent>
    </Card>
  );
};

export default TestGenerationDocuments;