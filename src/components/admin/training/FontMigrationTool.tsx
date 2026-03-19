import React, { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { supabase } from '@/integrations/supabase/client';
import { toast } from 'sonner';
import { 
  migrateBlockStyles, 
  validateBlockStyles, 
  detectFontSizeUnit,
  normalizeFontSizeToPoints 
} from '@/lib/font-migration-utils';

interface BlocWithStyles {
  id: string;
  nom_bloc: string;
  styles_css: any;
}

export const FontMigrationTool = () => {
  const [loading, setLoading] = useState(false);
  const [analysisResult, setAnalysisResult] = useState<{
    total: number;
    needsMigration: number;
    validBlocs: number;
    issues: string[];
  } | null>(null);

  const analyzeBlocs = async () => {
    setLoading(true);
    try {
      const { data: blocs, error } = await supabase
        .from('document_blocs')
        .select('id, nom_bloc, styles_css')
        .not('styles_css', 'is', null);

      if (error) throw error;

      let needsMigration = 0;
      let validBlocs = 0;
      const allIssues: string[] = [];

      blocs?.forEach((bloc: BlocWithStyles) => {
        const validation = validateBlockStyles(bloc.styles_css);
        if (validation.isValid) {
          validBlocs++;
        } else {
          needsMigration++;
          allIssues.push(`Bloc "${bloc.nom_bloc}": ${validation.issues.join(', ')}`);
        }
      });

      setAnalysisResult({
        total: blocs?.length || 0,
        needsMigration,
        validBlocs,
        issues: allIssues.slice(0, 10) // Limiter à 10 pour l'affichage
      });

      toast.success(`Analyse terminée: ${needsMigration} blocs nécessitent une migration`);
    } catch (error) {
      console.error('Erreur lors de l\'analyse:', error);
      toast.error('Erreur lors de l\'analyse');
    } finally {
      setLoading(false);
    }
  };

  const migrateAllBlocs = async () => {
    if (!analysisResult || analysisResult.needsMigration === 0) {
      toast.info('Aucun bloc ne nécessite de migration');
      return;
    }

    setLoading(true);
    try {
      // Récupérer tous les blocs qui nécessitent une migration
      const { data: blocs, error: fetchError } = await supabase
        .from('document_blocs')
        .select('id, nom_bloc, styles_css')
        .not('styles_css', 'is', null);

      if (fetchError) throw fetchError;

      const blocsToMigrate = blocs?.filter((bloc: BlocWithStyles) => {
        const validation = validateBlockStyles(bloc.styles_css);
        return !validation.isValid;
      }) || [];

      console.log(`🔄 Migration de ${blocsToMigrate.length} blocs...`);

      // Migrer chaque bloc
      const migrations = blocsToMigrate.map(async (bloc: BlocWithStyles) => {
        const oldStyles = bloc.styles_css;
        const newStyles = migrateBlockStyles(oldStyles);
        
        console.log(`Bloc "${bloc.nom_bloc}": ${oldStyles?.fontSize} → ${newStyles?.fontSize}pt`);

        const { error: updateError } = await supabase
          .from('document_blocs')
          .update({ styles_css: newStyles })
          .eq('id', bloc.id);

        if (updateError) {
          console.error(`Erreur migration bloc ${bloc.nom_bloc}:`, updateError);
          throw updateError;
        }

        return { nom: bloc.nom_bloc, old: oldStyles?.fontSize, new: newStyles?.fontSize };
      });

      const results = await Promise.all(migrations);
      
      console.log('✅ Migration terminée:', results);
      toast.success(`Migration réussie: ${results.length} blocs mis à jour`);
      
      // Re-analyser après migration
      await analyzeBlocs();
      
    } catch (error) {
      console.error('Erreur lors de la migration:', error);
      toast.error('Erreur lors de la migration');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Card className="w-full max-w-4xl mx-auto">
      <CardHeader>
        <CardTitle>🔧 Outil de Migration des Polices</CardTitle>
        <CardDescription>
          Analyse et migre les tailles de police des blocs pour assurer la cohérence entre l'éditeur et le PDF
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex gap-2">
          <Button 
            onClick={analyzeBlocs} 
            disabled={loading}
            variant="outline"
          >
            {loading ? 'Analyse...' : 'Analyser les Blocs'}
          </Button>
          
          {analysisResult && analysisResult.needsMigration > 0 && (
            <Button 
              onClick={migrateAllBlocs} 
              disabled={loading}
              className="bg-orange-600 hover:bg-orange-700"
            >
              {loading ? 'Migration...' : `Migrer ${analysisResult.needsMigration} Blocs`}
            </Button>
          )}
        </div>

        {analysisResult && (
          <div className="space-y-4">
            <div className="flex gap-2 flex-wrap">
              <Badge variant="secondary">
                Total: {analysisResult.total} blocs
              </Badge>
              <Badge variant="destructive">
                À migrer: {analysisResult.needsMigration}
              </Badge>
              <Badge variant="default">
                Conformes: {analysisResult.validBlocs}
              </Badge>
            </div>

            {analysisResult.issues.length > 0 && (
              <div className="bg-red-50 p-4 rounded-lg border border-red-200">
                <h4 className="font-semibold text-red-800 mb-2">Problèmes détectés:</h4>
                <ul className="text-sm text-red-700 space-y-1">
                  {analysisResult.issues.map((issue, index) => (
                    <li key={index} className="font-mono">• {issue}</li>
                  ))}
                </ul>
                {analysisResult.issues.length === 10 && (
                  <p className="text-xs text-red-600 mt-2">... et plus</p>
                )}
              </div>
            )}

            {analysisResult.needsMigration === 0 && (
              <div className="bg-green-50 p-4 rounded-lg border border-green-200">
                <p className="text-green-800 font-semibold">
                  ✅ Tous les blocs sont conformes ! Aucune migration nécessaire.
                </p>
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
};