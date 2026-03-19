import React, { useState } from 'react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { EnhancedCard } from '@/components/ui/enhanced-card';
import { Badge } from '@/components/ui/badge';
import { FileText, Rocket, Archive, TestTube } from 'lucide-react';
import GenerationDocumentsImproved from './GenerationDocumentsImproved';
import GenerationDocuments from './GenerationDocuments';
import TestDocumentGeneration from './TestDocumentGeneration';

const DocumentGenerationHub = () => {
  const [activeTab, setActiveTab] = useState('improved');

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-3xl font-bold">Centre de Génération de Documents</h1>
        <Badge variant="outline" className="bg-primary/10">
          Système Optimisé
        </Badge>
      </div>

      <EnhancedCard className="p-6">
        <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
          <TabsList className="grid w-full grid-cols-3">
            <TabsTrigger value="improved" className="flex items-center gap-2">
              <Rocket className="h-4 w-4" />
              Système Amélioré
              <Badge variant="secondary" className="ml-2">
                Nouveau
              </Badge>
            </TabsTrigger>
            <TabsTrigger value="tests" className="flex items-center gap-2">
              <TestTube className="h-4 w-4" />
              Tests Complets
            </TabsTrigger>
            <TabsTrigger value="legacy" className="flex items-center gap-2">
              <Archive className="h-4 w-4" />
              Ancien Système
            </TabsTrigger>
          </TabsList>

          <TabsContent value="improved" className="mt-6">
            <div className="space-y-4">
              <div className="bg-green-50 border border-green-200 rounded-lg p-4">
                <div className="flex items-center gap-2 mb-2">
                  <FileText className="h-5 w-5 text-green-600" />
                  <span className="font-semibold text-green-800">Système Amélioré</span>
                </div>
                <ul className="text-sm text-green-700 space-y-1">
                  <li>✅ Validation automatique du statut étudiant</li>
                  <li>✅ Détection automatique de la formation</li>
                  <li>✅ Logique corrigée pour les familles de documents</li>
                  <li>✅ Performances optimisées avec nouvelles fonctions DB</li>
                  <li>✅ Interface utilisateur modernisée</li>
                  <li>✅ Gestion d'erreurs améliorée</li>
                </ul>
              </div>
              <GenerationDocumentsImproved />
            </div>
          </TabsContent>

          <TabsContent value="tests" className="mt-6">
            <div className="space-y-4">
              <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                <div className="flex items-center gap-2 mb-2">
                  <TestTube className="h-5 w-5 text-blue-600" />
                  <span className="font-semibold text-blue-800">Tests Automatisés Complets</span>
                </div>
                <p className="text-sm text-blue-700">
                  Tests de validation de toutes les couches du système : fonctions DB, edge functions, et intégration complète.
                </p>
              </div>
              <TestDocumentGeneration />
            </div>
          </TabsContent>

          <TabsContent value="legacy" className="mt-6">
            <div className="space-y-4">
              <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
                <div className="flex items-center gap-2 mb-2">
                  <Archive className="h-5 w-5 text-yellow-600" />
                  <span className="font-semibold text-yellow-800">Ancien Système (Déprécié)</span>
                </div>
                <p className="text-sm text-yellow-700">
                  ⚠️ Ce système utilise l'ancienne logique et peut contenir des problèmes de doublons.
                  Il est recommandé d'utiliser le système amélioré.
                </p>
              </div>
              <GenerationDocuments />
            </div>
          </TabsContent>
        </Tabs>
      </EnhancedCard>
    </div>
  );
};

export default DocumentGenerationHub;