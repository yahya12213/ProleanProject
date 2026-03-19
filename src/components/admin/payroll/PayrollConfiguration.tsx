import React, { useState, useEffect } from 'react';
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Badge } from "@/components/ui/badge";
import { Settings, Percent, DollarSign, Plus, Edit2, Trash2 } from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { useToast } from "@/hooks/use-toast";
import PayrollLineModal from "./PayrollLineModal";
import GeneralSettingsModal from "./GeneralSettingsModal";
import IGRBracketsModal from "./IGRBracketsModal";
import CNSSConfigModal from "./CNSSConfigModal";
import DeleteConfirmModal from "./DeleteConfirmModal";
import { PeriodSettingsModal } from './PeriodSettingsModal';

interface PayrollLine {
  id: string;
  code: string;
  name: string;
  type: string;
  formula: string | null;
  base_amount: number;
  percentage: number;
  soumis_cnss: boolean;
  soumis_amo: boolean;
  imposable_igr: boolean;
  is_active: boolean;
  ordre_affichage: number;
  created_at?: string;
  updated_at?: string;
}

interface PayrollConfig {
  key: string;
  value: any;
  description: string;
}

const PayrollConfiguration = () => {
  const [lines, setLines] = useState<PayrollLine[]>([]);
  const [configs, setConfigs] = useState<PayrollConfig[]>([]);
  const [loading, setLoading] = useState(true);
  const [editingLine, setEditingLine] = useState<PayrollLine | null>(null);
  const [deletingLine, setDeletingLine] = useState<PayrollLine | null>(null);
  const [showLineModal, setShowLineModal] = useState(false);
  const [showGeneralSettings, setShowGeneralSettings] = useState(false);
  const [showIGRBrackets, setShowIGRBrackets] = useState(false);
  const [showCNSSConfig, setShowCNSSConfig] = useState(false);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [showPeriodSettings, setShowPeriodSettings] = useState(false);
  const { toast } = useToast();

  useEffect(() => {
    loadConfiguration();
  }, []);

  const loadConfiguration = async () => {
    try {
      const [linesResult, configsResult] = await Promise.all([
        supabase
          .from('payroll_lines')
          .select('*')
          .order('ordre_affichage'),
        
        supabase
          .from('payroll_config')
          .select('*')
          .eq('is_active', true)
          .order('key')
      ]);

      if (linesResult.error) throw linesResult.error;
      if (configsResult.error) throw configsResult.error;

      setLines(linesResult.data || []);
      setConfigs(configsResult.data || []);
    } catch (error: any) {
      toast({
        title: "Erreur",
        description: "Impossible de charger la configuration",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const toggleLineStatus = async (lineId: string, isActive: boolean) => {
    try {
      const { error } = await supabase
        .from('payroll_lines')
        .update({ is_active: isActive })
        .eq('id', lineId);

      if (error) throw error;

      setLines(prev => prev.map(line => 
        line.id === lineId ? { ...line, is_active: isActive } : line
      ));

      toast({
        title: "Succès",
        description: "Ligne de paie mise à jour",
      });
    } catch (error: any) {
      toast({
        title: "Erreur",
        description: "Impossible de modifier la ligne",
        variant: "destructive"
      });
    }
  };

  const handleAddLine = () => {
    setEditingLine(null);
    setShowLineModal(true);
  };

  const handleEditLine = (line: PayrollLine) => {
    setEditingLine(line);
    setShowLineModal(true);
  };

  const handleDeleteLine = (line: PayrollLine) => {
    setDeletingLine(line);
    setShowDeleteConfirm(true);
  };

  const confirmDeleteLine = async () => {
    if (!deletingLine) return;

    try {
      const { error } = await supabase
        .from('payroll_lines')
        .delete()
        .eq('id', deletingLine.id);

      if (error) throw error;

      setLines(prev => prev.filter(line => line.id !== deletingLine.id));
      
      toast({
        title: "Succès",
        description: "Ligne de paie supprimée"
      });
    } catch (error: any) {
      toast({
        title: "Erreur",
        description: "Impossible de supprimer la ligne",
        variant: "destructive"
      });
    } finally {
      setDeletingLine(null);
      setShowDeleteConfirm(false);
    }
  };

  const handleModalSave = () => {
    loadConfiguration();
  };

  const getConfigValue = (key: string) => {
    const config = configs.find(c => c.key === key);
    return config ? config.value : null;
  };

  const renderConfigSection = (
    title: string, 
    configKey: string, 
    description: string, 
    onConfigure?: () => void
  ) => {
    const config = getConfigValue(configKey);

    return (
      <Card>
        <CardHeader>
          <div className="flex justify-between items-start">
            <div>
              <CardTitle className="text-base">{title}</CardTitle>
              <p className="text-sm text-muted-foreground">{description}</p>
            </div>
            {onConfigure && (
              <Button onClick={onConfigure} size="sm" variant="outline">
                <Settings className="h-4 w-4 mr-2" />
                Configurer
              </Button>
            )}
          </div>
        </CardHeader>
        <CardContent>
          {config ? (
            <div className="bg-muted p-3 rounded-lg">
              <pre className="text-sm overflow-x-auto">
                {JSON.stringify(config, null, 2)}
              </pre>
            </div>
          ) : (
            <div className="text-center py-8 text-muted-foreground">
              <Settings className="h-8 w-8 mx-auto mb-2 opacity-50" />
              <p>Configuration non définie</p>
              {onConfigure && (
                <Button onClick={onConfigure} size="sm" className="mt-2">
                  Configurer maintenant
                </Button>
              )}
            </div>
          )}
        </CardContent>
      </Card>
    );
  };

  if (loading) {
    return <div className="flex justify-center p-8">Chargement...</div>;
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2 mb-6">
        <Settings className="h-6 w-6 text-gray-600" />
        <h4 className="text-lg font-semibold">Configuration de Paie</h4>
      </div>

      {/* Payroll Lines */}
      <Card>
        <CardHeader>
          <div className="flex justify-between items-center">
            <CardTitle>Lignes de Paie</CardTitle>
            <Button onClick={handleAddLine} size="sm" className="flex items-center gap-2">
              <Plus className="h-4 w-4" />
              Ajouter
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {/* Gains */}
            <div>
              <h5 className="font-medium text-green-700 mb-2 flex items-center gap-2">
                <DollarSign className="h-4 w-4" />
                Gains et Primes
              </h5>
              <div className="space-y-2">
                {lines.filter(line => line.type === 'gain').map((line) => (
                  <div key={line.id} className="flex items-center justify-between p-3 border rounded-lg">
                    <div className="flex-1">
                      <div className="flex items-center gap-2">
                        <span className="font-medium">{line.name}</span>
                        <Badge variant="outline" className="text-xs">
                          {line.code}
                        </Badge>
                        {line.formula && (
                          <Badge variant="secondary" className="text-xs">
                            Formule: {line.formula}
                          </Badge>
                        )}
                      </div>
                      <div className="flex items-center gap-4 mt-1 text-xs text-muted-foreground">
                        {line.soumis_cnss && <span className="bg-blue-100 text-blue-700 px-2 py-1 rounded">CNSS</span>}
                        {line.soumis_amo && <span className="bg-green-100 text-green-700 px-2 py-1 rounded">AMO</span>}
                        {line.imposable_igr && <span className="bg-purple-100 text-purple-700 px-2 py-1 rounded">IGR</span>}
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Switch
                        checked={line.is_active}
                        onCheckedChange={(checked) => toggleLineStatus(line.id, checked)}
                      />
                      <Button 
                        onClick={() => handleEditLine(line)}
                        size="sm" 
                        variant="ghost"
                      >
                        <Edit2 className="h-4 w-4" />
                      </Button>
                      <Button 
                        onClick={() => handleDeleteLine(line)}
                        size="sm" 
                        variant="ghost"
                        className="text-red-600 hover:text-red-700"
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Retenues */}
            <div>
              <h5 className="font-medium text-red-700 mb-2 flex items-center gap-2">
                <Percent className="h-4 w-4" />
                Retenues et Déductions
              </h5>
              <div className="space-y-2">
                {lines.filter(line => line.type === 'retenue').map((line) => (
                  <div key={line.id} className="flex items-center justify-between p-3 border rounded-lg">
                    <div className="flex-1">
                      <div className="flex items-center gap-2">
                        <span className="font-medium">{line.name}</span>
                        <Badge variant="outline" className="text-xs">
                          {line.code}
                        </Badge>
                        {line.percentage > 0 && (
                          <Badge variant="destructive" className="text-xs">
                            {line.percentage}%
                          </Badge>
                        )}
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Switch
                        checked={line.is_active}
                        onCheckedChange={(checked) => toggleLineStatus(line.id, checked)}
                      />
                      <Button 
                        onClick={() => handleEditLine(line)}
                        size="sm" 
                        variant="ghost"
                      >
                        <Edit2 className="h-4 w-4" />
                      </Button>
                      <Button 
                        onClick={() => handleDeleteLine(line)}
                        size="sm" 
                        variant="ghost"
                        className="text-red-600 hover:text-red-700"
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Configuration Sections */}
      <div className="grid gap-4">
        {renderConfigSection(
          "Configuration des Périodes de Paie",
          "period_defaults",
          "Définition des périodes et des jours de paie par défaut",
          () => setShowPeriodSettings(true)
        )}

        {renderConfigSection(
          "Paramètres Généraux",
          "payroll_settings",
          "Configuration de base : fenêtre de pointage, plafonds, seuils",
          () => setShowGeneralSettings(true)
        )}

        {renderConfigSection(
          "Barème IGR 2025",
          "igr_brackets",
          "Tranches d'imposition sur le revenu avec taux et déductions",
          () => setShowIGRBrackets(true)
        )}

        {renderConfigSection(
          "Configuration CNSS",
          "cnss_branches",
          "Branches et taux de cotisations CNSS (accidents, allocations, retraite)",
          () => setShowCNSSConfig(true)
        )}

        {renderConfigSection(
          "Configuration AMO",
          "amo_config",
          "Taux AMO salarié, employeur et contribution solidarité"
        )}

        {renderConfigSection(
          "Codes d'Absence",
          "absence_codes",
          "Codes assimilés et non-assimilés pour le calcul des congés"
        )}
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Paramètres Individuels des Employés</CardTitle>
          <CardDescription>
            Configuration des retenues et salaires individuels par employé
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div className="flex items-center justify-between p-4 border rounded-lg bg-muted/50">
              <div>
                <h3 className="font-medium">Salaire Horaire</h3>
                <p className="text-sm text-muted-foreground">
                  Chaque employé peut avoir un taux horaire personnalisé
                </p>
              </div>
              <Badge variant="outline">
                Configurable par employé
              </Badge>
            </div>
            
            <div className="flex items-center justify-between p-4 border rounded-lg bg-muted/50">
              <div>
                <h3 className="font-medium">Retenues Personnalisées</h3>
                <p className="text-sm text-muted-foreground">
                  Activation/désactivation individuelle de CNSS, AMO, IGR, Mutuelle
                </p>
              </div>
              <Badge variant="outline">
                Configurable par employé
              </Badge>
            </div>
            
            <div className="text-sm text-muted-foreground">
              <p>💡 Configurez les paramètres individuels dans la fiche employé &gt; Onglet "Paramètres de Paie"</p>
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Informations Système</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
            <div>
              <span className="font-medium">Devise:</span>
              <p className="text-muted-foreground">MAD (Dirham Marocain)</p>
            </div>
            <div>
              <span className="font-medium">Fuseau horaire:</span>
              <p className="text-muted-foreground">Africa/Casablanca</p>
            </div>
            <div>
              <span className="font-medium">Réglementation:</span>
              <p className="text-muted-foreground">Code du Travail Maroc</p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Modals */}
      <PayrollLineModal
        isOpen={showLineModal}
        onClose={() => {
          setShowLineModal(false);
          setEditingLine(null);
        }}
        onSave={handleModalSave}
        line={editingLine}
      />

      <GeneralSettingsModal
        isOpen={showGeneralSettings}
        onClose={() => setShowGeneralSettings(false)}
        onSave={handleModalSave}
      />

      <IGRBracketsModal
        isOpen={showIGRBrackets}
        onClose={() => setShowIGRBrackets(false)}
        onSave={handleModalSave}
      />

      <CNSSConfigModal
        isOpen={showCNSSConfig}
        onClose={() => setShowCNSSConfig(false)}
        onSave={handleModalSave}
      />

      <DeleteConfirmModal
        isOpen={showDeleteConfirm}
        onClose={() => {
          setShowDeleteConfirm(false);
          setDeletingLine(null);
        }}
        onConfirm={confirmDeleteLine}
        title={`Supprimer "${deletingLine?.name}"`}
        description={`Êtes-vous sûr de vouloir supprimer la ligne "${deletingLine?.name}" (${deletingLine?.code}) ?`}
      />

      <PeriodSettingsModal
        isOpen={showPeriodSettings}
        onClose={() => setShowPeriodSettings(false)}
        onSave={handleModalSave}
      />
    </div>
  );
};

export default PayrollConfiguration;