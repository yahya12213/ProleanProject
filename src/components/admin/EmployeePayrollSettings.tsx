import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useToast } from "@/hooks/use-toast";
import LoadingSpinner from "@/components/LoadingSpinner";
import { Calculator, DollarSign, Shield } from "lucide-react";
import SalaryAdvanceManager from './SalaryAdvanceManager';

interface EmployeePayrollSettingsProps {
  profileId: string;
  profileName: string;
  currentSalaireHoraire?: number;
}

interface PayrollSettings {
  id?: string;
  cnss_enabled: boolean;
  amo_enabled: boolean;
  igr_enabled: boolean;
  mutuelle_enabled: boolean;
  autres_retenues: Record<string, unknown>;
}

export const EmployeePayrollSettings: React.FC<EmployeePayrollSettingsProps> = ({
  profileId,
  profileName,
  currentSalaireHoraire
}) => {
  const [settings, setSettings] = useState<PayrollSettings>({
    cnss_enabled: true,
    amo_enabled: true,
    igr_enabled: true,
    mutuelle_enabled: false,
    autres_retenues: {}
  });
  const [salaireHoraire, setSalaireHoraire] = useState<string>(currentSalaireHoraire?.toString() || '');
  const [salaireBase, setSalaireBase] = useState<number>(0);
  const [autresRetenues, setAutresRetenues] = useState<string>('');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const { toast } = useToast();

  const loadPayrollSettings = React.useCallback(async () => {
    try {
      setLoading(true);
      
      // Charger les paramètres de paie
      const payrollResponse = await fetch(`/api/payroll-settings?profileId=${profileId}`);
      const payrollData = await payrollResponse.json();

      if (payrollData) {
        setSettings({
          ...payrollData,
          autres_retenues: payrollData.autres_retenues || {}
        });
        setAutresRetenues(JSON.stringify(payrollData.autres_retenues || {}, null, 2));
      }

      // Charger le salaire horaire actuel
      const profileResponse = await fetch(`/api/profiles/${profileId}`);
      const profileData = await profileResponse.json();

      if (profileData) {
        setSalaireHoraire(profileData.salaire_horaire?.toString() || '');
        setSalaireBase(profileData.salaire_base || 0);
      }
    } catch (error) {
      console.error('Error loading data:', error);
      toast({
        title: "Erreur",
        description: "Impossible de charger les paramètres de paie",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  }, [profileId, toast]);

  // Calculer automatiquement le salaire de base quand le taux horaire change
  useEffect(() => {
    if (salaireHoraire) {
      const newSalaireBase = Math.round(parseFloat(salaireHoraire) * 191);
      setSalaireBase(newSalaireBase);
    } else {
      setSalaireBase(0);
    }
  }, [salaireHoraire]);

  const handleSave = async () => {
    try {
      setSaving(true);

      // Mettre à jour le salaire horaire et le salaire de base dans les profils
      if (salaireHoraire) {
        const hourlyRate = parseFloat(salaireHoraire);
        const baseSalary = Math.round(hourlyRate * 191);

        const profileUpdateResponse = await fetch(`/api/profiles/${profileId}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ salaire_horaire: hourlyRate, salaire_base: baseSalary })
        });

        if (!profileUpdateResponse.ok) {
          const profileError = await profileUpdateResponse.json();
          console.error('Error updating profile:', profileError);
          throw new Error(profileError.message);
        }
      }

      // Parse autres retenues
      let parsedAutresRetenues = {};
      if (autresRetenues.trim()) {
        try {
          parsedAutresRetenues = JSON.parse(autresRetenues);
        } catch {
          toast({
            title: "Erreur",
            description: "Format JSON invalide pour les autres retenues",
            variant: "destructive"
          });
          return;
        }
      }

      // Mettre à jour ou insérer les paramètres de paie
      const payrollData = {
        profile_id: profileId,
        cnss_enabled: settings.cnss_enabled,
        amo_enabled: settings.amo_enabled,
        igr_enabled: settings.igr_enabled,
        mutuelle_enabled: settings.mutuelle_enabled,
        autres_retenues: parsedAutresRetenues
      };

      const payrollUpdateResponse = await fetch(`/api/payroll-settings`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payrollData)
      });

      if (!payrollUpdateResponse.ok) {
        const payrollError = await payrollUpdateResponse.json();
        console.error('Error updating payroll settings:', payrollError);
        throw new Error(payrollError.message);
      }

      console.log('💾 Paramètres sauvegardés:', payrollData);
      
      toast({
        title: "Succès",
        description: `Paramètres de paie mis à jour pour ${profileName}. Les calculs seront actualisés.`
      });

      // Émettre un événement pour notifier les autres composants et forcer le recalcul
      window.dispatchEvent(new CustomEvent('payroll-settings-updated', {
        detail: { 
          profileId, 
          profileName,
          settings: payrollData,
          timestamp: Date.now()
        }
      }));
      console.log('📡 Événement payroll-settings-updated émis pour profile:', profileId, 'avec données:', payrollData);
    } catch (error) {
      console.error('Error saving:', error);
      toast({
        title: "Erreur",
        description: "Impossible de sauvegarder les paramètres",
        variant: "destructive"
      });
    } finally {
      setSaving(false);
    }
  };

  const updateSetting = (key: keyof PayrollSettings, value: boolean) => {
    setSettings(prev => ({
      ...prev,
      [key]: value
    }));
  };

  useEffect(() => {
    loadPayrollSettings();
  }, [loadPayrollSettings]);

  if (loading) {
    return (
      <div className="flex justify-center p-8">
        <LoadingSpinner />
      </div>
    );
  }

  return (
    <Tabs defaultValue="retenues" className="space-y-6">
      <TabsList className="grid w-full grid-cols-2">
        <TabsTrigger value="retenues">Retenues & Salaire</TabsTrigger>
        <TabsTrigger value="avances">Avances sur Salaire</TabsTrigger>
      </TabsList>

      <TabsContent value="retenues" className="space-y-6">
        {/* Salaire Horaire */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <DollarSign className="h-5 w-5" />
              Salaire Horaire
            </CardTitle>
            <CardDescription>
              Définir le taux horaire pour les calculs de paie
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-4">
              <Label htmlFor="salaire-horaire" className="min-w-32">
                Taux horaire (MAD)
              </Label>
              <Input
                id="salaire-horaire"
                type="number"
                step="0.01"
                value={salaireHoraire}
                onChange={(e) => setSalaireHoraire(e.target.value)}
                placeholder="0.00"
                className="max-w-48"
              />
            </div>
            
            <div className="flex items-center gap-4 mt-4">
              <Label htmlFor="salaire-base" className="min-w-32">
                Salaire de base (MAD)
              </Label>
              <Input
                id="salaire-base"
                type="number"
                step="0.01"
                value={salaireBase.toString()}
                readOnly
                className="max-w-48 bg-gray-50 text-gray-600"
              />
              <span className="text-sm text-muted-foreground">
                = {salaireHoraire || '0'} × 191 heures (sauvegardé automatiquement)
              </span>
            </div>
          </CardContent>
        </Card>

        {/* Retenues Standard */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Calculator className="h-5 w-5" />
              Retenues Standard
            </CardTitle>
            <CardDescription>
              Activer ou désactiver les retenues automatiques
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between">
              <Label htmlFor="cnss-switch" className="flex flex-col space-y-1">
                <span>CNSS (Caisse Nationale de Sécurité Sociale)</span>
                <span className="text-sm text-muted-foreground">
                  Cotisations sociales obligatoires
                </span>
              </Label>
              <Switch
                id="cnss-switch"
                checked={settings.cnss_enabled}
                onCheckedChange={(checked) => updateSetting('cnss_enabled', checked)}
              />
            </div>

            <div className="flex items-center justify-between">
              <Label htmlFor="amo-switch" className="flex flex-col space-y-1">
                <span>AMO (Assurance Maladie Obligatoire)</span>
                <span className="text-sm text-muted-foreground">
                  Assurance maladie obligatoire
                </span>
              </Label>
              <Switch
                id="amo-switch"
                checked={settings.amo_enabled}
                onCheckedChange={(checked) => updateSetting('amo_enabled', checked)}
              />
            </div>

            <div className="flex items-center justify-between">
              <Label htmlFor="igr-switch" className="flex flex-col space-y-1">
                <span>IGR (Impôt Général sur le Revenu)</span>
                <span className="text-sm text-muted-foreground">
                  Impôt sur le revenu
                </span>
              </Label>
              <Switch
                id="igr-switch"
                checked={settings.igr_enabled}
                onCheckedChange={(checked) => updateSetting('igr_enabled', checked)}
              />
            </div>

            <div className="flex items-center justify-between">
              <Label htmlFor="mutuelle-switch" className="flex flex-col space-y-1">
                <span>Mutuelle</span>
                <span className="text-sm text-muted-foreground">
                  Assurance complémentaire
                </span>
              </Label>
              <Switch
                id="mutuelle-switch"
                checked={settings.mutuelle_enabled}
                onCheckedChange={(checked) => updateSetting('mutuelle_enabled', checked)}
              />
            </div>
          </CardContent>
        </Card>

        {/* Autres Retenues */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Shield className="h-5 w-5" />
              Autres Retenues
            </CardTitle>
            <CardDescription>
              Retenues personnalisées au format JSON
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Textarea
              value={autresRetenues}
              onChange={(e) => setAutresRetenues(e.target.value)}
              placeholder='{"avance_salaire": 500, "pret_entreprise": 200}'
              className="min-h-32 font-mono text-sm"
            />
            <p className="text-xs text-muted-foreground mt-2">
              Format JSON pour définir des retenues personnalisées avec leurs montants
            </p>
          </CardContent>
        </Card>

        {/* Save Button */}
        <div className="flex justify-end">
          <Button onClick={handleSave} disabled={saving}>
            {saving ? (
              <>
                <LoadingSpinner />
                Sauvegarde...
              </>
            ) : (
              'Sauvegarder les paramètres'
            )}
          </Button>
        </div>
      </TabsContent>

      <TabsContent value="avances">
        <SalaryAdvanceManager profileId={profileId} profileName={profileName} />
      </TabsContent>
    </Tabs>
  );
};