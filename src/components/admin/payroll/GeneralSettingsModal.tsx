import React, { useState, useEffect } from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useToast } from "@/hooks/use-toast";
import { supabase } from "@/integrations/supabase/client";

interface GeneralSettings {
  pointage_window_hours: number;
  cnss_ceiling: number;
  minimum_wage: number;
  tax_free_threshold: number;
  solidarity_threshold: number;
  family_deduction_per_dependent: number;
  max_dependents: number;
  overtime_rate: number;
  weekend_rate: number;
  holiday_rate: number;
}

interface GeneralSettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSave: () => void;
}

const GeneralSettingsModal: React.FC<GeneralSettingsModalProps> = ({
  isOpen,
  onClose,
  onSave
}) => {
  const { toast } = useToast();
  const [settings, setSettings] = useState<GeneralSettings>({
    pointage_window_hours: 2,
    cnss_ceiling: 7000,
    minimum_wage: 3500,
    tax_free_threshold: 3333,
    solidarity_threshold: 50000,
    family_deduction_per_dependent: 360,
    max_dependents: 6,
    overtime_rate: 1.25,
    weekend_rate: 1.5,
    holiday_rate: 2.0
  });
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (isOpen) {
      loadSettings();
    }
  }, [isOpen]);

  const loadSettings = async () => {
    try {
      const { data, error } = await supabase
        .from('payroll_config')
        .select('*')
        .eq('key', 'payroll_settings')
        .single();

      if (error && error.code !== 'PGRST116') throw error;
      
      if (data?.value && typeof data.value === 'object') {
        setSettings({ ...settings, ...(data.value as unknown as GeneralSettings) });
      }
    } catch (error: any) {
      console.error('Error loading settings:', error);
    }
  };

  const handleSave = async () => {
    setLoading(true);
    try {
      const { error } = await supabase
        .from('payroll_config')
        .upsert({
          key: 'payroll_settings',
          value: settings as any,
          description: 'Paramètres généraux de la paie',
          is_active: true
        }, {
          onConflict: 'key'
        });

      if (error) throw error;

      toast({
        title: "Succès",
        description: "Paramètres généraux sauvegardés"
      });

      onSave();
      onClose();
    } catch (error: any) {
      toast({
        title: "Erreur",
        description: error.message || "Erreur lors de la sauvegarde",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="max-w-4xl max-h-[80vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Paramètres Généraux de la Paie</DialogTitle>
        </DialogHeader>

        <div className="grid gap-6 py-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Pointage et Présence</CardTitle>
              <CardDescription>Configuration des règles de pointage</CardDescription>
            </CardHeader>
            <CardContent className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="pointage_window_hours">Fenêtre de pointage (heures)</Label>
                <Input
                  id="pointage_window_hours"
                  type="number"
                  step="0.5"
                  value={settings.pointage_window_hours}
                  onChange={(e) => setSettings(prev => ({ 
                    ...prev, 
                    pointage_window_hours: parseFloat(e.target.value) || 0 
                  }))}
                />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">Plafonds et Seuils</CardTitle>
              <CardDescription>Montants de référence en MAD</CardDescription>
            </CardHeader>
            <CardContent className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="cnss_ceiling">Plafond CNSS (MAD)</Label>
                <Input
                  id="cnss_ceiling"
                  type="number"
                  value={settings.cnss_ceiling}
                  onChange={(e) => setSettings(prev => ({ 
                    ...prev, 
                    cnss_ceiling: parseFloat(e.target.value) || 0 
                  }))}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="minimum_wage">SMIG mensuel (MAD)</Label>
                <Input
                  id="minimum_wage"
                  type="number"
                  value={settings.minimum_wage}
                  onChange={(e) => setSettings(prev => ({ 
                    ...prev, 
                    minimum_wage: parseFloat(e.target.value) || 0 
                  }))}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="tax_free_threshold">Seuil d'exonération IGR (MAD)</Label>
                <Input
                  id="tax_free_threshold"
                  type="number"
                  value={settings.tax_free_threshold}
                  onChange={(e) => setSettings(prev => ({ 
                    ...prev, 
                    tax_free_threshold: parseFloat(e.target.value) || 0 
                  }))}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="solidarity_threshold">Seuil solidarité (MAD/an)</Label>
                <Input
                  id="solidarity_threshold"
                  type="number"
                  value={settings.solidarity_threshold}
                  onChange={(e) => setSettings(prev => ({ 
                    ...prev, 
                    solidarity_threshold: parseFloat(e.target.value) || 0 
                  }))}
                />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">Déductions Familiales</CardTitle>
              <CardDescription>Configuration des charges de famille</CardDescription>
            </CardHeader>
            <CardContent className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="family_deduction_per_dependent">Déduction par personne à charge (MAD/an)</Label>
                <Input
                  id="family_deduction_per_dependent"
                  type="number"
                  value={settings.family_deduction_per_dependent}
                  onChange={(e) => setSettings(prev => ({ 
                    ...prev, 
                    family_deduction_per_dependent: parseFloat(e.target.value) || 0 
                  }))}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="max_dependents">Nombre maximum de personnes à charge</Label>
                <Input
                  id="max_dependents"
                  type="number"
                  value={settings.max_dependents}
                  onChange={(e) => setSettings(prev => ({ 
                    ...prev, 
                    max_dependents: parseInt(e.target.value) || 0 
                  }))}
                />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">Majorations</CardTitle>
              <CardDescription>Taux de majoration pour heures supplémentaires</CardDescription>
            </CardHeader>
            <CardContent className="grid grid-cols-3 gap-4">
              <div className="space-y-2">
                <Label htmlFor="overtime_rate">Heures supplémentaires</Label>
                <Input
                  id="overtime_rate"
                  type="number"
                  step="0.01"
                  value={settings.overtime_rate}
                  onChange={(e) => setSettings(prev => ({ 
                    ...prev, 
                    overtime_rate: parseFloat(e.target.value) || 0 
                  }))}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="weekend_rate">Week-end</Label>
                <Input
                  id="weekend_rate"
                  type="number"
                  step="0.01"
                  value={settings.weekend_rate}
                  onChange={(e) => setSettings(prev => ({ 
                    ...prev, 
                    weekend_rate: parseFloat(e.target.value) || 0 
                  }))}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="holiday_rate">Jours fériés</Label>
                <Input
                  id="holiday_rate"
                  type="number"
                  step="0.01"
                  value={settings.holiday_rate}
                  onChange={(e) => setSettings(prev => ({ 
                    ...prev, 
                    holiday_rate: parseFloat(e.target.value) || 0 
                  }))}
                />
              </div>
            </CardContent>
          </Card>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            Annuler
          </Button>
          <Button onClick={handleSave} disabled={loading}>
            {loading ? "Sauvegarde..." : "Sauvegarder"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
};

export default GeneralSettingsModal;