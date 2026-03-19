import React, { useState, useEffect } from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Separator } from '@/components/ui/separator';
import { Calendar, Clock, AlertCircle } from 'lucide-react';
import { supabase } from '@/integrations/supabase/client';
import { toast } from 'sonner';

interface PeriodConfig {
  period_type: 'fixed' | 'variable';
  start_day: number;
  end_day: number;
  payday_method: 'last_working_day' | 'fixed_day';
  payday_day?: number;
}

interface PeriodSettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSave: () => void;
}

export const PeriodSettingsModal: React.FC<PeriodSettingsModalProps> = ({
  isOpen,
  onClose,
  onSave
}) => {
  const [config, setConfig] = useState<PeriodConfig>({
    period_type: 'fixed',
    start_day: 20,
    end_day: 19,
    payday_method: 'last_working_day',
    payday_day: undefined
  });
  const [loading, setLoading] = useState(false);
  const [preview, setPreview] = useState<Array<{month: string, start: string, end: string, payday: string}>>([]);

  useEffect(() => {
    if (isOpen) {
      loadCurrentConfig();
    }
  }, [isOpen]);

  useEffect(() => {
    generatePreview();
  }, [config]);

  const loadCurrentConfig = async () => {
    try {
      const { data, error } = await supabase
        .from('payroll_config')
        .select('*')
        .eq('key', 'period_defaults')
        .maybeSingle();

      if (error) throw error;

      if (data?.value) {
        setConfig(data.value as unknown as PeriodConfig);
      }
    } catch (error) {
      console.error('Erreur lors du chargement de la configuration:', error);
    }
  };

  const generatePreview = () => {
    const now = new Date();
    const months = [];
    
    for (let i = 0; i < 3; i++) {
      const date = new Date(now.getFullYear(), now.getMonth() + i, 1);
      const year = date.getFullYear();
      const month = date.getMonth() + 1;
      
      // Calculer les dates de début et fin
      const startDate = new Date(year, month - 1, config.start_day);
      let endDate: Date;
      
      if (config.end_day < config.start_day) {
        // La période s'étend sur le mois suivant
        endDate = new Date(year, month, config.end_day);
      } else {
        endDate = new Date(year, month - 1, config.end_day);
      }
      
      // Calculer le jour de paie
      let payday: Date;
      if (config.payday_method === 'fixed_day' && config.payday_day) {
        payday = new Date(year, month, config.payday_day);
      } else {
        // Dernier jour ouvrable du mois
        payday = getLastWorkingDay(year, month);
      }
      
      months.push({
        month: date.toLocaleDateString('fr-FR', { month: 'long', year: 'numeric' }),
        start: startDate.toLocaleDateString('fr-FR'),
        end: endDate.toLocaleDateString('fr-FR'),
        payday: payday.toLocaleDateString('fr-FR')
      });
    }
    
    setPreview(months);
  };

  const getLastWorkingDay = (year: number, month: number): Date => {
    const lastDay = new Date(year, month, 0);
    while (lastDay.getDay() === 0 || lastDay.getDay() === 6) {
      lastDay.setDate(lastDay.getDate() - 1);
    }
    return lastDay;
  };

  const handleSave = async () => {
    setLoading(true);
    try {
      // Validation
      if (config.start_day < 1 || config.start_day > 31) {
        toast.error('Le jour de début doit être entre 1 et 31');
        return;
      }
      if (config.end_day < 1 || config.end_day > 31) {
        toast.error('Le jour de fin doit être entre 1 et 31');
        return;
      }
      if (config.payday_method === 'fixed_day' && (!config.payday_day || config.payday_day < 1 || config.payday_day > 31)) {
        toast.error('Le jour de paie doit être entre 1 et 31');
        return;
      }

      const { error } = await supabase
        .from('payroll_config')
        .upsert({
          key: 'period_defaults',
          value: config as any,
          description: 'Configuration par défaut des périodes de paie',
          is_active: true
        }, {
          onConflict: 'key'
        });

      if (error) throw error;

      toast.success('Configuration des périodes sauvegardée');
      onSave();
      onClose();
    } catch (error) {
      console.error('Erreur lors de la sauvegarde:', error);
      toast.error('Erreur lors de la sauvegarde de la configuration');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Calendar className="h-5 w-5" />
            Configuration des Périodes de Paie
          </DialogTitle>
        </DialogHeader>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Configuration */}
          <div className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="text-lg">Paramètres Généraux</CardTitle>
                <CardDescription>
                  Définissez la méthode de calcul des périodes de paie
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <Label htmlFor="period_type">Type de Période</Label>
                  <Select
                    value={config.period_type}
                    onValueChange={(value: 'fixed' | 'variable') => 
                      setConfig(prev => ({ ...prev, period_type: value }))
                    }
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="fixed">Fixe (même période chaque mois)</SelectItem>
                      <SelectItem value="variable">Variable (personnalisable)</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label htmlFor="start_day">Jour de Début</Label>
                    <Input
                      id="start_day"
                      type="number"
                      min="1"
                      max="31"
                      value={config.start_day}
                      onChange={(e) => setConfig(prev => ({ 
                        ...prev, 
                        start_day: parseInt(e.target.value) || 1 
                      }))}
                    />
                  </div>
                  <div>
                    <Label htmlFor="end_day">Jour de Fin</Label>
                    <Input
                      id="end_day"
                      type="number"
                      min="1"
                      max="31"
                      value={config.end_day}
                      onChange={(e) => setConfig(prev => ({ 
                        ...prev, 
                        end_day: parseInt(e.target.value) || 1 
                      }))}
                    />
                  </div>
                </div>

                <div className="flex items-start gap-2 p-3 bg-blue-50 dark:bg-blue-950/30 rounded-md">
                  <AlertCircle className="h-4 w-4 text-blue-500 mt-0.5 flex-shrink-0" />
                  <div className="text-sm text-blue-700 dark:text-blue-300">
                    Si le jour de fin est inférieur au jour de début, la période s'étendra sur le mois suivant.
                    Exemple: du 20 au 19 = du 20 janvier au 19 février.
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-lg flex items-center gap-2">
                  <Clock className="h-4 w-4" />
                  Jour de Paie
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <Label>Méthode de Calcul</Label>
                  <Select
                    value={config.payday_method}
                    onValueChange={(value: 'last_working_day' | 'fixed_day') => 
                      setConfig(prev => ({ ...prev, payday_method: value }))
                    }
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="last_working_day">Dernier jour ouvrable du mois</SelectItem>
                      <SelectItem value="fixed_day">Jour fixe du mois</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                {config.payday_method === 'fixed_day' && (
                  <div>
                    <Label htmlFor="payday_day">Jour de Paie</Label>
                    <Input
                      id="payday_day"
                      type="number"
                      min="1"
                      max="31"
                      value={config.payday_day || ''}
                      onChange={(e) => setConfig(prev => ({ 
                        ...prev, 
                        payday_day: parseInt(e.target.value) || undefined 
                      }))}
                      placeholder="Ex: 30"
                    />
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Aperçu */}
          <div>
            <Card>
              <CardHeader>
                <CardTitle className="text-lg">Aperçu des Prochaines Périodes</CardTitle>
                <CardDescription>
                  Visualisez comment vos paramètres affectent les périodes
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {preview.map((period, index) => (
                    <div key={index} className="p-4 border rounded-lg">
                      <h4 className="font-semibold text-sm text-primary mb-2">
                        {period.month}
                      </h4>
                      <div className="space-y-1 text-sm">
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">Période:</span>
                          <span>Du {period.start} au {period.end}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">Jour de paie:</span>
                          <span className="font-medium">{period.payday}</span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>
        </div>

        <Separator />

        <div className="flex justify-end gap-2">
          <Button variant="outline" onClick={onClose}>
            Annuler
          </Button>
          <Button onClick={handleSave} disabled={loading}>
            {loading ? 'Sauvegarde...' : 'Sauvegarder'}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
};