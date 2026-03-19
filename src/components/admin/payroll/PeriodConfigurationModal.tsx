import React, { useState, useEffect } from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { supabase } from '@/integrations/supabase/client';
import { useToast } from '@/hooks/use-toast';

interface PayrollPeriod {
  id: string;
  year: number;
  month: number;
  start_date: string;
  end_date: string;
  payday: string | null;
  status: string;
  window_config: any;
}

interface PeriodConfigurationModalProps {
  isOpen: boolean;
  onClose: () => void;
  period: PayrollPeriod | null;
  onSave: () => void;
}

interface WindowConfig {
  type: 'fixed_day' | 'last_working_day';
  day?: number;
}

export const PeriodConfigurationModal: React.FC<PeriodConfigurationModalProps> = ({
  isOpen,
  onClose,
  period,
  onSave
}) => {
  const { toast } = useToast();
  const [loading, setLoading] = useState(false);
  const [windowConfig, setWindowConfig] = useState<WindowConfig>({
    type: 'fixed_day',
    day: 25
  });
  const [payday, setPayday] = useState<string>('');

  useEffect(() => {
    if (period && isOpen) {
      // Charger la configuration actuelle
      setWindowConfig(period.window_config || { type: 'fixed_day', day: 25 });
      setPayday(period.payday || '');
    }
  }, [period, isOpen]);

  const handleSave = async () => {
    if (!period) return;

    setLoading(true);
    try {
      const { error } = await supabase
        .from('payroll_periods')
        .update({ 
          window_config: windowConfig as any,
          payday: payday || null
        })
        .eq('id', period.id);

      if (error) throw error;

      toast({
        title: "Succès",
        description: "Configuration de la période mise à jour",
      });

      onSave();
      onClose();
    } catch (error: any) {
      toast({
        title: "Erreur",
        description: error.message || "Impossible de sauvegarder la configuration",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const getLastWorkingDay = (year: number, month: number) => {
    const lastDay = new Date(year, month, 0);
    while (lastDay.getDay() === 0 || lastDay.getDay() === 6) {
      lastDay.setDate(lastDay.getDate() - 1);
    }
    return lastDay.getDate();
  };

  const calculatePayday = () => {
    if (!period) return '';
    
    if (windowConfig.type === 'last_working_day') {
      const lastWorkingDay = getLastWorkingDay(period.year, period.month);
      return `${period.year}-${period.month.toString().padStart(2, '0')}-${lastWorkingDay.toString().padStart(2, '0')}`;
    } else if (windowConfig.day) {
      return `${period.year}-${period.month.toString().padStart(2, '0')}-${windowConfig.day.toString().padStart(2, '0')}`;
    }
    return '';
  };

  useEffect(() => {
    const calculatedPayday = calculatePayday();
    setPayday(calculatedPayday);
  }, [windowConfig, period]);

  if (!period) return null;

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="sm:max-w-[500px]">
        <DialogHeader>
          <DialogTitle>
            Configuration de la période {period.month}/{period.year}
          </DialogTitle>
        </DialogHeader>

        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Informations de la période</CardTitle>
              <CardDescription>
                Détails de la période de paie
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label>Date de début</Label>
                  <Input value={period.start_date} disabled />
                </div>
                <div>
                  <Label>Date de fin</Label>
                  <Input value={period.end_date} disabled />
                </div>
              </div>
              <div>
                <Label>Statut</Label>
                <Input value={period.status} disabled />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Configuration du jour de paie</CardTitle>
              <CardDescription>
                Définir quand les salaires sont versés
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <Label>Type de jour de paie</Label>
                <Select 
                  value={windowConfig.type} 
                  onValueChange={(value: 'fixed_day' | 'last_working_day') => 
                    setWindowConfig(prev => ({ ...prev, type: value }))
                  }
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="fixed_day">Jour fixe du mois</SelectItem>
                    <SelectItem value="last_working_day">Dernier jour ouvrable</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              {windowConfig.type === 'fixed_day' && (
                <div>
                  <Label>Jour du mois (1-31)</Label>
                  <Input
                    type="number"
                    min="1"
                    max="31"
                    value={windowConfig.day || ''}
                    onChange={(e) => 
                      setWindowConfig(prev => ({ 
                        ...prev, 
                        day: parseInt(e.target.value) || undefined 
                      }))
                    }
                  />
                </div>
              )}

              <div>
                <Label>Date de paie calculée</Label>
                <Input value={payday} disabled />
              </div>
            </CardContent>
          </Card>
        </div>

        <div className="flex justify-end space-x-2">
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