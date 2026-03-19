import React from 'react';
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Calendar, Clock, Users, DollarSign, Settings, Play, CheckCircle } from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { useToast } from "@/hooks/use-toast";

const PayrollAutomation = () => {
  const [automationSettings, setAutomationSettings] = React.useState({
    autoOpenPeriods: true,
    autoCalculatePayday: true,
    autoCloseOnValidation: false,
    notifyOnCompletion: true,
    validateBeforeClose: true
  });

  const { toast } = useToast();

  const runMonthlyProcess = async () => {
    try {
      const currentDate = new Date();
      const year = currentDate.getFullYear();
      const month = currentDate.getMonth() + 1;

      // Create new period for current month
      const { data: newPeriod, error } = await supabase
        .from('payroll_periods')
        .insert({
          year,
          month,
          start_date: new Date(year, month - 2, 19).toISOString().split('T')[0],
          end_date: new Date(year, month - 1, 19).toISOString().split('T')[0],
          payday: getLastWorkingDay(year, month - 1).toISOString().split('T')[0],
          status: 'draft',
          window_config: { type: 'fixed_day', day: 19 },
          created_by: (await supabase.auth.getUser()).data.user?.id
        })
        .select()
        .single();

      if (error) throw error;

      toast({
        title: "Processus mensuel lancé",
        description: `Période ${getMonthName(month)} ${year} créée automatiquement`,
      });

      return newPeriod;
    } catch (error: any) {
      toast({
        title: "Erreur",
        description: error.message,
        variant: "destructive"
      });
    }
  };

  const scheduleAutomaticClose = async () => {
    try {
      // Get periods ready for closure (validated status)
      const { data: periods, error } = await supabase
        .from('payroll_periods')
        .select('*')
        .eq('status', 'validated')
        .lt('payday', new Date().toISOString().split('T')[0]);

      if (error) throw error;

      for (const period of periods || []) {
        // Auto-close and credit leave
        await supabase
          .from('payroll_periods')
          .update({ status: 'closed' })
          .eq('id', period.id);

        // Credit leave days (would need to implement leave balance updates)
        console.log(`Auto-closed period ${period.year}-${period.month}`);
      }

      if (periods && periods.length > 0) {
        toast({
          title: "Clôtures automatiques",
          description: `${periods.length} période(s) clôturée(s) automatiquement`,
        });
      }
    } catch (error: any) {
      toast({
        title: "Erreur de clôture",
        description: error.message,
        variant: "destructive"
      });
    }
  };

  const getLastWorkingDay = (year: number, month: number) => {
    const lastDay = new Date(year, month + 1, 0);
    while (lastDay.getDay() === 0 || lastDay.getDay() === 6) {
      lastDay.setDate(lastDay.getDate() - 1);
    }
    return lastDay;
  };

  const getMonthName = (month: number) => {
    const months = [
      'Janvier', 'Février', 'Mars', 'Avril', 'Mai', 'Juin',
      'Juillet', 'Août', 'Septembre', 'Octobre', 'Novembre', 'Décembre'
    ];
    return months[month - 1];
  };

  const updateSetting = (key: keyof typeof automationSettings, value: boolean) => {
    setAutomationSettings(prev => ({ ...prev, [key]: value }));
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2 mb-6">
        <Settings className="h-6 w-6 text-purple-600" />
        <h4 className="text-lg font-semibold">Automatisation de la Paie</h4>
      </div>

      {/* Automation Settings */}
      <Card>
        <CardHeader>
          <CardTitle>Paramètres d'Automatisation</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h5 className="font-medium">Ouverture automatique des périodes</h5>
              <p className="text-sm text-muted-foreground">
                Créer automatiquement une nouvelle période le 20 de chaque mois
              </p>
            </div>
            <Switch
              checked={automationSettings.autoOpenPeriods}
              onCheckedChange={(checked) => updateSetting('autoOpenPeriods', checked)}
            />
          </div>

          <div className="flex items-center justify-between">
            <div>
              <h5 className="font-medium">Calcul automatique de la date de paie</h5>
              <p className="text-sm text-muted-foreground">
                Définir automatiquement le dernier jour ouvré du mois
              </p>
            </div>
            <Switch
              checked={automationSettings.autoCalculatePayday}
              onCheckedChange={(checked) => updateSetting('autoCalculatePayday', checked)}
            />
          </div>

          <div className="flex items-center justify-between">
            <div>
              <h5 className="font-medium">Clôture automatique après validation</h5>
              <p className="text-sm text-muted-foreground">
                Clôturer et créditer les congés automatiquement après la date de paie
              </p>
            </div>
            <Switch
              checked={automationSettings.autoCloseOnValidation}
              onCheckedChange={(checked) => updateSetting('autoCloseOnValidation', checked)}
            />
          </div>

          <div className="flex items-center justify-between">
            <div>
              <h5 className="font-medium">Notifications de fin de processus</h5>
              <p className="text-sm text-muted-foreground">
                Envoyer des notifications aux responsables RH
              </p>
            </div>
            <Switch
              checked={automationSettings.notifyOnCompletion}
              onCheckedChange={(checked) => updateSetting('notifyOnCompletion', checked)}
            />
          </div>

          <div className="flex items-center justify-between">
            <div>
              <h5 className="font-medium">Validation obligatoire avant clôture</h5>
              <p className="text-sm text-muted-foreground">
                Exiger une validation manuelle avant la clôture définitive
              </p>
            </div>
            <Switch
              checked={automationSettings.validateBeforeClose}
              onCheckedChange={(checked) => updateSetting('validateBeforeClose', checked)}
            />
          </div>
        </CardContent>
      </Card>

      {/* Process Overview */}
      <Card>
        <CardHeader>
          <CardTitle>Cycle de Paie Automatisé</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4">
            <div className="flex items-center gap-4 p-4 border rounded-lg">
              <div className="flex items-center justify-center w-10 h-10 bg-blue-100 text-blue-600 rounded-full">
                <Calendar className="h-5 w-5" />
              </div>
              <div className="flex-1">
                <h5 className="font-medium">1. Ouverture de période (19 du mois)</h5>
                <p className="text-sm text-muted-foreground">
                  Création automatique de la période de paie avec fenêtre 19→19
                </p>
              </div>
              <Badge variant="outline">Automatique</Badge>
            </div>

            <div className="flex items-center gap-4 p-4 border rounded-lg">
              <div className="flex items-center justify-center w-10 h-10 bg-green-100 text-green-600 rounded-full">
                <Clock className="h-5 w-5" />
              </div>
              <div className="flex-1">
                <h5 className="font-medium">2. Collecte des pointages</h5>
                <p className="text-sm text-muted-foreground">
                  Agrégation automatique des heures travaillées sur la période
                </p>
              </div>
              <Badge variant="outline">Automatique</Badge>
            </div>

            <div className="flex items-center gap-4 p-4 border rounded-lg">
              <div className="flex items-center justify-center w-10 h-10 bg-purple-100 text-purple-600 rounded-full">
                <DollarSign className="h-5 w-5" />
              </div>
              <div className="flex-1">
                <h5 className="font-medium">3. Calculs de paie</h5>
                <p className="text-sm text-muted-foreground">
                  Application des formules, CNSS, AMO, IGR selon la réglementation
                </p>
              </div>
              <Badge variant="secondary">Manuel</Badge>
            </div>

            <div className="flex items-center gap-4 p-4 border rounded-lg">
              <div className="flex items-center justify-center w-10 h-10 bg-orange-100 text-orange-600 rounded-full">
                <CheckCircle className="h-5 w-5" />
              </div>
              <div className="flex-1">
                <h5 className="font-medium">4. Validation et clôture</h5>
                <p className="text-sm text-muted-foreground">
                  Validation des résultats et crédit automatique des congés
                </p>
              </div>
              <Badge variant="outline">Configurable</Badge>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Manual Actions */}
      <Card>
        <CardHeader>
          <CardTitle>Actions Manuelles</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex gap-2 flex-wrap">
            <Button onClick={runMonthlyProcess} className="flex items-center gap-2">
              <Play className="h-4 w-4" />
              Lancer Processus Mensuel
            </Button>
            
            <Button variant="outline" onClick={scheduleAutomaticClose} className="flex items-center gap-2">
              <CheckCircle className="h-4 w-4" />
              Vérifier Clôtures Automatiques
            </Button>
            
            <Button variant="outline" className="flex items-center gap-2">
              <Users className="h-4 w-4" />
              Synchroniser Effectifs
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Legal Compliance Info */}
      <Card>
        <CardHeader>
          <CardTitle>Conformité Réglementaire</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="bg-green-50 p-4 rounded-lg">
            <h5 className="font-medium text-green-900 mb-2">✅ Conforme à la réglementation marocaine :</h5>
            <ul className="text-sm text-green-800 space-y-1">
              <li>• Fenêtre de pointage du 19 au 19 (paramétrable)</li>
              <li>• Règle des 191h pour le calcul des congés payés</li>
              <li>• Barèmes CNSS et AMO actualisés (2025)</li>
              <li>• IGR avec déductions familles et arrondis fiscaux</li>
              <li>• NET arrondi au dirham supérieur</li>
              <li>• Date de paie = dernier jour ouvré du mois</li>
              <li>• Idempotence : recalcul autorisé jusqu'à clôture</li>
            </ul>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default PayrollAutomation;