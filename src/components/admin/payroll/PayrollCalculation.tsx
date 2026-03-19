import React, { useState, useEffect } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Calculator, Users, Clock, DollarSign, AlertCircle, Eye, Settings } from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { useToast } from "@/hooks/use-toast";
import { useCurrentProfile } from "@/hooks/useCurrentProfile";
import PayrollPreview from './PayrollPreview';

interface PayrollPeriod {
  id: string;
  year: number;
  month: number;
  status: string;
}

interface Segment {
  id: string;
  nom: string;
}

const PayrollCalculation = () => {
  const [periods, setPeriods] = useState<PayrollPeriod[]>([]);
  const [segments, setSegments] = useState<Segment[]>([]);
  const [selectedPeriod, setSelectedPeriod] = useState<string>('');
  const [selectedSegment, setSelectedSegment] = useState<string>('all');
  const [calculating, setCalculating] = useState(false);
  const [loading, setLoading] = useState(true);
  const [currentTab, setCurrentTab] = useState('config');
  const { toast } = useToast();
  const { data: currentProfile } = useCurrentProfile();

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      const [periodsResult, segmentsResult] = await Promise.all([
        supabase
          .from('payroll_periods')
          .select('id, year, month, status')
          .in('status', ['draft', 'active', 'validated'])
          .order('year', { ascending: false })
          .order('month', { ascending: false }),
        
        supabase
          .from('segments')
          .select('id, nom')
          .order('nom')
      ]);

      if (periodsResult.error) throw periodsResult.error;
      if (segmentsResult.error) throw segmentsResult.error;

      setPeriods(periodsResult.data || []);
      setSegments(segmentsResult.data || []);
      
      // Auto-select the first available period
      if (periodsResult.data && periodsResult.data.length > 0) {
        setSelectedPeriod(periodsResult.data[0].id);
      }
    } catch (error: any) {
      toast({
        title: "Erreur",
        description: "Impossible de charger les données",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const startCalculation = async (selectedEmployees?: string[]) => {
    if (!selectedPeriod) {
      toast({
        title: "Erreur",
        description: "Veuillez sélectionner une période",
        variant: "destructive"
      });
      return;
    }

    if (!currentProfile?.user_id) {
      toast({
        title: "Erreur",
        description: "Utilisateur non authentifié",
        variant: "destructive"
      });
      return;
    }

    // Annuler le calcul précédent s'il existe
    if (calculating) {
      console.log('Annulation du calcul en cours...');
      toast({
        title: "Calcul précédent annulé",
        description: "Le calcul précédent a été interrompu pour lancer le nouveau calcul",
        variant: "default"
      });
    }

    setCalculating(true);
    
    try {
      // Try multiple payroll functions in order of preference
      let data, error;
      
      console.log('Tentative de calcul de paie...');
      
      // First try the new payroll-calculate function
      try {
        console.log('Appel de payroll-calculate...');
        const calcResult = await supabase.functions.invoke('payroll-calculate', {
          body: {
            periodId: selectedPeriod,
            segmentId: selectedSegment === 'all' ? null : selectedSegment,
            scope: selectedEmployees ? 'employees' : (selectedSegment === 'all' ? 'all' : 'segment'),
            selectedEmployees: selectedEmployees || [],
            requestingUserId: currentProfile.user_id
          }
        });
        
        if (!calcResult.error) {
          data = calcResult.data;
          error = calcResult.error;
          console.log('Succès avec payroll-calculate');
        } else {
          throw new Error('payroll-calculate failed');
        }
      } catch (calcError) {
        console.log('payroll-calculate non disponible, tentative avec payroll-test-engine...');
        
        // Fallback to payroll-test-engine with correct action
        const testResult = await supabase.functions.invoke('payroll-test-engine', {
          body: {
            testType: 'payroll_calculation',
            testData: {
              periodId: selectedPeriod,
              segmentId: selectedSegment === 'all' ? null : selectedSegment,
              scope: selectedEmployees ? 'employees' : (selectedSegment === 'all' ? 'all' : 'segment'),
              selectedEmployees: selectedEmployees || [],
              requestingUserId: currentProfile.user_id
            }
          }
        });
        
        data = testResult.data;
        error = testResult.error;
        console.log('Tentative avec payroll-test-engine terminée');
      }

      if (error) throw error;

      // Afficher les détails du calcul dans le toast
      const summary = data.summary || {};
      const deductionsInfo = summary.disabled_deductions ? 
        `Retenues désactivées: CNSS=${summary.disabled_deductions.cnss ? 'NON' : 'OUI'}, AMO=${summary.disabled_deductions.amo ? 'NON' : 'OUI'}, IGR=${summary.disabled_deductions.igr ? 'NON' : 'OUI'}` :
        'Détails des retenues non disponibles';

      toast({
        title: "Calcul terminé avec succès",
        description: `Paie calculée pour ${data.results?.length || data.processedEmployees || 0} employés. Total brut: ${summary.total_gross?.toFixed(2) || 'N/A'} MAD, Total net: ${summary.total_net?.toFixed(2) || 'N/A'} MAD. ${deductionsInfo}`,
      });

      // Passer à l'onglet de prévisualisation après calcul
      setCurrentTab('preview');

    } catch (error: any) {
      toast({
        title: "Erreur de calcul",
        description: error.message || "Erreur lors du calcul de paie",
        variant: "destructive"
      });
    } finally {
      setCalculating(false);
    }
  };

  const generatePayrollPDF = async (selectedEmployees: string[]) => {
    if (selectedEmployees.length === 0) {
      toast({
        title: "Attention",
        description: "Aucun employé sélectionné pour la génération PDF",
        variant: "destructive"
      });
      return;
    }

    try {
      // TODO: Implémenter la génération PDF
      toast({
        title: "En cours de développement",
        description: "La génération PDF sera bientôt disponible",
      });
    } catch (error) {
      console.error('Erreur lors de la génération PDF:', error);
      toast({
        title: "Erreur",
        description: "Erreur lors de la génération PDF",
        variant: "destructive"
      });
    }
  };

  const formatMonth = (month: number) => {
    const months = [
      'Janvier', 'Février', 'Mars', 'Avril', 'Mai', 'Juin',
      'Juillet', 'Août', 'Septembre', 'Octobre', 'Novembre', 'Décembre'
    ];
    return months[month - 1];
  };

  if (loading) {
    return <div className="flex justify-center p-8">Chargement...</div>;
  }

  if (periods.length === 0) {
    return (
      <Card>
        <CardContent className="p-8 text-center">
          <AlertCircle className="h-12 w-12 mx-auto text-orange-500 mb-4" />
          <h3 className="text-lg font-semibold mb-2">Aucune période disponible</h3>
          <p className="text-muted-foreground">
            Créez d'abord une période de paie dans l'onglet "Périodes" avant de lancer les calculs.
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2 mb-6">
        <Calculator className="h-6 w-6 text-blue-600" />
        <h4 className="text-lg font-semibold">Calcul de Paie</h4>
      </div>

      <Tabs value={currentTab} onValueChange={setCurrentTab} className="w-full">
        <TabsList className="grid w-full grid-cols-2">
          <TabsTrigger value="config" className="flex items-center gap-2">
            <Settings className="h-4 w-4" />
            Configuration
          </TabsTrigger>
          <TabsTrigger value="preview" className="flex items-center gap-2">
            <Eye className="h-4 w-4" />
            Prévisualisation
          </TabsTrigger>
        </TabsList>

        <TabsContent value="config" className="mt-6">
          <Card>
            <CardHeader>
              <CardTitle>Configuration du Calcul</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium mb-2">
                    Période de paie
                  </label>
                  <Select value={selectedPeriod} onValueChange={setSelectedPeriod}>
                    <SelectTrigger>
                      <SelectValue placeholder="Sélectionnez une période" />
                    </SelectTrigger>
                    <SelectContent>
                      {periods.map((period) => (
                        <SelectItem key={period.id} value={period.id}>
                          <div className="flex items-center gap-2">
                            {formatMonth(period.month)} {period.year}
                            <Badge variant="outline" className="text-xs">
                              {period.status === 'draft' ? 'Brouillon' : 'Validé'}
                            </Badge>
                          </div>
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                <div>
                  <label className="block text-sm font-medium mb-2">
                    Segment
                  </label>
                  <Select value={selectedSegment} onValueChange={setSelectedSegment}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">Tous les segments</SelectItem>
                      {segments.map((segment) => (
                        <SelectItem key={segment.id} value={segment.id}>
                          {segment.nom}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <div className="bg-blue-50 p-4 rounded-lg">
                <h5 className="font-medium text-blue-900 mb-2">Calculs automatiques inclus :</h5>
                <ul className="text-sm text-blue-800 space-y-1">
                  <li>• Collecte automatique des pointages (fenêtre 19→19)</li>
                  <li>• Calcul des heures normales et supplémentaires (25%, 50%, 100%)</li>
                  <li>• Application des cotisations CNSS selon les barèmes 2025</li>
                  <li>• Calcul AMO (2,26% employé + 2,26% employeur + 1,85% solidarité)</li>
                  <li>• IGR avec déductions familles et arrondis réglementaires</li>
                  <li>• Crédit congés selon règle 191h (Maroc)</li>
                  <li>• NET arrondi au dirham supérieur</li>
                </ul>
              </div>

              <div className="flex gap-2">
                <Button 
                  onClick={() => startCalculation()} 
                  disabled={calculating || !selectedPeriod}
                  className="flex items-center gap-2"
                >
                  <Calculator className="h-4 w-4" />
                  {calculating ? 'Calcul en cours...' : 'Lancer le Calcul'}
                </Button>
                
                <Button 
                  onClick={() => setCurrentTab('preview')}
                  disabled={!selectedPeriod}
                  variant="outline"
                  className="flex items-center gap-2"
                >
                  <Eye className="h-4 w-4" />
                  Prévisualiser
                </Button>
                
                {calculating && (
                  <div className="flex items-center gap-2 text-sm text-muted-foreground">
                    <Clock className="h-4 w-4 animate-spin" />
                    Traitement des bulletins de paie...
                  </div>
                )}
              </div>
            </CardContent>
          </Card>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Card>
              <CardContent className="p-4">
                <div className="flex items-center gap-2">
                  <Users className="h-5 w-5 text-blue-600" />
                  <div>
                    <p className="text-sm font-medium">Employés actifs</p>
                    <p className="text-2xl font-bold text-blue-600">--</p>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="p-4">
                <div className="flex items-center gap-2">
                  <Clock className="h-5 w-5 text-green-600" />
                  <div>
                    <p className="text-sm font-medium">Heures pointées</p>
                    <p className="text-2xl font-bold text-green-600">--</p>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="p-4">
                <div className="flex items-center gap-2">
                  <DollarSign className="h-5 w-5 text-purple-600" />
                  <div>
                    <p className="text-sm font-medium">Masse salariale</p>
                    <p className="text-2xl font-bold text-purple-600">-- MAD</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="preview" className="mt-6">
          <PayrollPreview 
            periodId={selectedPeriod}
            segmentId={selectedSegment === 'all' ? null : selectedSegment}
            onCalculate={startCalculation}
            onGeneratePDF={generatePayrollPDF}
          />
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default PayrollCalculation;