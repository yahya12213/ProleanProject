import React, { useState, useEffect } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Calendar, Play, Check, Lock, Trash2 } from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { useToast } from "@/hooks/use-toast";
import PeriodSelector from "./PeriodSelector";
import DeleteConfirmModal from "./DeleteConfirmModal";
import { PeriodConfigurationModal } from "./PeriodConfigurationModal";
import { useCurrentProfile } from "@/hooks/useCurrentProfile";
import { useEnsureProfile } from "@/hooks/useEnsureProfile";

interface PayrollPeriod {
  id: string;
  segment_id: string | null;
  year: number;
  month: number;
  start_date: string;
  end_date: string;
  payday: string | null;
  status: string;
  window_config: any;
  created_at?: string;
  created_by?: string;
  updated_at?: string;
}

const PayrollPeriods = () => {
  const [periods, setPeriods] = useState<PayrollPeriod[]>([]);
  const [filteredPeriods, setFilteredPeriods] = useState<PayrollPeriod[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedYear, setSelectedYear] = useState<string>('all');
  const [availableYears, setAvailableYears] = useState<number[]>([]);
  const [deleteModalOpen, setDeleteModalOpen] = useState(false);
  const [periodToDelete, setPeriodToDelete] = useState<PayrollPeriod | null>(null);
  const [deleteLoading, setDeleteLoading] = useState(false);
  const [configureModalOpen, setConfigureModalOpen] = useState(false);
  const [periodToConfigure, setPeriodToConfigure] = useState<PayrollPeriod | null>(null);
  const [periodConfig, setPeriodConfig] = useState({
    start_day: 20,
    end_day: 19,
    payday_method: 'last_working_day' as 'last_working_day' | 'fixed_day'
  });
  const { toast } = useToast();
  const { data: currentProfile } = useCurrentProfile();
  const { ensureProfile, isEnsuring } = useEnsureProfile();

  useEffect(() => {
    loadPeriodConfig();
    fetchPeriods();
  }, []);

  useEffect(() => {
    filterPeriodsByYear();
  }, [periods, selectedYear]);

  const filterPeriodsByYear = () => {
    if (selectedYear === 'all') {
      setFilteredPeriods(periods);
    } else {
      const year = parseInt(selectedYear);
      setFilteredPeriods(periods.filter(period => period.year === year));
    }
  };

  const loadPeriodConfig = async () => {
    try {
      const { data, error } = await supabase
        .from('payroll_config')
        .select('value')
        .eq('key', 'period_defaults')
        .maybeSingle();

      if (error) throw error;

      if (data?.value) {
        const config = data.value as any;
        setPeriodConfig({
          start_day: config.start_day || 20,
          end_day: config.end_day || 19,
          payday_method: config.payday_method || 'last_working_day'
        });
      }
    } catch (error) {
      console.error('Erreur lors du chargement de la configuration des périodes:', error);
    }
  };

  const fetchPeriods = async () => {
    try {
      const { data, error } = await supabase
        .from('payroll_periods')
        .select('*')
        .order('year', { ascending: false })
        .order('month', { ascending: false });

      if (error) throw error;
      setPeriods(data || []);
      
      // Extract unique years for filter
      const years = [...new Set(data?.map(period => period.year) || [])].sort((a, b) => b - a);
      setAvailableYears(years);
    } catch (error: any) {
      toast({
        title: "Erreur",
        description: "Impossible de charger les périodes de paie",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const createNewPeriod = async (selectedYear?: number, selectedMonth?: number) => {
    try {
      // S'assurer que le profil utilisateur existe avant de créer une période
      const profileReady = await ensureProfile();
      if (!profileReady) {
        toast({
          title: "Erreur d'authentification",
          description: "Votre profil utilisateur n'est pas configuré correctement. Veuillez vous reconnecter.",
          variant: "destructive",
        });
        return;
      }

      const now = new Date();
      const year = selectedYear || now.getFullYear();
      const month = selectedMonth || now.getMonth() + 1;
      
      // Calculate period window based on configuration
      let startDate: Date;
      let endDate: Date;
      
      if (periodConfig.end_day < periodConfig.start_day) {
        // Period spans across months
        startDate = new Date(year, month - 2, periodConfig.start_day); // Previous month
        endDate = new Date(year, month - 1, periodConfig.end_day); // Current month
      } else {
        // Period within same month
        startDate = new Date(year, month - 1, periodConfig.start_day);
        endDate = new Date(year, month - 1, periodConfig.end_day);
      }
      
      const payday = periodConfig.payday_method === 'last_working_day' 
        ? getLastWorkingDay(year, month - 1)
        : new Date(year, month, periodConfig.end_day);

      // Vérifier si une période existe déjà pour cette année/mois
      const { data: existingPeriod, error: checkError } = await supabase
        .from('payroll_periods')
        .select('id')
        .eq('year', year)
        .eq('month', month)
        .maybeSingle();

      if (checkError) {
        toast({
          title: "Erreur",
          description: "Impossible de vérifier les périodes existantes",
          variant: "destructive"
        });
        return;
      }

      if (existingPeriod) {
        toast({
          title: "Période existante",
          description: `Une période existe déjà pour ${formatMonth(month)} ${year}`,
          variant: "destructive"
        });
        return;
      }

      const { data, error } = await supabase
        .from('payroll_periods')
        .insert({
          segment_id: null, // All segments by default
          year,
          month,
          start_date: startDate.toISOString().split('T')[0],
          end_date: endDate.toISOString().split('T')[0],
          payday: payday.toISOString().split('T')[0],
          status: 'active',
          window_config: { 
            type: 'configurable',
            start_day: periodConfig.start_day,
            end_day: periodConfig.end_day,
            payday_method: periodConfig.payday_method
          },
          created_by: (await supabase.auth.getUser()).data.user?.id
        })
        .select()
        .single();

      if (error) {
        console.error('Erreur lors de la création de la période:', error);
        
        // Messages d'erreur plus spécifiques
        let errorMessage = error.message;
        if (error.message.includes('row-level security policy')) {
          errorMessage = "Permissions insuffisantes. Votre profil utilisateur doit être configuré par un administrateur.";
        } else if (error.message.includes('duplicate key')) {
          errorMessage = "Cette période de paie existe déjà.";
        }
        
        toast({
          title: "Erreur",
          description: errorMessage,
          variant: "destructive"
        });
        return;
      }

      toast({
        title: "Succès",
        description: "Nouvelle période de paie créée",
      });

      fetchPeriods();
    } catch (error: any) {
      console.error('Exception lors de la création de la période:', error);
      toast({
        title: "Erreur",
        description: "Une erreur inattendue s'est produite. Veuillez réessayer.",
        variant: "destructive"
      });
    }
  };

  const handleDeletePeriod = (period: PayrollPeriod) => {
    setPeriodToDelete(period);
    setDeleteModalOpen(true);
  };

  const confirmDeletePeriod = async () => {
    if (!periodToDelete) return;

    setDeleteLoading(true);
    try {
      const { error } = await supabase
        .from('payroll_periods')
        .delete()
        .eq('id', periodToDelete.id);

      if (error) throw error;

      toast({
        title: "Succès",
        description: "Période supprimée avec succès",
      });

      fetchPeriods();
      setDeleteModalOpen(false);
      setPeriodToDelete(null);
    } catch (error: any) {
      toast({
        title: "Erreur",
        description: error.message || "Impossible de supprimer la période",
        variant: "destructive"
      });
    } finally {
      setDeleteLoading(false);
    }
  };

  const handleConfigurePeriod = async (period: PayrollPeriod) => {
    setPeriodToConfigure(period);
    setConfigureModalOpen(true);
  };

  const handleCalculatePeriod = async (period: PayrollPeriod) => {
    try {
      // Vérifier que la période est en statut active
      if (period.status !== 'active') {
        toast({
          title: "Erreur",
          description: "Seules les périodes actives peuvent être calculées",
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

      toast({
        title: "Calcul en cours",
        description: `Calcul de la paie pour ${formatMonth(period.month)} ${period.year}...`,
      });

      // Invoquer la fonction edge de calcul de paie
      const { data, error } = await supabase.functions.invoke('calculate-payroll', {
        body: { 
          periodId: period.id,
          segmentId: period.segment_id,
          scope: 'all' as const,
          requestingUserId: currentProfile.user_id
        }
      });

      if (error) throw error;

      toast({
        title: "Succès",
        description: "Calcul de paie terminé avec succès",
      });

      // Rafraîchir les périodes pour voir le changement de statut
      fetchPeriods();
    } catch (error: any) {
      toast({
        title: "Erreur",
        description: error.message || "Erreur lors du calcul de paie",
        variant: "destructive"
      });
    }
  };

  const handleClosePeriod = async (period: PayrollPeriod) => {
    try {
      const { error } = await supabase
        .from('payroll_periods')
        .update({ status: 'closed' })
        .eq('id', period.id);

      if (error) throw error;

      toast({
        title: "Succès",
        description: `Période ${formatMonth(period.month)} ${period.year} clôturée`,
      });

      fetchPeriods();
    } catch (error: any) {
      toast({
        title: "Erreur",
        description: error.message || "Impossible de clôturer la période",
        variant: "destructive"
      });
    }
  };

  const handleViewPeriod = (period: PayrollPeriod) => {
    toast({
      title: "Consultation",
      description: `Consultation de la période ${formatMonth(period.month)} ${period.year}`,
    });
    // TODO: Ouvrir vue de consultation
  };

  const getLastWorkingDay = (year: number, month: number) => {
    const lastDay = new Date(year, month + 1, 0);
    
    // Go back to find last working day (not Saturday or Sunday)
    while (lastDay.getDay() === 0 || lastDay.getDay() === 6) {
      lastDay.setDate(lastDay.getDate() - 1);
    }
    
    return lastDay;
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active': return 'bg-green-100 text-green-800';
      case 'validated': return 'bg-blue-100 text-blue-800';
      case 'closed': return 'bg-gray-100 text-gray-800';
      default: return 'bg-orange-100 text-orange-800';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'active': return <Play className="h-4 w-4" />;
      case 'validated': return <Check className="h-4 w-4" />;
      case 'closed': return <Lock className="h-4 w-4" />;
      default: return null;
    }
  };

  const getStatusLabel = (status: string) => {
    switch (status) {
      case 'active': return 'Active';
      case 'validated': return 'Validé';
      case 'closed': return 'Clôturé';
      default: return status;
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

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h4 className="text-lg font-semibold">Périodes de Paie</h4>
        <div className="flex items-center gap-4">
          <Select value={selectedYear} onValueChange={setSelectedYear}>
            <SelectTrigger className="w-40">
              <SelectValue placeholder="Filtrer par année" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">Toutes les années</SelectItem>
              {availableYears.map(year => (
                <SelectItem key={year} value={year.toString()}>
                  {year}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <PeriodSelector onCreatePeriod={createNewPeriod} />
        </div>
      </div>

      <div className="grid gap-4">
        {filteredPeriods.length === 0 ? (
          <Card>
            <CardContent className="p-8 text-center">
              <Calendar className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
              <p className="text-muted-foreground">Aucune période de paie trouvée</p>
              <p className="text-sm text-muted-foreground">
                Créez votre première période pour commencer les calculs de paie
              </p>
            </CardContent>
          </Card>
        ) : (
          filteredPeriods.map((period) => (
            <Card key={period.id}>
              <CardHeader>
                <div className="flex justify-between items-center">
                  <CardTitle className="flex items-center gap-2">
                    <Calendar className="h-5 w-5" />
                    {formatMonth(period.month)} {period.year}
                  </CardTitle>
                  <Badge className={getStatusColor(period.status)}>
                    <div className="flex items-center gap-1">
                      {getStatusIcon(period.status)}
                      {getStatusLabel(period.status)}
                    </div>
                  </Badge>
                </div>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                  <div>
                    <span className="font-medium">Période de pointage:</span>
                    <p className="text-muted-foreground">
                      {new Date(period.start_date).toLocaleDateString('fr-FR')} au{' '}
                      {new Date(period.end_date).toLocaleDateString('fr-FR')}
                    </p>
                  </div>
                  <div>
                    <span className="font-medium">Date de paie:</span>
                    <p className="text-muted-foreground">
                      {period.payday ? new Date(period.payday).toLocaleDateString('fr-FR') : 'Non définie'}
                    </p>
                  </div>
                  <div>
                    <span className="font-medium">Fenêtre:</span>
                    <p className="text-muted-foreground">
                      {period.window_config.type === 'configurable' 
                        ? `Du ${period.window_config.start_day} au ${period.window_config.end_day}`
                        : `Du ${period.window_config.day} au ${period.window_config.day}`
                      }
                    </p>
                  </div>
                </div>
                
                <div className="flex justify-between items-center mt-4">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => handleDeletePeriod(period)}
                    className="text-destructive hover:bg-destructive/10"
                  >
                    <Trash2 className="h-4 w-4 mr-1" />
                    Supprimer
                  </Button>
                  
                  <div className="flex gap-2">
                    {period.status === 'active' && (
                      <>
                        <Button 
                          variant="outline" 
                          size="sm"
                          onClick={() => handleConfigurePeriod(period)}
                        >
                          Configurer
                        </Button>
                        <Button 
                          size="sm"
                          onClick={() => handleCalculatePeriod(period)}
                        >
                          Calculer
                        </Button>
                      </>
                    )}
                    {period.status === 'validated' && (
                      <Button 
                        size="sm"
                        onClick={() => handleClosePeriod(period)}
                      >
                        Clôturer
                      </Button>
                    )}
                    {period.status === 'closed' && (
                      <Button 
                        variant="outline" 
                        size="sm"
                        onClick={() => handleViewPeriod(period)}
                      >
                        Consulter
                      </Button>
                    )}
                  </div>
                </div>
              </CardContent>
            </Card>
          ))
        )}
      </div>

      <DeleteConfirmModal
        isOpen={deleteModalOpen}
        onClose={() => {
          setDeleteModalOpen(false);
          setPeriodToDelete(null);
        }}
        onConfirm={confirmDeletePeriod}
        title={`Supprimer la période ${periodToDelete ? formatMonth(periodToDelete.month) + ' ' + periodToDelete.year : ''}`}
        description="Cette action supprimera définitivement cette période de paie. Assurez-vous qu'aucun calcul n'est associé à cette période."
        loading={deleteLoading}
      />

      <PeriodConfigurationModal
        isOpen={configureModalOpen}
        onClose={() => {
          setConfigureModalOpen(false);
          setPeriodToConfigure(null);
        }}
        period={periodToConfigure}
        onSave={() => {
          fetchPeriods();
          toast({
            title: "Succès",
            description: "Configuration mise à jour avec succès",
          });
        }}
      />
    </div>
  );
};

export default PayrollPeriods;