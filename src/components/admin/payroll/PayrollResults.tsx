import React, { useState, useEffect } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { FileText, Download, Eye, Search } from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { useToast } from "@/hooks/use-toast";

interface PayrollResult {
  id: string;
  profile_id: string;
  gross_pay: number;
  net_pay: number;
  cnss_employee: number;
  amo_employee: number;
  igr_amount: number;
  worked_hours: number;
  overtime_hours: number;
  profiles: {
    nom: string;
    prenom: string;
    poste: string;
  };
}

interface PayrollPeriod {
  id: string;
  year: number;
  month: number;
  status: string;
}

const PayrollResults = () => {
  const [periods, setPeriods] = useState<PayrollPeriod[]>([]);
  const [results, setResults] = useState<PayrollResult[]>([]);
  const [selectedPeriod, setSelectedPeriod] = useState<string>('');
  const [loading, setLoading] = useState(true);
  const [loadingResults, setLoadingResults] = useState(false);
  const { toast } = useToast();

  useEffect(() => {
    loadPeriods();
  }, []);

  useEffect(() => {
    if (selectedPeriod) {
      loadResults();
    }
  }, [selectedPeriod]);

  const loadPeriods = async () => {
    try {
      const { data, error } = await supabase
        .from('payroll_periods')
        .select('id, year, month, status')
        .in('status', ['validated', 'closed'])
        .order('year', { ascending: false })
        .order('month', { ascending: false });

      if (error) throw error;
      
      setPeriods(data || []);
      if (data && data.length > 0) {
        setSelectedPeriod(data[0].id);
      }
    } catch (error: any) {
      toast({
        title: "Erreur",
        description: "Impossible de charger les périodes",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const loadResults = async () => {
    if (!selectedPeriod) return;
    
    setLoadingResults(true);
    try {
      const { data, error } = await supabase
        .from('payroll_results')
        .select(`
          id,
          profile_id,
          gross_pay,
          net_pay,
          cnss_employee,
          amo_employee,
          igr_amount,
          worked_hours,
          overtime_hours,
          profiles:profile_id (
            nom,
            prenom,
            poste
          )
        `)
        .eq('period_id', selectedPeriod)
        .order('profiles(nom)');

      if (error) throw error;
      setResults(data || []);
    } catch (error: any) {
      toast({
        title: "Erreur",
        description: "Impossible de charger les résultats",
        variant: "destructive"
      });
    } finally {
      setLoadingResults(false);
    }
  };

  const formatCurrency = (amount: number) => {
    return new Intl.NumberFormat('fr-MA', {
      style: 'currency',
      currency: 'MAD',
      minimumFractionDigits: 0,
      maximumFractionDigits: 0
    }).format(amount);
  };

  const formatMonth = (month: number) => {
    const months = [
      'Janvier', 'Février', 'Mars', 'Avril', 'Mai', 'Juin',
      'Juillet', 'Août', 'Septembre', 'Octobre', 'Novembre', 'Décembre'
    ];
    return months[month - 1];
  };

  const getTotalStats = () => {
    const totalGross = results.reduce((sum, r) => sum + r.gross_pay, 0);
    const totalNet = results.reduce((sum, r) => sum + r.net_pay, 0);
    const totalCnss = results.reduce((sum, r) => sum + r.cnss_employee, 0);
    const totalIgr = results.reduce((sum, r) => sum + r.igr_amount, 0);
    const totalHours = results.reduce((sum, r) => sum + r.worked_hours, 0);

    return { totalGross, totalNet, totalCnss, totalIgr, totalHours };
  };

  const stats = getTotalStats();

  if (loading) {
    return <div className="flex justify-center p-8">Chargement...</div>;
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div className="flex items-center gap-2">
          <FileText className="h-6 w-6 text-green-600" />
          <h4 className="text-lg font-semibold">Bulletins de Paie</h4>
        </div>
        
        <div className="flex gap-2">
          <Button variant="outline" className="flex items-center gap-2">
            <Download className="h-4 w-4" />
            Exporter Tout
          </Button>
        </div>
      </div>

      <div className="flex items-center gap-4">
        <div className="flex-1 max-w-md">
          <Select value={selectedPeriod} onValueChange={setSelectedPeriod}>
            <SelectTrigger>
              <SelectValue placeholder="Sélectionnez une période" />
            </SelectTrigger>
            <SelectContent>
              {periods.map((period) => (
                <SelectItem key={period.id} value={period.id}>
                  {formatMonth(period.month)} {period.year}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        
        {selectedPeriod && (
          <Badge variant="outline">
            {results.length} bulletins
          </Badge>
        )}
      </div>

      {selectedPeriod && (
        <>
          {/* Summary Cards */}
          <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
            <Card>
              <CardContent className="p-4">
                <div className="text-center">
                  <p className="text-sm font-medium text-muted-foreground">Masse Brute</p>
                  <p className="text-2xl font-bold text-blue-600">
                    {formatCurrency(stats.totalGross)}
                  </p>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="p-4">
                <div className="text-center">
                  <p className="text-sm font-medium text-muted-foreground">Masse Nette</p>
                  <p className="text-2xl font-bold text-green-600">
                    {formatCurrency(stats.totalNet)}
                  </p>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="p-4">
                <div className="text-center">
                  <p className="text-sm font-medium text-muted-foreground">CNSS Total</p>
                  <p className="text-2xl font-bold text-orange-600">
                    {formatCurrency(stats.totalCnss)}
                  </p>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="p-4">
                <div className="text-center">
                  <p className="text-sm font-medium text-muted-foreground">IGR Total</p>
                  <p className="text-2xl font-bold text-purple-600">
                    {formatCurrency(stats.totalIgr)}
                  </p>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="p-4">
                <div className="text-center">
                  <p className="text-sm font-medium text-muted-foreground">Heures Total</p>
                  <p className="text-2xl font-bold text-cyan-600">
                    {stats.totalHours.toFixed(1)}h
                  </p>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Results Table */}
          <Card>
            <CardHeader>
              <CardTitle>Détail des Bulletins</CardTitle>
            </CardHeader>
            <CardContent>
              {loadingResults ? (
                <div className="text-center py-8">Chargement des résultats...</div>
              ) : results.length === 0 ? (
                <div className="text-center py-8 text-muted-foreground">
                  Aucun bulletin trouvé pour cette période
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b">
                        <th className="text-left p-2 font-medium">Employé</th>
                        <th className="text-left p-2 font-medium">Poste</th>
                        <th className="text-right p-2 font-medium">Heures</th>
                        <th className="text-right p-2 font-medium">Brut</th>
                        <th className="text-right p-2 font-medium">CNSS</th>
                        <th className="text-right p-2 font-medium">IGR</th>
                        <th className="text-right p-2 font-medium">Net</th>
                        <th className="text-center p-2 font-medium">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {results.map((result) => (
                        <tr key={result.id} className="border-b hover:bg-muted/50">
                          <td className="p-2">
                            <div>
                              <p className="font-medium">
                                {result.profiles?.prenom} {result.profiles?.nom}
                              </p>
                            </div>
                          </td>
                          <td className="p-2 text-sm text-muted-foreground">
                            {result.profiles?.poste || 'Non défini'}
                          </td>
                          <td className="p-2 text-right">
                            <div className="text-sm">
                              <div>{result.worked_hours}h</div>
                              {result.overtime_hours > 0 && (
                                <div className="text-orange-600">+{result.overtime_hours}h sup</div>
                              )}
                            </div>
                          </td>
                          <td className="p-2 text-right font-medium">
                            {formatCurrency(result.gross_pay)}
                          </td>
                          <td className="p-2 text-right text-orange-600">
                            -{formatCurrency(result.cnss_employee)}
                          </td>
                          <td className="p-2 text-right text-purple-600">
                            -{formatCurrency(result.igr_amount)}
                          </td>
                          <td className="p-2 text-right font-bold text-green-600">
                            {formatCurrency(result.net_pay)}
                          </td>
                          <td className="p-2 text-center">
                            <div className="flex gap-1 justify-center">
                              <Button size="sm" variant="outline">
                                <Eye className="h-4 w-4" />
                              </Button>
                              <Button size="sm" variant="outline">
                                <Download className="h-4 w-4" />
                              </Button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
};

export default PayrollResults;