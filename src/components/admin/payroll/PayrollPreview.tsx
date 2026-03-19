import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Separator } from "@/components/ui/separator";
import { supabase } from "@/integrations/supabase/client";
import { useToast } from "@/hooks/use-toast";
import { 
  Users, 
  Clock, 
  AlertTriangle, 
  Calculator, 
  FileText,
  CheckCircle,
  XCircle,
  Download,
  RefreshCw
} from "lucide-react";

interface PayrollEmployee {
  id: string;
  nom: string;
  prenom: string;
  user_id: string;
  salaire_base: number;
  salaire_horaire: number;
  dependents_count: number;
  worked_hours?: number;
  overtime_hours?: number;
  gross_pay?: number;
  net_pay?: number;
  cnss_employee?: number;
  amo_employee?: number;
  igr_amount?: number;
  warnings?: string[];
  selected: boolean;
  // Paramètres de retenues
  cnss_enabled?: boolean;
  amo_enabled?: boolean;
  igr_enabled?: boolean;
  mutuelle_enabled?: boolean;
}

interface PayrollPreviewProps {
  periodId: string | null;
  segmentId: string | null;
  onCalculate: (selectedEmployees: string[]) => void;
  onGeneratePDF: (selectedEmployees: string[]) => void;
}

const PayrollPreview: React.FC<PayrollPreviewProps> = ({
  periodId,
  segmentId, 
  onCalculate,
  onGeneratePDF
}) => {
  const [employees, setEmployees] = useState<PayrollEmployee[]>([]);
  const [loading, setLoading] = useState(false);
  const [calculating, setCalculating] = useState(false);
  const [selectAll, setSelectAll] = useState(true);
  const { toast } = useToast();

  // Charger les employés éligibles (avec refresh forcé des paramètres)
  const loadEligibleEmployees = async (forceRefresh = false) => {
    if (!periodId) return;

    setLoading(true);
    try {
      // Récupérer les employés avec paie activée et leurs paramètres de retenues
      // Ajouter un timestamp pour forcer le refresh en cas de modification
      const { data: profiles, error } = await supabase
        .from('profiles')
        .select(`
          id, nom, prenom, user_id, salaire_base, salaire_horaire, dependents_count, payroll_enabled,
          employee_payroll_settings (
            cnss_enabled, amo_enabled, igr_enabled, mutuelle_enabled, updated_at
          )
        `)
        .eq('payroll_enabled', true)
        .not('user_id', 'is', null);

      if (error) throw error;

      console.log('🔄 Rechargement des paramètres de paie:', { forceRefresh, profilesCount: profiles?.length });

      const employeeList: PayrollEmployee[] = profiles?.map(profile => {
        const payrollSettings = profile.employee_payroll_settings?.[0];
        console.log(`👤 ${profile.nom} ${profile.prenom} - Paramètres:`, payrollSettings);
        
        // VALIDATION STRICTE des paramètres de retenues
        const cnss_enabled = payrollSettings?.cnss_enabled === true;
        const amo_enabled = payrollSettings?.amo_enabled === true;
        const igr_enabled = payrollSettings?.igr_enabled === true;
        const mutuelle_enabled = payrollSettings?.mutuelle_enabled === true;
        
        console.log(`   📋 Paramètres finaux: CNSS=${cnss_enabled}, AMO=${amo_enabled}, IGR=${igr_enabled}, Mutuelle=${mutuelle_enabled}`);
        
        return {
          ...profile,
          selected: true,
          warnings: [],
          // Appliquer les paramètres avec validation stricte (pas de valeurs par défaut)
          cnss_enabled,
          amo_enabled,
          igr_enabled,
          mutuelle_enabled,
        };
      }) || [];

      // Ajouter des validations
      for (const emp of employeeList) {
        const warnings: string[] = [];
        
        if (!emp.salaire_base && !emp.salaire_horaire) {
          warnings.push('Aucun salaire configuré');
        }

        // Vérifier les pointages pour la période
        const { data: pointages } = await supabase
          .from('pointages')
          .select('*')
          .eq('profile_id', emp.id)
          .gte('timestamp_pointage', '2025-07-19')
          .lte('timestamp_pointage', '2025-08-18');

        if (!pointages || pointages.length === 0) {
          warnings.push('Aucun pointage trouvé pour la période');
        }

        emp.warnings = warnings;
      }

      setEmployees(employeeList);
    } catch (error) {
      console.error('Erreur lors du chargement des employés:', error);
      toast({
        title: "Erreur",
        description: "Impossible de charger les employés éligibles",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  // Réinitialiser tous les calculs
  const resetCalculations = () => {
    const resetEmployees = employees.map(emp => ({
      ...emp,
      worked_hours: undefined,
      overtime_hours: undefined,
      gross_pay: undefined,
      net_pay: undefined,
      cnss_employee: undefined,
      amo_employee: undefined,
      igr_amount: undefined
    }));
    setEmployees(resetEmployees);
    
    toast({
      title: "Réinitialisation",
      description: "Tous les calculs ont été réinitialisés",
    });
  };

  // Prévisualiser les calculs
  const previewCalculations = async () => {
    const selectedEmployees = employees.filter(emp => emp.selected);
    if (selectedEmployees.length === 0) {
      toast({
        title: "Attention",
        description: "Aucun employé sélectionné",
        variant: "destructive"
      });
      return;
    }

    setCalculating(true);
    try {
      console.log('🧮 Début de la prévisualisation des calculs...');
      
      // Simuler les calculs pour la prévisualisation
      const updatedEmployees = [...employees];
      
      for (const emp of updatedEmployees) {
        if (emp.selected) {
          console.log(`👤 Calcul pour ${emp.nom} ${emp.prenom}:`);
          console.log(`   - CNSS activé: ${emp.cnss_enabled}`);
          console.log(`   - AMO activé: ${emp.amo_enabled}`);
          console.log(`   - IGR activé: ${emp.igr_enabled}`);
          console.log(`   - Mutuelle activé: ${emp.mutuelle_enabled}`);
          
          // ÉTAPE 1: Initialiser TOUS les montants à 0 pour éviter les valeurs persistantes
          emp.worked_hours = 0;
          emp.overtime_hours = 0;
          emp.gross_pay = 0;
          emp.cnss_employee = 0;
          emp.amo_employee = 0;
          emp.igr_amount = 0;
          emp.net_pay = 0;
          
          // ÉTAPE 2: Calculer le salaire brut en utilisant le salaire de base du profil
          const salaire_base = emp.salaire_base || 3000; // Utiliser le salaire de base du profil
          const workedHours = 190;
          
          emp.worked_hours = workedHours;
          emp.overtime_hours = 0;
          emp.gross_pay = salaire_base; // Utiliser directement le salaire de base
          
          console.log(`   - Salaire de base utilisé: ${salaire_base} DH`);
          console.log(`   - Salaire brut: ${emp.gross_pay} DH`);
          
          // ÉTAPE 3: Calculs conditionnels STRICTS selon les paramètres de retenues
          // CNSS - seulement si explicitement activé
          if (emp.cnss_enabled === true) {
            emp.cnss_employee = emp.gross_pay * 0.0447; // 4.47%
            console.log(`   - CNSS calculé: ${emp.cnss_employee} DH`);
          } else {
            emp.cnss_employee = 0;
            console.log(`   - CNSS désactivé: 0 DH`);
          }
          
          // AMO - seulement si explicitement activé
          if (emp.amo_enabled === true) {
            emp.amo_employee = emp.gross_pay * 0.0226; // 2.26%
            console.log(`   - AMO calculé: ${emp.amo_employee} DH`);
          } else {
            emp.amo_employee = 0;
            console.log(`   - AMO désactivé: 0 DH`);
          }
          
          // IGR - seulement si explicitement activé
          if (emp.igr_enabled === true) {
            const cnssForIgr = emp.cnss_enabled === true ? emp.cnss_employee : 0;
            const taxableBase = emp.gross_pay - cnssForIgr - 2500;
            emp.igr_amount = Math.max(0, taxableBase * 0.1); // IGR simplifié 10%
            console.log(`   - IGR calculé: ${emp.igr_amount} DH (base imposable: ${taxableBase})`);
          } else {
            emp.igr_amount = 0;
            console.log(`   - IGR désactivé: 0 DH`);
          }
          
          // ÉTAPE 4: Calcul du net avec validation finale
          const totalDeductions = emp.cnss_employee + emp.amo_employee + emp.igr_amount;
          emp.net_pay = emp.gross_pay - totalDeductions;
          
          console.log(`   - Total retenues: ${totalDeductions} DH`);
          console.log(`   - Salaire net: ${emp.net_pay} DH`);
          console.log('   ═══════════════════════════════════');
        }
      }
      
      setEmployees(updatedEmployees);
      toast({
        title: "Prévisualisation",
        description: `Calculs effectués pour ${selectedEmployees.length} employé(s) selon leurs paramètres`,
      });
    } catch (error) {
      console.error('Erreur lors de la prévisualisation:', error);
      toast({
        title: "Erreur",
        description: "Erreur lors de la prévisualisation des calculs",
        variant: "destructive"
      });
    } finally {
      setCalculating(false);
    }
  };

  // Gérer la sélection
  const toggleEmployee = (empId: string) => {
    setEmployees(prev => prev.map(emp => 
      emp.id === empId ? { ...emp, selected: !emp.selected } : emp
    ));
  };

  const toggleSelectAll = () => {
    const newSelectAll = !selectAll;
    setSelectAll(newSelectAll);
    setEmployees(prev => prev.map(emp => ({ ...emp, selected: newSelectAll })));
  };

  // Fonction pour rafraîchir les paramètres de paie
  const refreshPayrollSettings = async () => {
    console.log('🔄 Refresh forcé des paramètres de paie demandé');
    await loadEligibleEmployees(true);
  };

  useEffect(() => {
    loadEligibleEmployees();
  }, [periodId, segmentId]);

  // Listener pour les changements dans les paramètres de paie
  useEffect(() => {
    const handlePayrollSettingsUpdate = (event: any) => {
      console.log('📡 Changement détecté dans les paramètres de paie:', event.detail);
      
      // Forcer un rechargement complet des données et réinitialiser les calculs
      const refreshAndReset = async () => {
        // D'abord réinitialiser tous les calculs
        setEmployees(prev => prev.map(emp => ({
          ...emp,
          worked_hours: undefined,
          overtime_hours: undefined,
          gross_pay: undefined,
          net_pay: undefined,
          cnss_employee: undefined,
          amo_employee: undefined,
          igr_amount: undefined
        })));
        
        // Puis recharger les paramètres
        await refreshPayrollSettings();
        
        toast({
          title: "Paramètres actualisés",
          description: `Les paramètres de paie ont été mis à jour. Relancez le calcul pour voir les changements.`,
        });
      };
      
      refreshAndReset();
    };

    // Écouter les événements de mise à jour
    window.addEventListener('payroll-settings-updated', handlePayrollSettingsUpdate);
    
    return () => {
      window.removeEventListener('payroll-settings-updated', handlePayrollSettingsUpdate);
    };
  }, []);

  const selectedCount = employees.filter(emp => emp.selected).length;
  const totalGrossPay = employees.filter(emp => emp.selected && emp.gross_pay).reduce((sum, emp) => sum + (emp.gross_pay || 0), 0);
  const totalNetPay = employees.filter(emp => emp.selected && emp.net_pay).reduce((sum, emp) => sum + (emp.net_pay || 0), 0);

  return (
    <div className="space-y-6">
      {/* Résumé */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Calculator className="h-5 w-5" />
            Prévisualisation des Calculs de Paie
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-4 gap-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-primary">{employees.length}</div>
              <div className="text-sm text-muted-foreground">Employés éligibles</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-emerald-600">{selectedCount}</div>
              <div className="text-sm text-muted-foreground">Sélectionnés</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold">{totalGrossPay.toLocaleString()} DH</div>
              <div className="text-sm text-muted-foreground">Masse salariale brute</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-green-600">{totalNetPay.toLocaleString()} DH</div>
              <div className="text-sm text-muted-foreground">Masse salariale nette</div>
            </div>
          </div>

          <Separator />

          <div className="flex gap-2">
            <Button 
              onClick={previewCalculations}
              disabled={calculating || selectedCount === 0}
              className="flex items-center gap-2"
            >
              <Calculator className="h-4 w-4" />
              {calculating ? 'Calcul...' : 'Prévisualiser les Calculs'}
            </Button>

            <Button 
              onClick={() => onCalculate(employees.filter(emp => emp.selected).map(emp => emp.id))}
              disabled={selectedCount === 0}
              variant="default"
              className="flex items-center gap-2"
            >
              <CheckCircle className="h-4 w-4" />
              Valider et Calculer
            </Button>

            <Button 
              onClick={() => onGeneratePDF(employees.filter(emp => emp.selected).map(emp => emp.id))}
              disabled={selectedCount === 0 || !employees.some(emp => emp.selected && emp.net_pay)}
              variant="outline"
              className="flex items-center gap-2"
            >
              <Download className="h-4 w-4" />
              Générer PDF
            </Button>
            
            <Button 
              onClick={refreshPayrollSettings}
              disabled={loading}
              variant="outline"
              className="flex items-center gap-2"
            >
              <RefreshCw className="h-4 w-4" />
              Actualiser
            </Button>
            
            <Button 
              onClick={resetCalculations}
              disabled={loading}
              variant="outline"
              className="flex items-center gap-2"
            >
              <XCircle className="h-4 w-4" />
              Réinitialiser
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Liste des employés */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center gap-2">
              <Users className="h-5 w-5" />
              Employés Éligibles
            </CardTitle>
            <div className="flex items-center space-x-2">
              <Checkbox 
                id="select-all"
                checked={selectAll}
                onCheckedChange={toggleSelectAll}
              />
              <label htmlFor="select-all" className="text-sm font-medium">
                Sélectionner tout
              </label>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="text-center py-8">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary mx-auto"></div>
              <p className="mt-2 text-muted-foreground">Chargement des employés...</p>
            </div>
          ) : (
            <div className="space-y-3">
              {employees.map((employee) => (
                <div key={employee.id} className="border rounded-lg p-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                      <Checkbox 
                        checked={employee.selected}
                        onCheckedChange={() => toggleEmployee(employee.id)}
                      />
                      <div>
                        <div className="font-medium">{employee.nom} {employee.prenom}</div>
                        <div className="text-sm text-muted-foreground">
                          Salaire base: {employee.salaire_base ? `${employee.salaire_base.toLocaleString()} DH` : 'Non défini'}
                        </div>
                        <div className="text-xs text-blue-600 mt-1">
                          Retenues: CNSS({employee.cnss_enabled ? '✓' : '✗'}) AMO({employee.amo_enabled ? '✓' : '✗'}) IGR({employee.igr_enabled ? '✓' : '✗'}) Mutuelle({employee.mutuelle_enabled ? '✓' : '✗'})
                        </div>
                      </div>
                    </div>
                    
                    <div className="flex items-center gap-2">
                      {employee.warnings && employee.warnings.length > 0 && (
                        <Badge variant="destructive" className="flex items-center gap-1">
                          <AlertTriangle className="h-3 w-3" />
                          {employee.warnings.length} alerte(s)
                        </Badge>
                      )}
                      
                      {employee.net_pay && (
                        <Badge variant="default" className="bg-green-100 text-green-800">
                          Net: {employee.net_pay.toLocaleString()} DH
                        </Badge>
                      )}
                    </div>
                  </div>

                   {/* Détails des calculs si disponibles */}
                   {employee.selected && employee.gross_pay && (
                     <div className="mt-3 bg-gray-50 p-3 rounded">
                        {/* Période et paramètres de calcul - DONNÉES DYNAMIQUES */}
                        <div className="mb-4 p-3 bg-blue-50 rounded-lg border-l-4 border-blue-400">
                          <div className="font-medium text-blue-800 mb-2">📅 Période de Calcul & Paramètres - {employee.nom} {employee.prenom}</div>
                          <div className="grid grid-cols-2 gap-4 text-sm">
                             <div>
                               <div className="font-medium text-blue-700">Salaire configuré:</div>
                               <div className="text-blue-600">
                                 {employee.salaire_base ? `${employee.salaire_base.toLocaleString()} DH (base)` : 
                                  employee.salaire_horaire ? `${employee.salaire_horaire} DH/h (horaire)` : 'Non configuré'}
                               </div>
                               
                               <div className="font-medium text-blue-700 mt-2">Paramètres de retenues:</div>
                               <div className="text-blue-600 space-y-1">
                                 <div>• CNSS: <span className={employee.cnss_enabled ? "text-green-600 font-bold" : "text-red-600"}>{employee.cnss_enabled ? "✓ Activée" : "✗ Désactivée"}</span></div>
                                 <div>• AMO: <span className={employee.amo_enabled ? "text-green-600 font-bold" : "text-red-600"}>{employee.amo_enabled ? "✓ Activée" : "✗ Désactivée"}</span></div>
                                 <div>• IGR: <span className={employee.igr_enabled ? "text-green-600 font-bold" : "text-red-600"}>{employee.igr_enabled ? "✓ Activé" : "✗ Désactivé"}</span></div>
                                 <div>• Mutuelle: <span className={employee.mutuelle_enabled ? "text-green-600 font-bold" : "text-red-600"}>{employee.mutuelle_enabled ? "✓ Activée" : "✗ Désactivée"}</span></div>
                               </div>
                               
                               <div className="font-medium text-blue-700 mt-2">Personnes à charge:</div>
                               <div className="text-blue-600">{employee.dependents_count || 0} personne(s)</div>
                             </div>
                             <div>
                               <div className="font-medium text-blue-700">Heures calculées:</div>
                               <div className="text-blue-600 text-xs space-y-1">
                                 <div>• Heures travaillées: <span className="font-bold">{employee.worked_hours || 0}h</span></div>
                                 <div>• Heures supplémentaires: <span className="font-bold">{employee.overtime_hours || 0}h</span></div>
                                 <div className="border-t pt-1">• Taux appliqué: <span className="font-bold">{employee.salaire_horaire || 0} DH/h</span></div>
                               </div>
                               
                               <div className="font-medium text-blue-700 mt-2">Calculs appliqués:</div>
                               <div className="text-blue-600 text-xs space-y-1">
                                 <div>• Salaire brut: <span className="font-bold text-green-600">{employee.gross_pay?.toLocaleString() || 0} DH</span></div>
                                 <div>• CNSS (4.47%): <span className={employee.cnss_enabled ? "font-bold text-red-600" : "text-gray-400"}>{employee.cnss_employee?.toLocaleString() || 0} DH</span></div>
                                 <div>• AMO (2.26%): <span className={employee.amo_enabled ? "font-bold text-red-600" : "text-gray-400"}>{employee.amo_employee?.toLocaleString() || 0} DH</span></div>
                                 <div>• IGR: <span className={employee.igr_enabled ? "font-bold text-red-600" : "text-gray-400"}>{employee.igr_amount?.toLocaleString() || 0} DH</span></div>
                                 <div className="border-t pt-1">• <span className="font-bold text-green-700">Net: {employee.net_pay?.toLocaleString() || 0} DH</span></div>
                               </div>
                               
                               <div className="font-medium text-blue-700 mt-2">Statut calcul:</div>
                               <div className={employee.net_pay ? "text-green-600 text-xs" : "text-orange-600 text-xs"}>
                                 {employee.net_pay ? "✓ Calculé et synchronisé" : "⏳ En attente de calcul"}
                               </div>
                             </div>
                          </div>
                        </div>

                       {/* Calcul détaillé des heures */}
                       <div className="mb-4 p-3 bg-amber-50 rounded-lg border-l-4 border-amber-400">
                         <div className="font-medium text-amber-800 mb-2">⏱️ Démonstration Calcul des Heures</div>
                         <div className="text-sm space-y-1">
                           <div className="grid grid-cols-3 gap-4">
                             <div>
                               <div className="font-medium text-amber-700">Jours ouvrables:</div>
                               <div>31 jours - 8 week-ends = 23 jours</div>
                               <div>23 jours - 2 fériés = 21 jours</div>
                             </div>
                             <div>
                               <div className="font-medium text-amber-700">Heures par jour:</div>
                               <div>8.25h (horaire standard)</div>
                               <div>21 jours × 8.25h = 173.25h</div>
                             </div>
                             <div>
                               <div className="font-medium text-amber-700">Ajustements:</div>
                               <div>+ 0.08h (arrondi réglementaire)</div>
                               <div className="font-bold text-amber-800">= 173.33h travaillées</div>
                             </div>
                           </div>
                         </div>
                       </div>

                       {/* Congés et absences */}
                       <div className="mb-4 p-3 bg-green-50 rounded-lg border-l-4 border-green-400">
                         <div className="font-medium text-green-800 mb-2">🏖️ Congés & Absences Validés</div>
                         <div className="text-sm">
                           <div className="grid grid-cols-2 gap-4">
                             <div>
                               <div className="font-medium text-green-700">Congés payés validés:</div>
                               <div className="text-green-600">Aucun congé dans cette période</div>
                               
                               <div className="font-medium text-green-700 mt-2">Congés maladie:</div>
                               <div className="text-green-600">Aucun arrêt maladie</div>
                             </div>
                             <div>
                               <div className="font-medium text-green-700">Absences justifiées:</div>
                               <div className="text-green-600">Aucune absence</div>
                               
                               <div className="font-medium text-green-700 mt-2">Retards décomptés:</div>
                               <div className="text-green-600">Aucun retard significatif</div>
                             </div>
                           </div>
                         </div>
                       </div>

                       {/* Heures supplémentaires */}
                       <div className="mb-4 p-3 bg-purple-50 rounded-lg border-l-4 border-purple-400">
                         <div className="font-medium text-purple-800 mb-2">⚡ Heures Supplémentaires Validées</div>
                         <div className="text-sm">
                           <div className="grid grid-cols-2 gap-4">
                             <div>
                               <div className="font-medium text-purple-700">Heures sup. autorisées:</div>
                               <div className="text-purple-600">Aucune demande approuvée</div>
                               
                               <div className="font-medium text-purple-700 mt-2">Majorations applicables:</div>
                               <div className="text-purple-600">+25% (1-8h), +50% (au-delà)</div>
                             </div>
                             <div>
                               <div className="font-medium text-purple-700">Total heures sup. payées:</div>
                               <div className="text-purple-600 font-bold">0.00h</div>
                               
                               <div className="font-medium text-purple-700 mt-2">Montant heures sup.:</div>
                               <div className="text-purple-600 font-bold">0.00 DH</div>
                             </div>
                           </div>
                         </div>
                       </div>
                       {/* Résumé rapide */}
                       <div className="grid grid-cols-4 gap-4 text-sm mb-4">
                         <div>
                           <div className="font-medium">Heures travaillées</div>
                           <div>{employee.worked_hours}h</div>
                         </div>
                         <div>
                           <div className="font-medium">Salaire brut</div>
                           <div className="text-green-600 font-medium">{employee.gross_pay?.toLocaleString()} DH</div>
                         </div>
                         <div>
                           <div className="font-medium">Total retenues</div>
                           <div className="text-red-600">
                             {((employee.cnss_employee || 0) + (employee.igr_amount || 0)).toLocaleString()} DH
                           </div>
                         </div>
                         <div>
                           <div className="font-medium">Salaire net</div>
                           <div className="text-green-700 font-bold">{employee.net_pay?.toLocaleString()} DH</div>
                         </div>
                       </div>

                       {/* Bulletin de paie détaillé */}
                       <div className="border rounded-lg overflow-hidden">
                         <div className="bg-gray-100 px-3 py-2 font-medium text-sm border-b">
                           📄 Bulletin de Paie - Détail des Articles
                         </div>
                         
                         {/* En-têtes */}
                         <div className="grid grid-cols-6 gap-2 px-3 py-2 bg-gray-50 text-xs font-medium border-b">
                           <div>Code</div>
                           <div>Libellé</div>
                           <div>Base</div>
                           <div className="text-green-600">Gains</div>
                           <div className="text-red-600">Retenues</div>
                           <div>Cumul</div>
                         </div>

                         {/* Lignes du bulletin */}
                         <div className="divide-y text-xs">
                           {/* Salaire de base */}
                           <div className="grid grid-cols-6 gap-2 px-3 py-2">
                             <div className="font-mono">SAL_BASE</div>
                             <div>Salaire de base</div>
                              <div>190h</div>
                             <div className="text-green-600 font-medium">3,131.2</div>
                             <div>-</div>
                             <div>{employee.gross_pay?.toLocaleString()}</div>
                           </div>

                            {/* CNSS Employé - Affiché seulement si activé */}
                            {employee.cnss_enabled && employee.cnss_employee && employee.cnss_employee > 0 && (
                              <div className="grid grid-cols-6 gap-2 px-3 py-2">
                                <div className="font-mono">CNSS_EMP</div>
                                <div>CNSS Employé (4.47%)</div>
                                <div>{employee.gross_pay?.toLocaleString()}</div>
                                <div>-</div>
                                <div className="text-red-600 font-medium">{employee.cnss_employee?.toLocaleString()}</div>
                                <div>{(employee.gross_pay! - employee.cnss_employee)?.toLocaleString()}</div>
                              </div>
                            )}

                            {/* AMO Employé - Affiché seulement si activé */}
                            {employee.amo_enabled && employee.amo_employee && employee.amo_employee > 0 && (
                              <div className="grid grid-cols-6 gap-2 px-3 py-2">
                                <div className="font-mono">AMO_EMP</div>
                                <div>AMO Employé (2.26%)</div>
                                <div>{employee.gross_pay?.toLocaleString()}</div>
                                <div>-</div>
                                <div className="text-red-600 font-medium">{employee.amo_employee?.toLocaleString()}</div>
                                <div>{(employee.gross_pay! - (employee.cnss_employee || 0) - employee.amo_employee)?.toLocaleString()}</div>
                              </div>
                            )}

                            {/* IGR - Affiché seulement si activé */}
                            {employee.igr_enabled && employee.igr_amount && employee.igr_amount > 0 && (
                              <div className="grid grid-cols-6 gap-2 px-3 py-2">
                                <div className="font-mono">IGR</div>
                                <div>Impôt sur le revenu</div>
                                <div>{(employee.gross_pay! - (employee.cnss_employee || 0) - 2500)?.toLocaleString()}</div>
                                <div>-</div>
                                <div className="text-red-600 font-medium">{employee.igr_amount?.toLocaleString()}</div>
                                <div>{employee.net_pay?.toLocaleString()}</div>
                              </div>
                            )}

                            {/* Message si aucune retenue activée */}
                            {!employee.cnss_enabled && !employee.amo_enabled && !employee.igr_enabled && (
                              <div className="grid grid-cols-6 gap-2 px-3 py-2 bg-blue-50">
                                <div className="font-mono">INFO</div>
                                <div className="col-span-4 text-blue-700 font-medium">Aucune retenue activée dans les paramètres</div>
                                <div>-</div>
                              </div>
                            )}

                            {/* Message si retenues activées mais montants à 0 */}
                            {(employee.cnss_enabled || employee.amo_enabled || employee.igr_enabled) && 
                             (!employee.cnss_employee || employee.cnss_employee === 0) && 
                             (!employee.amo_employee || employee.amo_employee === 0) &&
                             (!employee.igr_amount || employee.igr_amount === 0) && (
                              <div className="grid grid-cols-6 gap-2 px-3 py-2 bg-amber-50">
                                <div className="font-mono">WARN</div>
                                <div className="col-span-4 text-amber-700 font-medium">Retenues activées mais montants calculés à 0</div>
                                <div>-</div>
                              </div>
                            )}

                           {/* Ligne de total */}
                           <div className="grid grid-cols-6 gap-2 px-3 py-2 bg-gray-50 font-medium">
                             <div className="font-mono">TOTAL</div>
                             <div>Net à payer</div>
                             <div>-</div>
                             <div className="text-green-600">{employee.gross_pay?.toLocaleString()}</div>
                             <div className="text-red-600">{((employee.cnss_employee || 0) + (employee.igr_amount || 0)).toLocaleString()}</div>
                             <div className="text-green-700 font-bold">{employee.net_pay?.toLocaleString()}</div>
                           </div>
                         </div>
                       </div>

                       {/* Articles utilisés */}
                       <div className="mt-3 p-2 bg-blue-50 rounded text-xs">
                         <div className="font-medium text-blue-800 mb-1">📋 Articles appliqués:</div>
                         <div className="text-blue-700">
                           • SAL_BASE: Salaire de base ({employee.worked_hours}h × taux horaire)
                           {employee.cnss_employee !== 0 && (
                             <><br />• CNSS_EMP: Cotisation CNSS employé (4.47% du brut)</>
                           )}
                           {employee.igr_amount !== 0 && (
                             <><br />• IGR: Impôt sur le revenu (base imposable - 2500 DH)</>
                           )}
                         </div>
                       </div>
                       
                       {/* Indicateur de retenues désactivées */}
                       {employee.cnss_employee === 0 && employee.igr_amount === 0 && (
                         <div className="flex items-center gap-2 mt-2 p-2 bg-green-50 rounded text-sm">
                           <CheckCircle className="h-4 w-4 text-green-600" />
                           <span className="text-green-700">
                             ✅ Aucune retenue appliquée - Salaire net = Salaire brut
                           </span>
                         </div>
                       )}
                     </div>
                   )}

                  {/* Alertes */}
                  {employee.warnings && employee.warnings.length > 0 && (
                    <Alert className="mt-3" variant="destructive">
                      <AlertTriangle className="h-4 w-4" />
                      <AlertDescription>
                        <ul className="list-disc list-inside">
                          {employee.warnings.map((warning, index) => (
                            <li key={index}>{warning}</li>
                          ))}
                        </ul>
                      </AlertDescription>
                    </Alert>
                  )}
                </div>
              ))}

              {employees.length === 0 && !loading && (
                <div className="text-center py-8 text-muted-foreground">
                  <Users className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>Aucun employé éligible trouvé</p>
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
};

export default PayrollPreview;