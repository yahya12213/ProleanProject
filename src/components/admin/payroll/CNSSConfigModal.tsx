import React, { useState, useEffect } from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useToast } from "@/hooks/use-toast";
import { supabase } from "@/integrations/supabase/client";

interface CNSSBranch {
  code: string;
  name: string;
  employee_rate: number;
  employer_rate: number;
  description: string;
}

interface CNSSConfig {
  ceiling: number;
  branches: CNSSBranch[];
}

interface CNSSConfigModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSave: () => void;
}

const CNSSConfigModal: React.FC<CNSSConfigModalProps> = ({
  isOpen,
  onClose,
  onSave
}) => {
  const { toast } = useToast();
  const [config, setConfig] = useState<CNSSConfig>({
    ceiling: 7000,
    branches: [
      {
        code: 'AT',
        name: 'Accidents du travail',
        employee_rate: 0,
        employer_rate: 0.65,
        description: 'Assurance contre les accidents du travail et maladies professionnelles'
      },
      {
        code: 'AF',
        name: 'Allocations familiales',
        employee_rate: 0,
        employer_rate: 6.4,
        description: 'Prestations familiales'
      },
      {
        code: 'PF',
        name: 'Pension et formation',
        employee_rate: 3.96,
        employer_rate: 7.93,
        description: 'Pension de vieillesse, invalidité et formation professionnelle'
      }
    ]
  });
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (isOpen) {
      loadConfig();
    }
  }, [isOpen]);

  const loadConfig = async () => {
    try {
      const { data, error } = await supabase
        .from('payroll_config')
        .select('*')
        .eq('key', 'cnss_branches')
        .single();

      if (error && error.code !== 'PGRST116') throw error;
      
      if (data?.value && typeof data.value === 'object') {
        setConfig(data.value as unknown as CNSSConfig);
      }
    } catch (error: any) {
      console.error('Error loading CNSS config:', error);
    }
  };

  const updateBranch = (index: number, field: keyof CNSSBranch, value: string | number) => {
    setConfig(prev => ({
      ...prev,
      branches: prev.branches.map((branch, i) => 
        i === index ? { ...branch, [field]: value } : branch
      )
    }));
  };

  const handleSave = async () => {
    setLoading(true);
    try {
      const { error } = await supabase
        .from('payroll_config')
        .upsert({
          key: 'cnss_branches',
          value: config as any,
          description: 'Configuration des branches et taux CNSS',
          is_active: true
        }, {
          onConflict: 'key'
        });

      if (error) throw error;

      toast({
        title: "Succès",
        description: "Configuration CNSS sauvegardée"
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

  const totalEmployeeRate = config.branches.reduce((sum, branch) => sum + branch.employee_rate, 0);
  const totalEmployerRate = config.branches.reduce((sum, branch) => sum + branch.employer_rate, 0);

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="max-w-4xl max-h-[80vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Configuration CNSS</DialogTitle>
        </DialogHeader>

        <div className="space-y-6 py-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Plafond CNSS</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                <Label htmlFor="ceiling">Plafond mensuel (MAD)</Label>
                <Input
                  id="ceiling"
                  type="number"
                  value={config.ceiling}
                  onChange={(e) => setConfig(prev => ({ 
                    ...prev, 
                    ceiling: parseFloat(e.target.value) || 0 
                  }))}
                />
                <p className="text-xs text-muted-foreground">
                  Plafond de la rémunération soumise aux cotisations CNSS
                </p>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">Branches CNSS</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {config.branches.map((branch, index) => (
                  <Card key={branch.code} className="border-l-4 border-l-blue-500">
                    <CardHeader className="pb-3">
                      <CardTitle className="text-sm">{branch.name}</CardTitle>
                      <p className="text-xs text-muted-foreground">{branch.description}</p>
                    </CardHeader>
                    <CardContent>
                      <div className="grid grid-cols-4 gap-4">
                        <div className="space-y-2">
                          <Label>Code</Label>
                          <Input
                            value={branch.code}
                            onChange={(e) => updateBranch(index, 'code', e.target.value)}
                          />
                        </div>
                        <div className="space-y-2">
                          <Label>Nom</Label>
                          <Input
                            value={branch.name}
                            onChange={(e) => updateBranch(index, 'name', e.target.value)}
                          />
                        </div>
                        <div className="space-y-2">
                          <Label>Taux salarié (%)</Label>
                          <Input
                            type="number"
                            step="0.01"
                            value={branch.employee_rate}
                            onChange={(e) => updateBranch(index, 'employee_rate', parseFloat(e.target.value) || 0)}
                          />
                        </div>
                        <div className="space-y-2">
                          <Label>Taux patronal (%)</Label>
                          <Input
                            type="number"
                            step="0.01"
                            value={branch.employer_rate}
                            onChange={(e) => updateBranch(index, 'employer_rate', parseFloat(e.target.value) || 0)}
                          />
                        </div>
                      </div>
                      <div className="mt-3">
                        <Label>Description</Label>
                        <Input
                          value={branch.description}
                          onChange={(e) => updateBranch(index, 'description', e.target.value)}
                          placeholder="Description de la branche"
                        />
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>

              <div className="mt-6 p-4 bg-muted rounded-lg">
                <h4 className="font-medium mb-2">Totaux des taux CNSS</h4>
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <span className="font-medium">Taux total salarié:</span>
                    <span className="ml-2 font-mono">{totalEmployeeRate.toFixed(2)}%</span>
                  </div>
                  <div>
                    <span className="font-medium">Taux total patronal:</span>
                    <span className="ml-2 font-mono">{totalEmployerRate.toFixed(2)}%</span>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="bg-green-50 border-green-200">
            <CardHeader>
              <CardTitle className="text-sm text-green-800">Exemple de calcul</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-xs text-green-700 space-y-1">
                <p><strong>Salaire brut:</strong> 8,000 MAD (plafonné à {config.ceiling.toLocaleString()} MAD)</p>
                <p><strong>Base CNSS:</strong> {Math.min(8000, config.ceiling).toLocaleString()} MAD</p>
                <p><strong>Cotisation salarié:</strong> {Math.min(8000, config.ceiling).toLocaleString()} × {totalEmployeeRate.toFixed(2)}% = {(Math.min(8000, config.ceiling) * totalEmployeeRate / 100).toFixed(2)} MAD</p>
                <p><strong>Cotisation patronale:</strong> {Math.min(8000, config.ceiling).toLocaleString()} × {totalEmployerRate.toFixed(2)}% = {(Math.min(8000, config.ceiling) * totalEmployerRate / 100).toFixed(2)} MAD</p>
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

export default CNSSConfigModal;