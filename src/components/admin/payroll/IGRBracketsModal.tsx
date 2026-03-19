import React, { useState, useEffect } from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Plus, Trash2 } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { supabase } from "@/integrations/supabase/client";

interface IGRBracket {
  min_income: number;
  max_income: number | null;
  rate: number;
  deduction: number;
}

interface IGRBracketsModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSave: () => void;
}

const IGRBracketsModal: React.FC<IGRBracketsModalProps> = ({
  isOpen,
  onClose,
  onSave
}) => {
  const { toast } = useToast();
  const [brackets, setBrackets] = useState<IGRBracket[]>([
    { min_income: 0, max_income: 5800, rate: 10, deduction: 0 },
    { min_income: 5800, max_income: 14000, rate: 16.8, deduction: 394.4 },
    { min_income: 14000, max_income: 22000, rate: 24, deduction: 1402.4 },
    { min_income: 22000, max_income: 35000, rate: 32, deduction: 3162.4 },
    { min_income: 35000, max_income: null, rate: 38, deduction: 5262.4 }
  ]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (isOpen) {
      loadBrackets();
    }
  }, [isOpen]);

  const loadBrackets = async () => {
    try {
      const { data, error } = await supabase
        .from('payroll_config')
        .select('*')
        .eq('key', 'igr_brackets')
        .single();

      if (error && error.code !== 'PGRST116') throw error;
      
      if (data?.value && typeof data.value === 'object' && 'brackets' in data.value) {
        setBrackets((data.value as any).brackets);
      }
    } catch (error: any) {
      console.error('Error loading IGR brackets:', error);
    }
  };

  const addBracket = () => {
    setBrackets(prev => [...prev, {
      min_income: 0,
      max_income: null,
      rate: 0,
      deduction: 0
    }]);
  };

  const removeBracket = (index: number) => {
    setBrackets(prev => prev.filter((_, i) => i !== index));
  };

  const updateBracket = (index: number, field: keyof IGRBracket, value: number | null) => {
    setBrackets(prev => prev.map((bracket, i) => 
      i === index ? { ...bracket, [field]: value } : bracket
    ));
  };

  const handleSave = async () => {
    // Validation
    const sortedBrackets = [...brackets].sort((a, b) => a.min_income - b.min_income);
    
    setLoading(true);
    try {
      const { error } = await supabase
        .from('payroll_config')
        .upsert({
          key: 'igr_brackets',
          value: { 
            brackets: sortedBrackets,
            updated_at: new Date().toISOString()
          } as any,
          description: 'Barème IGR 2025 - Tranches d\'imposition sur le revenu',
          is_active: true
        }, {
          onConflict: 'key'
        });

      if (error) throw error;

      toast({
        title: "Succès",
        description: "Barème IGR sauvegardé"
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
      <DialogContent className="max-w-5xl max-h-[80vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Configuration du Barème IGR 2025</DialogTitle>
        </DialogHeader>

        <div className="space-y-4 py-4">
          <div className="flex justify-between items-center">
            <p className="text-sm text-muted-foreground">
              Configurez les tranches d'imposition sur le revenu avec leurs taux et déductions
            </p>
            <Button onClick={addBracket} size="sm" className="flex items-center gap-2">
              <Plus className="h-4 w-4" />
              Ajouter une tranche
            </Button>
          </div>

          <div className="space-y-3">
            {brackets.map((bracket, index) => (
              <Card key={index}>
                <CardHeader className="pb-3">
                  <div className="flex justify-between items-center">
                    <CardTitle className="text-sm">
                      Tranche {index + 1}
                      <Badge variant="outline" className="ml-2">
                        {bracket.rate}%
                      </Badge>
                    </CardTitle>
                    {brackets.length > 1 && (
                      <Button
                        onClick={() => removeBracket(index)}
                        size="sm"
                        variant="ghost"
                        className="text-red-600 hover:text-red-700"
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    )}
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-4 gap-4">
                    <div className="space-y-2">
                      <Label>Revenu minimum (MAD)</Label>
                      <Input
                        type="number"
                        value={bracket.min_income}
                        onChange={(e) => updateBracket(index, 'min_income', parseFloat(e.target.value) || 0)}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>Revenu maximum (MAD)</Label>
                      <Input
                        type="number"
                        value={bracket.max_income || ''}
                        onChange={(e) => updateBracket(index, 'max_income', 
                          e.target.value ? parseFloat(e.target.value) : null)}
                        placeholder="Illimité"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>Taux (%)</Label>
                      <Input
                        type="number"
                        step="0.1"
                        value={bracket.rate}
                        onChange={(e) => updateBracket(index, 'rate', parseFloat(e.target.value) || 0)}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>Déduction (MAD)</Label>
                      <Input
                        type="number"
                        step="0.01"
                        value={bracket.deduction}
                        onChange={(e) => updateBracket(index, 'deduction', parseFloat(e.target.value) || 0)}
                      />
                    </div>
                  </div>
                  <div className="mt-3 p-3 bg-muted rounded-lg">
                    <p className="text-xs text-muted-foreground">
                      <strong>Formule:</strong> IGR = (Revenu × {bracket.rate}%) - {bracket.deduction} MAD
                      {bracket.max_income ? 
                        ` • Revenu entre ${bracket.min_income.toLocaleString()} et ${bracket.max_income.toLocaleString()} MAD` :
                        ` • Revenu supérieur à ${bracket.min_income.toLocaleString()} MAD`
                      }
                    </p>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>

          <Card className="bg-blue-50 border-blue-200">
            <CardHeader>
              <CardTitle className="text-sm text-blue-800">Exemple de calcul</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-xs text-blue-700 space-y-1">
                <p><strong>Salaire brut:</strong> 10,000 MAD</p>
                <p><strong>Tranche 1:</strong> 5,800 × 10% = 580 MAD</p>
                <p><strong>Tranche 2:</strong> (10,000 - 5,800) × 16.8% = 705.6 MAD</p>
                <p><strong>IGR total:</strong> 580 + 705.6 - 394.4 = 891.2 MAD</p>
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

export default IGRBracketsModal;