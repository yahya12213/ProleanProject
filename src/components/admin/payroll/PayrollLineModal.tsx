import React, { useState, useEffect } from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks/use-toast";
import { supabase } from "@/integrations/supabase/client";

interface PayrollLine {
  id?: string;
  code: string;
  name: string;
  type: string;
  formula: string | null;
  base_amount: number;
  percentage: number;
  soumis_cnss: boolean;
  soumis_amo: boolean;
  imposable_igr: boolean;
  is_active: boolean;
  ordre_affichage: number;
}

interface PayrollLineModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSave: () => void;
  line?: PayrollLine | null;
}

const PayrollLineModal: React.FC<PayrollLineModalProps> = ({
  isOpen,
  onClose,
  onSave,
  line
}) => {
  const { toast } = useToast();
  const [formData, setFormData] = useState<PayrollLine>({
    code: '',
    name: '',
    type: 'gain',
    formula: null,
    base_amount: 0,
    percentage: 0,
    soumis_cnss: false,
    soumis_amo: false,
    imposable_igr: false,
    is_active: true,
    ordre_affichage: 0
  });
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (line) {
      setFormData(line);
    } else {
      setFormData({
        code: '',
        name: '',
        type: 'gain',
        formula: null,
        base_amount: 0,
        percentage: 0,
        soumis_cnss: false,
        soumis_amo: false,
        imposable_igr: false,
        is_active: true,
        ordre_affichage: 0
      });
    }
  }, [line, isOpen]);

  const handleSave = async () => {
    if (!formData.code || !formData.name) {
      toast({
        title: "Erreur",
        description: "Le code et le nom sont obligatoires",
        variant: "destructive"
      });
      return;
    }

    setLoading(true);
    try {
      if (line?.id) {
        // Update existing line
        const { error } = await supabase
          .from('payroll_lines')
          .update(formData)
          .eq('id', line.id);
        
        if (error) throw error;
        
        toast({
          title: "Succès",
          description: "Ligne de paie modifiée avec succès"
        });
      } else {
        // Create new line
        const { error } = await supabase
          .from('payroll_lines')
          .insert([formData]);
        
        if (error) throw error;
        
        toast({
          title: "Succès",
          description: "Ligne de paie créée avec succès"
        });
      }
      
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
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>
            {line ? "Modifier la ligne de paie" : "Ajouter une ligne de paie"}
          </DialogTitle>
        </DialogHeader>
        
        <div className="grid gap-4 py-4">
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="code">Code *</Label>
              <Input
                id="code"
                value={formData.code}
                onChange={(e) => setFormData(prev => ({ ...prev, code: e.target.value }))}
                placeholder="Ex: SAL_BASE"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="type">Type *</Label>
              <Select
                value={formData.type}
                onValueChange={(value) => setFormData(prev => ({ ...prev, type: value }))}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="gain">Gain</SelectItem>
                  <SelectItem value="retenue">Retenue</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="space-y-2">
            <Label htmlFor="name">Nom *</Label>
            <Input
              id="name"
              value={formData.name}
              onChange={(e) => setFormData(prev => ({ ...prev, name: e.target.value }))}
              placeholder="Ex: Salaire de base"
            />
          </div>

          <div className="grid grid-cols-3 gap-4">
            <div className="space-y-2">
              <Label htmlFor="base_amount">Montant de base</Label>
              <Input
                id="base_amount"
                type="number"
                step="0.01"
                value={formData.base_amount}
                onChange={(e) => setFormData(prev => ({ ...prev, base_amount: parseFloat(e.target.value) || 0 }))}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="percentage">Pourcentage</Label>
              <Input
                id="percentage"
                type="number"
                step="0.01"
                value={formData.percentage}
                onChange={(e) => setFormData(prev => ({ ...prev, percentage: parseFloat(e.target.value) || 0 }))}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="ordre_affichage">Ordre d'affichage</Label>
              <Input
                id="ordre_affichage"
                type="number"
                value={formData.ordre_affichage}
                onChange={(e) => setFormData(prev => ({ ...prev, ordre_affichage: parseInt(e.target.value) || 0 }))}
              />
            </div>
          </div>

          <div className="space-y-2">
            <Label htmlFor="formula">Formule de calcul</Label>
            <Textarea
              id="formula"
              value={formData.formula || ''}
              onChange={(e) => setFormData(prev => ({ ...prev, formula: e.target.value || null }))}
              placeholder="Ex: SALAIRE_BASE * 0.10"
              rows={2}
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-4">
              <div className="flex items-center space-x-2">
                <Switch
                  id="soumis_cnss"
                  checked={formData.soumis_cnss}
                  onCheckedChange={(checked) => setFormData(prev => ({ ...prev, soumis_cnss: checked }))}
                />
                <Label htmlFor="soumis_cnss">Soumis CNSS</Label>
              </div>
              <div className="flex items-center space-x-2">
                <Switch
                  id="soumis_amo"
                  checked={formData.soumis_amo}
                  onCheckedChange={(checked) => setFormData(prev => ({ ...prev, soumis_amo: checked }))}
                />
                <Label htmlFor="soumis_amo">Soumis AMO</Label>
              </div>
            </div>
            <div className="space-y-4">
              <div className="flex items-center space-x-2">
                <Switch
                  id="imposable_igr"
                  checked={formData.imposable_igr}
                  onCheckedChange={(checked) => setFormData(prev => ({ ...prev, imposable_igr: checked }))}
                />
                <Label htmlFor="imposable_igr">Imposable IGR</Label>
              </div>
              <div className="flex items-center space-x-2">
                <Switch
                  id="is_active"
                  checked={formData.is_active}
                  onCheckedChange={(checked) => setFormData(prev => ({ ...prev, is_active: checked }))}
                />
                <Label htmlFor="is_active">Actif</Label>
              </div>
            </div>
          </div>
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

export default PayrollLineModal;