import { useState, useEffect } from "react";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { toast } from "sonner";
import { supabase } from "@/integrations/supabase/client";
import { Loader2 } from "lucide-react";

interface PaymentForEdit {
  id: string;
  montant: number;
  date_paiement: string;
  methode_paiement: string;
  numero_piece?: string;
  notes?: string;
  created_by?: string;
}

interface ModifierPaiementModalProps {
  isOpen: boolean;
  onOpenChange: (open: boolean) => void;
  payment: PaymentForEdit | null;
  onSuccess: () => void;
}

export default function ModifierPaiementModal({
  isOpen,
  onOpenChange,
  payment,
  onSuccess
}: ModifierPaiementModalProps) {
  const [loading, setLoading] = useState(false);
  const [formData, setFormData] = useState({
    montant: "",
    date_paiement: "",
    methode_paiement: "",
    numero_piece: "",
    notes: ""
  });

  useEffect(() => {
    if (payment) {
      setFormData({
        montant: payment.montant.toString(),
        date_paiement: payment.date_paiement.split('T')[0],
        methode_paiement: payment.methode_paiement,
        numero_piece: payment.numero_piece || "",
        notes: payment.notes || ""
      });
    } else {
      setFormData({
        montant: "",
        date_paiement: "",
        methode_paiement: "",
        numero_piece: "",
        notes: ""
      });
    }
  }, [payment]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!payment) return;

    setLoading(true);

    try {
      const montant = parseFloat(formData.montant);
      if (isNaN(montant) || montant <= 0) {
        toast.error("Le montant doit être un nombre positif");
        return;
      }

      const { error } = await supabase
        .from("paiements")
        .update({
          montant,
          date_paiement: formData.date_paiement,
          methode_paiement: formData.methode_paiement,
          numero_piece: formData.numero_piece || null,
          notes: formData.notes || null,
          updated_at: new Date().toISOString()
        })
        .eq("id", payment.id);

      if (error) {
        console.error("Erreur lors de la modification du paiement:", error);
        toast.error("Erreur lors de la modification du paiement");
        return;
      }

      toast.success("Paiement modifié avec succès");
      onSuccess();
      onOpenChange(false);
    } catch (error) {
      console.error("Erreur:", error);
      toast.error("Une erreur est survenue");
    } finally {
      setLoading(false);
    }
  };

  const handleCancel = () => {
    onOpenChange(false);
  };

  if (!payment) return null;

  return (
    <Dialog open={isOpen} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[500px]">
        <DialogHeader>
          <DialogTitle>Modifier le paiement</DialogTitle>
        </DialogHeader>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="montant">Montant (DH)</Label>
            <Input
              id="montant"
              type="number"
              step="0.01"
              min="0"
              value={formData.montant}
              onChange={(e) => setFormData({ ...formData, montant: e.target.value })}
              required
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="date_paiement">Date de paiement</Label>
            <Input
              id="date_paiement"
              type="date"
              value={formData.date_paiement}
              onChange={(e) => setFormData({ ...formData, date_paiement: e.target.value })}
              required
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="methode_paiement">Méthode de paiement</Label>
            <Select
              value={formData.methode_paiement}
              onValueChange={(value) => setFormData({ ...formData, methode_paiement: value })}
            >
              <SelectTrigger>
                <SelectValue placeholder="Sélectionner une méthode" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="Espèces">Espèces</SelectItem>
                <SelectItem value="Chèque">Chèque</SelectItem>
                <SelectItem value="Virement">Virement</SelectItem>
                <SelectItem value="Carte bancaire">Carte bancaire</SelectItem>
                <SelectItem value="TPE">TPE</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {(formData.methode_paiement === "Chèque" || formData.methode_paiement === "Virement") && (
            <div className="space-y-2">
              <Label htmlFor="numero_piece">
                {formData.methode_paiement === "Chèque" ? "Numéro de chèque" : "Référence virement"}
              </Label>
              <Input
                id="numero_piece"
                value={formData.numero_piece}
                onChange={(e) => setFormData({ ...formData, numero_piece: e.target.value })}
                placeholder={
                  formData.methode_paiement === "Chèque" 
                    ? "Numéro du chèque" 
                    : "Référence du virement"
                }
              />
            </div>
          )}

          <div className="space-y-2">
            <Label htmlFor="notes">Notes (optionnel)</Label>
            <Textarea
              id="notes"
              value={formData.notes}
              onChange={(e) => setFormData({ ...formData, notes: e.target.value })}
              placeholder="Notes sur le paiement..."
              rows={3}
            />
          </div>

          <div className="flex justify-end space-x-2 pt-4">
            <Button
              type="button"
              variant="outline"
              onClick={handleCancel}
              disabled={loading}
            >
              Annuler
            </Button>
            <Button type="submit" disabled={loading}>
              {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Modifier le paiement
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}