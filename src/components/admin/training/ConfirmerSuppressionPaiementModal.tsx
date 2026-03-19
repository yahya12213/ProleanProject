import { useState } from "react";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { toast } from "sonner";
import { supabase } from "@/integrations/supabase/client";
import { Loader2 } from "lucide-react";

interface PaymentForDelete {
  id: string;
  montant: number;
  date_paiement: string;
  methode_paiement: string;
}

interface ConfirmerSuppressionPaiementModalProps {
  isOpen: boolean;
  onOpenChange: (open: boolean) => void;
  payment: PaymentForDelete | null;
  onSuccess: () => void;
}

export default function ConfirmerSuppressionPaiementModal({
  isOpen,
  onOpenChange,
  payment,
  onSuccess
}: ConfirmerSuppressionPaiementModalProps) {
  const [loading, setLoading] = useState(false);

  const handleDelete = async () => {
    if (!payment) return;

    setLoading(true);

    try {
      const { error } = await supabase
        .from("paiements")
        .delete()
        .eq("id", payment.id);

      if (error) {
        console.error("Erreur lors de la suppression du paiement:", error);
        toast.error("Erreur lors de la suppression du paiement");
        return;
      }

      toast.success("Paiement supprimé avec succès");
      onSuccess();
      onOpenChange(false);
    } catch (error) {
      console.error("Erreur:", error);
      toast.error("Une erreur est survenue");
    } finally {
      setLoading(false);
    }
  };

  if (!payment) return null;

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('fr-FR');
  };

  return (
    <AlertDialog open={isOpen} onOpenChange={onOpenChange}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Confirmer la suppression</AlertDialogTitle>
          <AlertDialogDescription className="space-y-2">
            <p>Êtes-vous sûr de vouloir supprimer ce paiement ?</p>
            <div className="bg-muted p-3 rounded-md">
              <p><strong>Montant :</strong> {payment.montant} DH</p>
              <p><strong>Date :</strong> {formatDate(payment.date_paiement)}</p>
              <p><strong>Méthode :</strong> {payment.methode_paiement}</p>
            </div>
            <p className="text-destructive text-sm">
              Cette action est irréversible. Un enregistrement de suppression sera conservé dans l'historique d'audit.
            </p>
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel disabled={loading}>Annuler</AlertDialogCancel>
          <AlertDialogAction
            onClick={handleDelete}
            disabled={loading}
            className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
          >
            {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            Supprimer
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}