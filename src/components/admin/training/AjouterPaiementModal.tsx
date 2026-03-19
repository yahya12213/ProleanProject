import React, { useState, useEffect } from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { Card, CardContent } from "@/components/ui/card";
import { supabase } from "@/integrations/supabase/client";
import { useToast } from "@/hooks/use-toast";
import { Loader2 } from "lucide-react";

interface AjouterPaiementModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  inscription: {
    id: string;
    avance?: number;
    etudiant: {
      nom: string;
      prenom: string;
    };
    formations?: {
      titre: string;
      prix: number;
    };
    classes?: {
      formations?: {
        titre: string;
        prix: number;
      };
    };
  };
  onSuccess: () => void;
}

export const AjouterPaiementModal: React.FC<AjouterPaiementModalProps> = ({
  open,
  onOpenChange,
  inscription,
  onSuccess
}) => {
  const { toast } = useToast();
  const [formData, setFormData] = useState({
    montant: '',
    methode_paiement: 'Espèces',
    numero_piece: '',
    notes: ''
  });
  const [loading, setLoading] = useState(false);
  const [resteAPayer, setResteAPayer] = useState<number | null>(null);
  const [loadingReste, setLoadingReste] = useState(false);

  // Charger le reste à payer lors de l'ouverture du modal
  useEffect(() => {
    if (open && inscription.id) {
      fetchResteAPayer();
    }
  }, [open, inscription.id]);

  const fetchResteAPayer = async () => {
    setLoadingReste(true);
    try {
      const { data, error } = await supabase.rpc('calculate_remaining_payment', {
        p_inscription_id: inscription.id
      });

      if (error) throw error;
      setResteAPayer(data);
    } catch (error) {
      console.error('Erreur lors du calcul du reste à payer:', error);
      setResteAPayer(null);
    } finally {
      setLoadingReste(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    const montantPaiement = parseFloat(formData.montant);
    
    if (!formData.montant || montantPaiement <= 0) {
      toast({
        title: "Erreur",
        description: "Veuillez saisir un montant valide",
        variant: "destructive"
      });
      return;
    }

    // Vérifier si le montant ne dépasse pas le reste à payer
    if (resteAPayer !== null && montantPaiement > resteAPayer) {
      toast({
        title: "Attention",
        description: `Le montant (${montantPaiement} DH) dépasse le reste à payer (${resteAPayer} DH). Voulez-vous continuer ?`,
        variant: "destructive"
      });
      // On peut continuer mais on avertit l'utilisateur
    }

    setLoading(true);

    try {
      const { data: { user } } = await supabase.auth.getUser();
      
      if (!user) {
        throw new Error("Utilisateur non authentifié");
      }

      const { error } = await supabase
        .from('paiements')
        .insert({
          inscription_id: inscription.id,
          montant: montantPaiement,
          methode_paiement: formData.methode_paiement,
          numero_piece: formData.numero_piece || null,
          notes: formData.notes || null,
          created_by: user.id
        });

      if (error) throw error;

      toast({
        title: "Succès",
        description: "Paiement ajouté avec succès"
      });

      setFormData({
        montant: '',
        methode_paiement: 'Espèces',
        numero_piece: '',
        notes: ''
      });
      
      onSuccess();
      onOpenChange(false);
    } catch (error) {
      console.error('Error adding payment:', error);
      toast({
        title: "Erreur",
        description: "Erreur lors de l'ajout du paiement",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const formation = inscription.formations || inscription.classes?.formations;
  const studentName = `${inscription.etudiant.prenom} ${inscription.etudiant.nom}`;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Ajouter un paiement</DialogTitle>
          <div className="space-y-2">
            <p className="text-sm text-muted-foreground">
              <span className="font-medium">Étudiant:</span> {studentName}
            </p>
            {formation && (
              <p className="text-sm text-muted-foreground">
                <span className="font-medium">Formation:</span> {formation.titre}
              </p>
            )}
            
            {/* Affichage du reste à payer */}
            <Card className="bg-muted/50">
              <CardContent className="p-3">
                <div className="flex justify-between items-center">
                  <span className="text-sm font-medium">Reste à payer:</span>
                  {loadingReste ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : resteAPayer !== null ? (
                    <span className={`text-sm font-bold ${resteAPayer > 0 ? 'text-destructive' : 'text-green-600'}`}>
                      {resteAPayer.toFixed(2)} DH
                    </span>
                  ) : (
                    <span className="text-sm text-muted-foreground">Non calculé</span>
                  )}
                </div>
                {formation?.prix && (
                  <div className="text-xs text-muted-foreground mt-1">
                    Prix formation: {formation.prix} DH
                    {inscription.avance && inscription.avance > 0 && (
                      <span> | Avance: {inscription.avance} DH</span>
                    )}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </DialogHeader>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <Label htmlFor="montant">Montant * (DH)</Label>
            <div className="space-y-2">
              <Input
                id="montant"
                type="number"
                step="0.01"
                min="0"
                value={formData.montant}
                onChange={(e) => setFormData(prev => ({ ...prev, montant: e.target.value }))}
                placeholder="0.00"
                required
              />
              {resteAPayer !== null && resteAPayer > 0 && (
                <div className="flex gap-2">
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => setFormData(prev => ({ ...prev, montant: resteAPayer.toString() }))}
                  >
                    Solde complet ({resteAPayer} DH)
                  </Button>
                  {resteAPayer > 100 && (
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      onClick={() => setFormData(prev => ({ ...prev, montant: (resteAPayer / 2).toFixed(2) }))}
                    >
                      Moitié ({(resteAPayer / 2).toFixed(2)} DH)
                    </Button>
                  )}
                </div>
              )}
            </div>
          </div>

          <div>
            <Label htmlFor="methode">Méthode de paiement</Label>
            <Select 
              value={formData.methode_paiement} 
              onValueChange={(value) => setFormData(prev => ({ ...prev, methode_paiement: value }))}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="Espèces">Espèces</SelectItem>
                <SelectItem value="Chèque">Chèque</SelectItem>
                <SelectItem value="Virement">Virement bancaire</SelectItem>
                <SelectItem value="Carte">Carte bancaire</SelectItem>
                <SelectItem value="Mobile">Paiement mobile</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {(formData.methode_paiement === 'Chèque' || formData.methode_paiement === 'Virement') && (
            <div>
              <Label htmlFor="numero_piece">
                {formData.methode_paiement === 'Chèque' ? 'Numéro de chèque' : 'Référence virement'}
              </Label>
              <Input
                id="numero_piece"
                value={formData.numero_piece}
                onChange={(e) => setFormData(prev => ({ ...prev, numero_piece: e.target.value }))}
                placeholder={formData.methode_paiement === 'Chèque' ? 'N° chèque' : 'Réf. virement'}
              />
            </div>
          )}

          <div>
            <Label htmlFor="notes">Notes (optionnel)</Label>
            <Textarea
              id="notes"
              value={formData.notes}
              onChange={(e) => setFormData(prev => ({ ...prev, notes: e.target.value }))}
              placeholder="Notes ou commentaires..."
              rows={3}
            />
          </div>

          <div className="flex justify-end space-x-2 pt-4">
            <Button
              type="button"
              variant="outline"
              onClick={() => onOpenChange(false)}
              disabled={loading}
            >
              Annuler
            </Button>
            <Button type="submit" disabled={loading}>
              {loading ? 'Ajout...' : 'Ajouter le paiement'}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
};