import React, { useState, useEffect } from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { supabase } from "@/integrations/supabase/client";
import { format } from 'date-fns';
import { fr } from 'date-fns/locale';
import { CreditCard, Calendar, User, FileText, Hash, Edit, Trash2, History } from 'lucide-react';
import ModifierPaiementModal from "./ModifierPaiementModal";
import ConfirmerSuppressionPaiementModal from "./ConfirmerSuppressionPaiementModal";

interface Payment {
  id?: string;
  paiement_id?: string;
  montant: number;
  date_paiement: string;
  methode_paiement: string;
  numero_piece?: string;
  notes?: string;
  created_by?: string;
  created_at?: string;
  creator_name?: string;
  audit_count?: number;
  last_modified?: string;
  last_modifier_name?: string;
}

interface HistoriquePaiementsModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  inscription: {
    id: string;
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
    avance?: number;
  };
}

export const HistoriquePaiementsModal: React.FC<HistoriquePaiementsModalProps> = ({
  open,
  onOpenChange,
  inscription
}) => {
  const [payments, setPayments] = useState<Payment[]>([]);
  const [loading, setLoading] = useState(false);
  const [selectedPayment, setSelectedPayment] = useState<any>(null);
  const [modifyModalOpen, setModifyModalOpen] = useState(false);
  const [deleteModalOpen, setDeleteModalOpen] = useState(false);
  const [totalPrice, setTotalPrice] = useState(0);
  const [remainingBalance, setRemainingBalance] = useState(0);

  useEffect(() => {
    if (open) {
      loadPayments();
    }
  }, [open, inscription.id]);

  const loadPayments = async () => {
    setLoading(true);
    try {
      console.log('Loading payments for inscription:', inscription.id);
      
      // Utiliser la fonction pour récupérer l'historique avec audit
      const { data: paymentHistory, error: historyError } = await supabase
        .rpc('get_payment_history_with_audit', {
          p_inscription_id: inscription.id
        });

      if (historyError) {
        console.error("Erreur lors du chargement de l'historique des paiements:", historyError);
        // Si la fonction n'existe pas encore, utiliser l'ancienne méthode
        const { data: paymentsData, error: paymentsError } = await supabase
          .from('paiements')
          .select('*')
          .eq('inscription_id', inscription.id)
          .order('date_paiement', { ascending: false });

        if (paymentsError) {
          throw paymentsError;
        }

        // Mapper vers la nouvelle structure
        const mappedPayments = await Promise.all(
          (paymentsData || []).map(async (payment) => {
            try {
              const { data: profileData } = await supabase
                .from('profiles')
                .select('nom, prenom')
                .eq('user_id', payment.created_by)
                .maybeSingle();

              return {
                id: payment.id,
                paiement_id: payment.id,
                montant: payment.montant,
                date_paiement: payment.date_paiement,
                methode_paiement: payment.methode_paiement,
                numero_piece: payment.numero_piece,
                notes: payment.notes,
                created_by: payment.created_by,
                created_at: payment.created_at,
                creator_name: profileData ? `${profileData.prenom} ${profileData.nom}` : 'Inconnu',
                audit_count: 0,
                last_modified: null,
                last_modifier_name: null
              };
            } catch (err) {
              return {
                id: payment.id,
                paiement_id: payment.id,
                montant: payment.montant,
                date_paiement: payment.date_paiement,
                methode_paiement: payment.methode_paiement,
                numero_piece: payment.numero_piece,
                notes: payment.notes,
                created_by: payment.created_by,
                created_at: payment.created_at,
                creator_name: 'Inconnu',
                audit_count: 0,
                last_modified: null,
                last_modifier_name: null
              };
            }
          })
        );

        setPayments(mappedPayments);
      } else {
        // Mapper les données de la fonction RPC vers l'interface Payment
        const mappedHistory = (paymentHistory || []).map(payment => ({
          id: payment.paiement_id,
          paiement_id: payment.paiement_id,
          montant: payment.montant,
          date_paiement: payment.date_paiement,
          methode_paiement: payment.methode_paiement,
          numero_piece: payment.numero_piece,
          notes: payment.notes,
          created_by: payment.created_by,
          created_at: payment.created_at,
          creator_name: payment.creator_name,
          audit_count: payment.audit_count,
          last_modified: payment.last_modified,
          last_modifier_name: payment.last_modifier_name
        }));
        setPayments(mappedHistory);
      }

      // Calculer le reste à payer avec la nouvelle fonction
      const { data: remaining, error: remainingError } = await supabase
        .rpc('calculate_remaining_payment', {
          p_inscription_id: inscription.id
        });

      if (remainingError) {
        console.error("Erreur lors du calcul du reste à payer:", remainingError);
        // Calcul de fallback
        const formation = inscription.formations || inscription.classes?.formations;
        const totalPrice = formation?.prix || 0;
        const totalPaid = payments.reduce((sum, payment) => sum + Number(payment.montant), 0);
        const avance = inscription.avance || 0;
        setRemainingBalance(totalPrice - avance - totalPaid);
        setTotalPrice(totalPrice);
      } else {
        setRemainingBalance(remaining || 0);
      }

      // Récupérer le prix de la formation
      const formation = inscription.formations || inscription.classes?.formations;
      if (formation?.prix) {
        setTotalPrice(formation.prix);
      }
    } catch (error) {
      console.error('Error loading payments:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleEditPayment = (payment: Payment) => {
    const paymentToEdit = {
      id: payment.id || payment.paiement_id || '',
      montant: payment.montant,
      date_paiement: payment.date_paiement,
      methode_paiement: payment.methode_paiement,
      numero_piece: payment.numero_piece,
      notes: payment.notes,
      created_by: payment.created_by || ''
    };
    setSelectedPayment(paymentToEdit);
    setModifyModalOpen(true);
  };

  const handleDeletePayment = (payment: Payment) => {
    const paymentToDelete = {
      id: payment.id || payment.paiement_id || '',
      montant: payment.montant,
      date_paiement: payment.date_paiement,
      methode_paiement: payment.methode_paiement
    };
    setSelectedPayment(paymentToDelete);
    setDeleteModalOpen(true);
  };

  const handlePaymentModified = () => {
    loadPayments();
  };

  const formation = inscription.formations || inscription.classes?.formations;
  const studentName = `${inscription.etudiant.prenom} ${inscription.etudiant.nom}`;
  const totalPaid = payments.reduce((sum, payment) => sum + Number(payment.montant), 0);

  const getPaymentMethodColor = (method: string) => {
    switch (method) {
      case 'Espèces':
        return 'bg-green-100 text-green-800';
      case 'Chèque':
        return 'bg-blue-100 text-blue-800';
      case 'Virement':
        return 'bg-purple-100 text-purple-800';
      case 'Carte bancaire':
      case 'Carte':
        return 'bg-orange-100 text-orange-800';
      case 'TPE':
      case 'Mobile':
        return 'bg-pink-100 text-pink-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle>Historique des paiements</DialogTitle>
        </DialogHeader>

        <div className="space-y-4 p-4 bg-muted/50 rounded-lg">
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <span className="font-medium">Étudiant:</span>
              <p>{studentName}</p>
            </div>
            <div>
              <span className="font-medium">Formation:</span>
              <p>{formation?.titre}</p>
            </div>
          </div>
          
          <div className="grid grid-cols-4 gap-4 text-sm pt-2 border-t">
            <div>
              <span className="font-medium">Prix formation:</span>
              <p className="text-lg font-bold">{totalPrice} DH</p>
            </div>
            <div>
              <span className="font-medium">Avance:</span>
              <p className="text-lg font-bold text-blue-600">{inscription.avance || 0} DH</p>
            </div>
            <div>
              <span className="font-medium">Total payé:</span>
              <p className="text-lg font-bold text-green-600">{totalPaid.toFixed(2)} DH</p>
            </div>
            <div>
              <span className="font-medium">Reste à payer:</span>
              <p className={`text-lg font-bold ${remainingBalance > 0 ? 'text-red-600' : 'text-green-600'}`}>
                {remainingBalance.toFixed(2)} DH
              </p>
            </div>
          </div>
        </div>

        <ScrollArea className="max-h-96">
          {loading ? (
            <div className="text-center py-8">Chargement...</div>
          ) : payments.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              Aucun paiement enregistré
            </div>
          ) : (
            <div className="space-y-4">
              {payments.map((payment) => (
                <div key={payment.id || payment.paiement_id} className="border rounded-lg p-4 space-y-3">
                  <div className="flex items-start justify-between">
                    <div className="space-y-2">
                      <div className="flex items-center gap-2">
                        <CreditCard className="h-4 w-4 text-muted-foreground" />
                        <span className="font-medium text-lg">
                          {Number(payment.montant).toFixed(2)} DH
                        </span>
                        <Badge className={getPaymentMethodColor(payment.methode_paiement)}>
                          {payment.methode_paiement}
                        </Badge>
                        {payment.audit_count > 0 && (
                          <Badge variant="outline" className="text-xs">
                            <History className="h-3 w-3 mr-1" />
                            Modifié
                          </Badge>
                        )}
                      </div>
                      
                      <div className="grid grid-cols-2 gap-4 text-sm">
                        <div className="flex items-center gap-2">
                          <Calendar className="h-4 w-4 text-muted-foreground" />
                          <span>
                            {format(new Date(payment.date_paiement), 'dd MMMM yyyy à HH:mm', { locale: fr })}
                          </span>
                        </div>

                        <div className="flex items-center gap-2">
                          <User className="h-4 w-4 text-muted-foreground" />
                          <span>{payment.creator_name || 'Utilisateur inconnu'}</span>
                        </div>
                      </div>

                      {payment.last_modified && (
                        <div className="text-xs text-muted-foreground">
                          Dernière modification: {format(new Date(payment.last_modified), 'dd/MM/yyyy à HH:mm', { locale: fr })} 
                          par {payment.last_modifier_name}
                        </div>
                      )}
                    </div>

                    <div className="flex items-center gap-1">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => handleEditPayment(payment)}
                        className="h-8 w-8 p-0"
                        title="Modifier le paiement"
                      >
                        <Edit className="h-3 w-3" />
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => handleDeletePayment(payment)}
                        className="h-8 w-8 p-0 hover:bg-destructive hover:text-destructive-foreground"
                        title="Supprimer le paiement"
                      >
                        <Trash2 className="h-3 w-3" />
                      </Button>
                    </div>
                  </div>

                  {payment.numero_piece && (
                    <div className="flex items-center gap-2 text-sm">
                      <Hash className="h-4 w-4 text-muted-foreground" />
                      <span>
                        {payment.methode_paiement === 'Chèque' ? 'N° chèque:' : 'Réf:'} {payment.numero_piece}
                      </span>
                    </div>
                  )}

                  {payment.notes && (
                    <div className="flex items-start gap-2 text-sm">
                      <FileText className="h-4 w-4 text-muted-foreground mt-0.5" />
                      <div className="text-sm text-muted-foreground bg-muted/50 p-2 rounded">
                        <strong>Notes:</strong> {payment.notes}
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </ScrollArea>

        <ModifierPaiementModal
          isOpen={modifyModalOpen}
          onOpenChange={setModifyModalOpen}
          payment={selectedPayment}
          onSuccess={handlePaymentModified}
        />

        <ConfirmerSuppressionPaiementModal
          isOpen={deleteModalOpen}
          onOpenChange={setDeleteModalOpen}
          payment={selectedPayment}
          onSuccess={handlePaymentModified}
        />
      </DialogContent>
    </Dialog>
  );
};