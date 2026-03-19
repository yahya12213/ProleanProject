import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { useToast } from "@/hooks/use-toast";
import { supabase } from "@/integrations/supabase/client";
import { useCurrentProfile } from "@/hooks/useCurrentProfile";
import { 
  Plus, 
  Edit, 
  Trash2, 
  CreditCard, 
  Calendar, 
  User, 
  DollarSign,
  FileText,
  Clock,
  CheckCircle2,
  AlertCircle,
  Calculator
} from 'lucide-react';
import { format } from 'date-fns';
import { fr } from 'date-fns/locale';
import ConfirmerSuppressionPaiementModal from "./ConfirmerSuppressionPaiementModal";

interface Payment {
  id: string;
  montant: number;
  date_paiement: string;
  methode_paiement: string;
  numero_piece?: string;
  notes?: string;
  created_by: string;
  created_at: string;
  creator_name?: string;
  audit_count?: number;
  last_modified?: string;
  last_modifier_name?: string;
}

interface Inscription {
  id: string;
  etudiant_id: string;
  formation_id?: string;
  avance?: number;
  etudiants: {
    nom: string;
    prenom: string;
    cin?: string;
  };
  formations?: {
    titre: string;
    prix: number;
  };
}

interface GestionPaiementsModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  inscription: Inscription | null;
  onSuccess?: () => void;
}

export const GestionPaiementsModal: React.FC<GestionPaiementsModalProps> = ({
  open,
  onOpenChange,
  inscription,
  onSuccess
}) => {
  const { toast } = useToast();
  const { data: currentProfile } = useCurrentProfile();
  const [activeTab, setActiveTab] = useState("history");
  const [payments, setPayments] = useState<Payment[]>([]);
  const [resteAPayer, setResteAPayer] = useState<number>(0);
  const [isLoading, setIsLoading] = useState(false);

  // État pour l'ajout de paiement
  const [formData, setFormData] = useState({
    montant: '',
    date_paiement: new Date().toISOString().split('T')[0],
    methode_paiement: 'Espèces',
    numero_piece: '',
    notes: ''
  });
  const [loading, setLoading] = useState(false);

  // État pour l'édition
  const [editingPayment, setEditingPayment] = useState<Payment | null>(null);
  const [editFormData, setEditFormData] = useState({
    montant: '',
    date_paiement: '',
    methode_paiement: '',
    numero_piece: '',
    notes: ''
  });
  const [loadingEdit, setLoadingEdit] = useState(false);

  // État pour la suppression
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);
  const [paymentToDelete, setPaymentToDelete] = useState<Payment | null>(null);

  // Fonction optimisée pour charger toutes les données d'un coup
  const loadAllData = useCallback(async () => {
    if (!inscription?.id) return;
    
    setIsLoading(true);
    
    try {
      // Charger paiements et calculer le reste en parallèle
      const [paymentsResult, remainingResult] = await Promise.all([
        supabase
          .from('paiements')
          .select('*')
          .eq('inscription_id', inscription.id)
          .order('date_paiement', { ascending: false }),
        
        supabase.rpc('calculate_remaining_payment', { 
          p_inscription_id: inscription.id 
        })
      ]);

      // Charger les profils des créateurs séparément
      const creatorIds = paymentsResult.data?.map(p => p.created_by).filter(Boolean) || [];
      const uniqueCreatorIds = [...new Set(creatorIds)];
      
      let profilesData: any[] = [];
      if (uniqueCreatorIds.length > 0) {
        const { data: profiles } = await supabase
          .from('profiles')
          .select('user_id, nom, prenom')
          .in('user_id', uniqueCreatorIds);
        profilesData = profiles || [];
      }

      if (paymentsResult.error) {
        console.error('Erreur lors du chargement des paiements:', paymentsResult.error);
        throw paymentsResult.error;
      }

      // Formater les données avec les noms des créateurs
      const formattedData = (paymentsResult.data || []).map(payment => {
        const creatorProfile = profilesData.find(p => p.user_id === payment.created_by);
        const creatorName = creatorProfile 
          ? `${creatorProfile.nom} ${creatorProfile.prenom}` 
          : 'Utilisateur supprimé';
        
        return {
          ...payment,
          creator_name: creatorName,
          paiement_id: payment.id,
          audit_count: 0,
          last_modified: payment.updated_at !== payment.created_at ? payment.updated_at : null,
          last_modifier_name: null
        };
      });

      setPayments(formattedData);

      // Calculer le reste à payer (avec fallback si la fonction RPC échoue)
      if (remainingResult.error || remainingResult.data === null) {
        console.warn('RPC échoué, calcul manuel du reste à payer');
        const prixFormation = inscription.formations?.prix || 0;
        const avance = inscription.avance || 0;
        const totalPaid = formattedData.reduce((sum, p) => sum + Number(p.montant), 0);
        setResteAPayer(Math.max(0, prixFormation - avance - totalPaid));
      } else {
        setResteAPayer(Math.max(0, remainingResult.data));
      }
    } catch (error) {
      console.error('Erreur lors du chargement des données:', error);
      toast({
        title: "Erreur",
        description: "Impossible de charger les données de paiement",
        variant: "destructive"
      });
    } finally {
      setIsLoading(false);
    }
  }, [inscription?.id, inscription?.formations?.prix, inscription?.avance, toast]);

  // Charger toutes les données quand le modal s'ouvre
  useEffect(() => {
    if (open && inscription) {
      loadAllData();
      // Revenir à l'historique si on était sur "edit" sans édition
      if (activeTab === "edit" && !editingPayment) {
        setActiveTab("history");
      }
    }
  }, [open, inscription, loadAllData, activeTab, editingPayment]);

  // Calculs mémorisés pour éviter les re-rendus inutiles
  const totalPaid = useMemo(() => {
    return payments.reduce((sum, p) => sum + Number(p.montant), 0);
  }, [payments]);

  const formationPrice = useMemo(() => {
    return inscription?.formations?.prix || 0;
  }, [inscription?.formations?.prix]);

  const avance = useMemo(() => {
    return inscription?.avance || 0;
  }, [inscription?.avance]);

  const handleSubmit = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inscription) return;

    const montant = parseFloat(formData.montant);
    if (isNaN(montant) || montant <= 0) {
      toast({
        title: "Erreur",
        description: "Veuillez saisir un montant valide",
        variant: "destructive"
      });
      return;
    }

    setLoading(true);
    try {
      const { error } = await supabase
        .from('paiements')
        .insert({
          inscription_id: inscription.id,
          montant: montant,
          date_paiement: formData.date_paiement,
          methode_paiement: formData.methode_paiement,
          numero_piece: formData.numero_piece || null,
          notes: formData.notes || null,
          created_by: (await supabase.auth.getUser()).data.user?.id
        });

      if (error) throw error;

      // Mise à jour locale immédiate pour éviter le clignotement
      const currentUserName = currentProfile 
        ? `${currentProfile.nom} ${currentProfile.prenom}` 
        : 'Utilisateur';

      const newPayment = {
        id: Date.now().toString(),
        inscription_id: inscription.id,
        montant: montant,
        date_paiement: formData.date_paiement,
        methode_paiement: formData.methode_paiement,
        numero_piece: formData.numero_piece || null,
        notes: formData.notes || null,
        created_by: (await supabase.auth.getUser()).data.user?.id || '',
        created_at: new Date().toISOString(),
        creator_name: currentUserName,
        paiement_id: Date.now().toString(),
        audit_count: 0,
        last_modified: null,
        last_modifier_name: null
      };
      
      setPayments(prev => [newPayment, ...prev]);
      setResteAPayer(prev => Math.max(0, prev - montant));

      toast({
        title: "Succès",
        description: "Paiement ajouté avec succès"
      });

      // Reset form
      setFormData({
        montant: '',
        date_paiement: new Date().toISOString().split('T')[0],
        methode_paiement: 'Espèces',
        numero_piece: '',
        notes: ''
      });

      // Recharger les données réelles en arrière-plan
      await loadAllData();
      
      // Retourner à l'onglet historique
      setActiveTab("history");
    } catch (error) {
      console.error('Error adding payment:', error);
      toast({
        title: "Erreur",
        description: "Impossible d'ajouter le paiement",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  }, [inscription, formData, toast, loadAllData]);

  const handleEdit = useCallback((payment: Payment) => {
    setEditingPayment(payment);
    setEditFormData({
      montant: payment.montant.toString(),
      date_paiement: payment.date_paiement.split('T')[0],
      methode_paiement: payment.methode_paiement,
      numero_piece: payment.numero_piece || '',
      notes: payment.notes || ''
    });
    setActiveTab("edit");
  }, []);

  const handleUpdatePayment = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingPayment) return;

    const montant = parseFloat(editFormData.montant);
    if (isNaN(montant) || montant <= 0) {
      toast({
        title: "Erreur",
        description: "Veuillez saisir un montant valide",
        variant: "destructive"
      });
      return;
    }

    setLoadingEdit(true);
    try {
      const { error } = await supabase
        .from('paiements')
        .update({
          montant: montant,
          date_paiement: editFormData.date_paiement,
          methode_paiement: editFormData.methode_paiement,
          numero_piece: editFormData.numero_piece || null,
          notes: editFormData.notes || null
        })
        .eq('id', editingPayment.id);

      if (error) throw error;

      // Mise à jour locale immédiate
      setPayments(prev => prev.map(p => 
        p.id === editingPayment.id 
          ? { ...p, 
              montant: montant,
              date_paiement: editFormData.date_paiement,
              methode_paiement: editFormData.methode_paiement,
              numero_piece: editFormData.numero_piece || null,
              notes: editFormData.notes || null
            }
          : p
      ));

      toast({
        title: "Succès",
        description: "Paiement modifié avec succès"
      });

      setEditingPayment(null);
      setActiveTab("history");
      
      // Recharger les données réelles en arrière-plan
      await loadAllData();
    } catch (error) {
      console.error('Error updating payment:', error);
      toast({
        title: "Erreur",
        description: "Impossible de modifier le paiement",
        variant: "destructive"
      });
    } finally {
      setLoadingEdit(false);
    }
  }, [editingPayment, editFormData, toast, loadAllData]);

  const handleDeleteClick = useCallback((payment: Payment) => {
    setPaymentToDelete(payment);
    setIsDeleteModalOpen(true);
  }, []);

  const handleDeleteConfirmed = useCallback(async () => {
    if (!paymentToDelete) return;
    
    // Mise à jour locale immédiate pour éviter le clignotement
    setPayments(prev => prev.filter(p => p.id !== paymentToDelete.id));
    setResteAPayer(prev => prev + paymentToDelete.montant);
    
    setIsDeleteModalOpen(false);
    setPaymentToDelete(null);
    setActiveTab("history");
    
    // Recharger les données réelles en arrière-plan
    await loadAllData();
    
    toast({
      title: "Succès",
      description: "Paiement supprimé avec succès"
    });
  }, [paymentToDelete, loadAllData, toast]);

  const getPaymentMethodColor = (method: string) => {
    const colors: Record<string, string> = {
      'Espèces': 'bg-green-100 text-green-800',
      'Chèque': 'bg-blue-100 text-blue-800',
      'Virement': 'bg-purple-100 text-purple-800',
      'Carte': 'bg-orange-100 text-orange-800'
    };
    return colors[method] || 'bg-gray-100 text-gray-800';
  };

  const handleQuickAmount = useCallback((percentage: number) => {
    const amount = Math.round(resteAPayer * percentage / 100);
    setFormData(prev => ({ ...prev, montant: amount.toString() }));
  }, [resteAPayer]);

  if (!inscription) return null;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-4xl max-h-[90vh] overflow-hidden">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <CreditCard className="h-5 w-5" />
            Gestion des Paiements - {inscription.etudiants.nom} {inscription.etudiants.prenom}
          </DialogTitle>
        </DialogHeader>

        {/* Informations financières */}
        <Card className="border-l-4 border-l-primary">
          <CardContent className="pt-4">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="text-center">
                <div className="text-2xl font-bold text-primary">{formationPrice} DH</div>
                <div className="text-sm text-muted-foreground">Prix formation</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-blue-600">{avance} DH</div>
                <div className="text-sm text-muted-foreground">Avance</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-green-600">{isLoading ? '...' : totalPaid} DH</div>
                <div className="text-sm text-muted-foreground">Total payé</div>
              </div>
              <div className="text-center">
                <div className={`text-2xl font-bold ${resteAPayer > 0 ? 'text-red-600' : 'text-green-600'}`}>
                  {isLoading ? '...' : `${resteAPayer} DH`}
                </div>
                <div className="text-sm text-muted-foreground">Reste à payer</div>
              </div>
            </div>
          </CardContent>
        </Card>

        <Tabs value={activeTab} onValueChange={setActiveTab} className="flex-1">
          <TabsList className="grid w-full grid-cols-3">
            <TabsTrigger value="history">Historique</TabsTrigger>
            <TabsTrigger value="add">Ajouter Paiement</TabsTrigger>
            <TabsTrigger value="edit" disabled={!editingPayment}>
              {editingPayment ? 'Modifier' : 'Modifier'}
            </TabsTrigger>
          </TabsList>

          <TabsContent value="add" className="space-y-4">
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label htmlFor="montant">Montant (DH) *</Label>
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
                  {resteAPayer > 0 && (
                    <div className="flex gap-2 mt-2">
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        onClick={() => handleQuickAmount(100)}
                      >
                        Solde complet
                      </Button>
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        onClick={() => handleQuickAmount(50)}
                      >
                        50%
                      </Button>
                    </div>
                  )}
                </div>

                <div>
                  <Label htmlFor="date_paiement">Date de paiement *</Label>
                  <Input
                    id="date_paiement"
                    type="date"
                    value={formData.date_paiement}
                    onChange={(e) => setFormData(prev => ({ ...prev, date_paiement: e.target.value }))}
                    required
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label htmlFor="methode_paiement">Méthode de paiement *</Label>
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
                      <SelectItem value="Virement">Virement</SelectItem>
                      <SelectItem value="Carte">Carte bancaire</SelectItem>
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
                      placeholder={formData.methode_paiement === 'Chèque' ? 'Ex: 1234567' : 'Ex: VIR123456'}
                    />
                  </div>
                )}
              </div>

              <div>
                <Label htmlFor="notes">Notes</Label>
                <Textarea
                  id="notes"
                  value={formData.notes}
                  onChange={(e) => setFormData(prev => ({ ...prev, notes: e.target.value }))}
                  placeholder="Notes complémentaires sur ce paiement..."
                  rows={3}
                />
              </div>

              <div className="flex justify-end gap-2">
                <Button 
                  type="button" 
                  variant="outline" 
                  onClick={() => onOpenChange(false)}
                >
                  Annuler
                </Button>
                <Button type="submit" disabled={loading}>
                  {loading ? 'Ajout...' : 'Ajouter le paiement'}
                </Button>
              </div>
            </form>
          </TabsContent>

          <TabsContent value="history" className="space-y-4">
            <ScrollArea className="h-[400px]">
              {isLoading ? (
                <div className="text-center py-8">Chargement de l'historique...</div>
              ) : payments.length === 0 ? (
                <div className="text-center py-8 text-muted-foreground">
                  Aucun paiement enregistré
                </div>
              ) : (
                <div className="space-y-3">
                  {payments.map((payment) => (
                    <Card key={payment.id} className="p-4">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          <div className="text-2xl font-bold text-primary">
                            {payment.montant} DH
                          </div>
                          <Badge className={getPaymentMethodColor(payment.methode_paiement)}>
                            {payment.methode_paiement}
                          </Badge>
                        </div>
                        <div className="flex items-center gap-2">
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => handleEdit(payment)}
                          >
                            <Edit className="h-4 w-4" />
                          </Button>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => handleDeleteClick(payment)}
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </div>
                      </div>
                      
                      <Separator className="my-2" />
                      
                      <div className="grid grid-cols-2 gap-4 text-sm">
                        <div>
                          <span className="text-muted-foreground">Date:</span>{' '}
                          {format(new Date(payment.date_paiement), 'dd MMMM yyyy', { locale: fr })}
                        </div>
                        <div>
                          <span className="text-muted-foreground">Créé par:</span>{' '}
                          {payment.creator_name || 'Inconnu'}
                        </div>
                        {payment.numero_piece && (
                          <div>
                            <span className="text-muted-foreground">N° pièce:</span>{' '}
                            {payment.numero_piece}
                          </div>
                        )}
                        {payment.audit_count && payment.audit_count > 0 && (
                          <div>
                            <span className="text-muted-foreground">Modifié:</span>{' '}
                            {payment.audit_count} fois
                          </div>
                        )}
                      </div>
                      
                      {payment.notes && (
                        <div className="mt-2 p-2 bg-muted rounded text-sm">
                          <span className="text-muted-foreground">Notes:</span> {payment.notes}
                        </div>
                      )}
                    </Card>
                  ))}
                </div>
              )}
            </ScrollArea>
          </TabsContent>

          <TabsContent value="edit" className="space-y-4">
            {editingPayment && (
              <form onSubmit={handleUpdatePayment} className="space-y-4">
                <div className="bg-muted p-3 rounded-lg">
                  <h4 className="font-medium">Modification du paiement #{editingPayment.id.slice(-8)}</h4>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label htmlFor="edit_montant">Montant (DH) *</Label>
                    <Input
                      id="edit_montant"
                      type="number"
                      step="0.01"
                      min="0"
                      value={editFormData.montant}
                      onChange={(e) => setEditFormData(prev => ({ ...prev, montant: e.target.value }))}
                      required
                    />
                  </div>

                  <div>
                    <Label htmlFor="edit_date_paiement">Date de paiement *</Label>
                    <Input
                      id="edit_date_paiement"
                      type="date"
                      value={editFormData.date_paiement}
                      onChange={(e) => setEditFormData(prev => ({ ...prev, date_paiement: e.target.value }))}
                      required
                    />
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label htmlFor="edit_methode_paiement">Méthode de paiement *</Label>
                    <Select
                      value={editFormData.methode_paiement}
                      onValueChange={(value) => setEditFormData(prev => ({ ...prev, methode_paiement: value }))}
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="Espèces">Espèces</SelectItem>
                        <SelectItem value="Chèque">Chèque</SelectItem>
                        <SelectItem value="Virement">Virement</SelectItem>
                        <SelectItem value="Carte">Carte bancaire</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  {(editFormData.methode_paiement === 'Chèque' || editFormData.methode_paiement === 'Virement') && (
                    <div>
                      <Label htmlFor="edit_numero_piece">
                        {editFormData.methode_paiement === 'Chèque' ? 'Numéro de chèque' : 'Référence virement'}
                      </Label>
                      <Input
                        id="edit_numero_piece"
                        value={editFormData.numero_piece}
                        onChange={(e) => setEditFormData(prev => ({ ...prev, numero_piece: e.target.value }))}
                      />
                    </div>
                  )}
                </div>

                <div>
                  <Label htmlFor="edit_notes">Notes</Label>
                  <Textarea
                    id="edit_notes"
                    value={editFormData.notes}
                    onChange={(e) => setEditFormData(prev => ({ ...prev, notes: e.target.value }))}
                    rows={3}
                  />
                </div>

                <div className="flex justify-end gap-2">
                  <Button 
                    type="button" 
                    variant="outline" 
                    onClick={() => {
                      setEditingPayment(null);
                      setActiveTab("history");
                    }}
                  >
                    Annuler
                  </Button>
                  <Button type="submit" disabled={loadingEdit}>
                    {loadingEdit ? 'Modification...' : 'Modifier le paiement'}
                  </Button>
                </div>
              </form>
            )}
          </TabsContent>
        </Tabs>

        {/* Modal de confirmation de suppression */}
        <ConfirmerSuppressionPaiementModal
          isOpen={isDeleteModalOpen}
          onOpenChange={setIsDeleteModalOpen}
          payment={paymentToDelete}
          onSuccess={handleDeleteConfirmed}
        />
      </DialogContent>
    </Dialog>
  );
};