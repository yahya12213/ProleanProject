import React, { useState, useEffect } from 'react';
import { supabase } from '@/integrations/supabase/client';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Textarea } from '@/components/ui/textarea';
import { Separator } from '@/components/ui/separator';
import { AlertCircle, History, Plus, Calendar, DollarSign, Clock } from 'lucide-react';
import { toast } from '@/components/ui/use-toast';
import { format } from 'date-fns';
import { fr } from 'date-fns/locale';

interface SalaryAdvanceManagerProps {
  profileId: string;
  profileName: string;
}

interface SalaryAdvance {
  id: string;
  montant_avance: number;
  retenue_mensuelle: number;
  date_octroi: string;
  date_debut_retenue: string;
  nombre_traites_total: number;
  traites_payees: number;
  statut: string;
  motif?: string;
  notes?: string;
}

interface AdvanceInstallment {
  id: string;
  mois_echeance: string;
  montant: number;
  statut_paiement: string;
  date_paiement?: string;
}

export default function SalaryAdvanceManager({ profileId, profileName }: SalaryAdvanceManagerProps) {
  const [advances, setAdvances] = useState<SalaryAdvance[]>([]);
  const [installments, setInstallments] = useState<AdvanceInstallment[]>([]);
  const [selectedAdvanceId, setSelectedAdvanceId] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [newAdvanceOpen, setNewAdvanceOpen] = useState(false);
  const [historyOpen, setHistoryOpen] = useState(false);

  // État pour le nouveau formulaire d'avance
  const [formData, setFormData] = useState({
    montant_avance: '',
    retenue_mensuelle: '',
    date_debut_retenue: '',
    motif: '',
    notes: ''
  });

  const [calculatedMonths, setCalculatedMonths] = useState(0);

  useEffect(() => {
    loadAdvances();
  }, [profileId]);

  // Calcul automatique du nombre de mois
  useEffect(() => {
    const montant = parseFloat(formData.montant_avance);
    const retenue = parseFloat(formData.retenue_mensuelle);
    
    if (montant > 0 && retenue > 0) {
      const months = Math.ceil(montant / retenue);
      setCalculatedMonths(months);
    } else {
      setCalculatedMonths(0);
    }
  }, [formData.montant_avance, formData.retenue_mensuelle]);

  const loadAdvances = async () => {
    try {
      const { data, error } = await supabase
        .from('salary_advances')
        .select('*')
        .eq('profile_id', profileId)
        .order('created_at', { ascending: false });

      if (error) throw error;
      setAdvances(data || []);
    } catch (error) {
      console.error('Erreur lors du chargement des avances:', error);
      toast({
        title: "Erreur",
        description: "Impossible de charger les avances sur salaire",
        variant: "destructive"
      });
    }
  };

  const loadInstallments = async (advanceId: string) => {
    try {
      const { data, error } = await supabase
        .from('salary_advance_installments')
        .select('*')
        .eq('advance_id', advanceId)
        .order('mois_echeance', { ascending: true });

      if (error) throw error;
      setInstallments(data || []);
      setSelectedAdvanceId(advanceId);
    } catch (error) {
      console.error('Erreur lors du chargement des échéances:', error);
      toast({
        title: "Erreur",
        description: "Impossible de charger les échéances",
        variant: "destructive"
      });
    }
  };

  const createAdvance = async () => {
    if (!formData.montant_avance || !formData.retenue_mensuelle || !formData.date_debut_retenue) {
      toast({
        title: "Erreur",
        description: "Veuillez remplir tous les champs obligatoires",
        variant: "destructive"
      });
      return;
    }

    setLoading(true);
    try {
      const { error } = await supabase
        .from('salary_advances')
        .insert({
          profile_id: profileId,
          montant_avance: parseFloat(formData.montant_avance),
          retenue_mensuelle: parseFloat(formData.retenue_mensuelle),
          date_debut_retenue: formData.date_debut_retenue,
          nombre_traites_total: calculatedMonths,
          motif: formData.motif || null,
          notes: formData.notes || null,
          created_by: (await supabase.auth.getUser()).data.user?.id
        });

      if (error) throw error;

      toast({
        title: "Succès",
        description: "Avance sur salaire créée avec succès"
      });

      setNewAdvanceOpen(false);
      setFormData({
        montant_avance: '',
        retenue_mensuelle: '',
        date_debut_retenue: '',
        motif: '',
        notes: ''
      });
      loadAdvances();
    } catch (error) {
      console.error('Erreur lors de la création de l\'avance:', error);
      toast({
        title: "Erreur",
        description: "Impossible de créer l'avance sur salaire",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const getStatusBadge = (statut: string) => {
    switch (statut) {
      case 'en_cours':
        return <Badge variant="default">En cours</Badge>;
      case 'termine':
        return <Badge variant="secondary">Terminé</Badge>;
      case 'annule':
        return <Badge variant="destructive">Annulé</Badge>;
      default:
        return <Badge>{statut}</Badge>;
    }
  };

  const getPaymentStatusBadge = (statut: string) => {
    switch (statut) {
      case 'en_attente':
        return <Badge variant="outline">En attente</Badge>;
      case 'paye':
        return <Badge variant="secondary">Payé</Badge>;
      case 'reporte':
        return <Badge variant="destructive">Reporté</Badge>;
      default:
        return <Badge>{statut}</Badge>;
    }
  };

  const activeAdvances = advances.filter(adv => adv.statut === 'en_cours');
  const totalCurrentAdvances = activeAdvances.reduce((sum, adv) => sum + (adv.montant_avance - (adv.traites_payees * adv.retenue_mensuelle)), 0);

  return (
    <div className="space-y-6">
      {/* En-tête avec résumé */}
      <div className="flex justify-between items-start">
        <div>
          <h3 className="text-lg font-semibold">Avances sur Salaire</h3>
          <p className="text-sm text-muted-foreground">Gestion des avances pour {profileName}</p>
        </div>
        <div className="flex gap-2">
          <Dialog open={historyOpen} onOpenChange={setHistoryOpen}>
            <DialogTrigger asChild>
              <Button variant="outline" size="sm">
                <History className="h-4 w-4 mr-2" />
                Historique
              </Button>
            </DialogTrigger>
            <DialogContent className="max-w-4xl max-h-[80vh] overflow-y-auto">
              <DialogHeader>
                <DialogTitle>Historique des Avances</DialogTitle>
                <DialogDescription>
                  Toutes les avances accordées à {profileName}
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-4">
                {advances.map((advance) => (
                  <Card key={advance.id}>
                    <CardHeader className="pb-3">
                      <div className="flex justify-between items-start">
                        <div>
                          <CardTitle className="text-base">{advance.montant_avance} MAD</CardTitle>
                          <CardDescription>
                            {advance.retenue_mensuelle} MAD/mois · {advance.traites_payees}/{advance.nombre_traites_total} traites
                          </CardDescription>
                        </div>
                        {getStatusBadge(advance.statut)}
                      </div>
                    </CardHeader>
                    <CardContent>
                      <div className="grid grid-cols-2 gap-4 text-sm">
                        <div>
                          <span className="font-medium">Date d'octroi:</span> {format(new Date(advance.date_octroi), 'dd/MM/yyyy', { locale: fr })}
                        </div>
                        <div>
                          <span className="font-medium">Début retenues:</span> {format(new Date(advance.date_debut_retenue), 'dd/MM/yyyy', { locale: fr })}
                        </div>
                        {advance.motif && (
                          <div className="col-span-2">
                            <span className="font-medium">Motif:</span> {advance.motif}
                          </div>
                        )}
                      </div>
                      <Button
                        variant="outline"
                        size="sm"
                        className="mt-3"
                        onClick={() => loadInstallments(advance.id)}
                      >
                        Voir les échéances
                      </Button>
                    </CardContent>
                  </Card>
                ))}
              </div>
            </DialogContent>
          </Dialog>

          <Dialog open={newAdvanceOpen} onOpenChange={setNewAdvanceOpen}>
            <DialogTrigger asChild>
              <Button size="sm">
                <Plus className="h-4 w-4 mr-2" />
                Nouvelle Avance
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Nouvelle Avance sur Salaire</DialogTitle>
                <DialogDescription>
                  Créer une nouvelle avance pour {profileName}
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label htmlFor="montant_avance">Montant de l'avance (MAD) *</Label>
                    <Input
                      id="montant_avance"
                      type="number"
                      step="0.01"
                      value={formData.montant_avance}
                      onChange={(e) => setFormData({...formData, montant_avance: e.target.value})}
                      placeholder="1000.00"
                    />
                  </div>
                  <div>
                    <Label htmlFor="retenue_mensuelle">Retenue mensuelle (MAD) *</Label>
                    <Input
                      id="retenue_mensuelle"
                      type="number"
                      step="0.01"
                      value={formData.retenue_mensuelle}
                      onChange={(e) => setFormData({...formData, retenue_mensuelle: e.target.value})}
                      placeholder="250.00"
                    />
                  </div>
                </div>

                {calculatedMonths > 0 && (
                  <Card className="bg-muted/50">
                    <CardContent className="pt-4">
                      <div className="flex items-center gap-2">
                        <Clock className="h-4 w-4 text-primary" />
                        <span className="font-medium">Durée calculée: {calculatedMonths} mois</span>
                      </div>
                    </CardContent>
                  </Card>
                )}

                <div>
                  <Label htmlFor="date_debut_retenue">Date de début des retenues *</Label>
                  <Input
                    id="date_debut_retenue"
                    type="date"
                    value={formData.date_debut_retenue}
                    onChange={(e) => setFormData({...formData, date_debut_retenue: e.target.value})}
                  />
                </div>

                <div>
                  <Label htmlFor="motif">Motif</Label>
                  <Input
                    id="motif"
                    value={formData.motif}
                    onChange={(e) => setFormData({...formData, motif: e.target.value})}
                    placeholder="Ex: Urgence familiale, frais médicaux..."
                  />
                </div>

                <div>
                  <Label htmlFor="notes">Notes internes</Label>
                  <Textarea
                    id="notes"
                    value={formData.notes}
                    onChange={(e) => setFormData({...formData, notes: e.target.value})}
                    placeholder="Notes ou commentaires..."
                    rows={3}
                  />
                </div>

                <div className="flex justify-end gap-2">
                  <Button variant="outline" onClick={() => setNewAdvanceOpen(false)}>
                    Annuler
                  </Button>
                  <Button onClick={createAdvance} disabled={loading}>
                    {loading ? "Création..." : "Créer l'avance"}
                  </Button>
                </div>
              </div>
            </DialogContent>
          </Dialog>
        </div>
      </div>

      {/* Résumé des avances actives */}
      {activeAdvances.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <AlertCircle className="h-4 w-4 text-orange-500" />
              Avances en cours
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="text-center">
                <div className="text-2xl font-bold text-primary">{activeAdvances.length}</div>
                <div className="text-xs text-muted-foreground">Avance(s) active(s)</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-orange-600">{totalCurrentAdvances.toFixed(2)} MAD</div>
                <div className="text-xs text-muted-foreground">Reste à rembourser</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-green-600">
                  {activeAdvances.reduce((sum, adv) => sum + adv.retenue_mensuelle, 0).toFixed(2)} MAD
                </div>
                <div className="text-xs text-muted-foreground">Retenue mensuelle totale</div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Liste des avances actives avec détails */}
      {activeAdvances.map((advance) => (
        <Card key={advance.id}>
          <CardHeader>
            <div className="flex justify-between items-start">
              <div>
                <CardTitle className="flex items-center gap-2">
                  <DollarSign className="h-4 w-4" />
                  {advance.montant_avance} MAD
                </CardTitle>
                <CardDescription>
                  Retenue: {advance.retenue_mensuelle} MAD/mois · Progression: {advance.traites_payees}/{advance.nombre_traites_total}
                </CardDescription>
              </div>
              {getStatusBadge(advance.statut)}
            </div>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                <div>
                  <span className="font-medium">Date d'octroi:</span>
                  <div>{format(new Date(advance.date_octroi), 'dd/MM/yyyy', { locale: fr })}</div>
                </div>
                <div>
                  <span className="font-medium">Début retenues:</span>
                  <div>{format(new Date(advance.date_debut_retenue), 'dd/MM/yyyy', { locale: fr })}</div>
                </div>
                <div>
                  <span className="font-medium">Reste à payer:</span>
                  <div className="font-bold text-orange-600">
                    {(advance.montant_avance - (advance.traites_payees * advance.retenue_mensuelle)).toFixed(2)} MAD
                  </div>
                </div>
                <div>
                  <span className="font-medium">Traites restantes:</span>
                  <div className="font-bold">
                    {advance.nombre_traites_total - advance.traites_payees} mois
                  </div>
                </div>
              </div>

              {advance.motif && (
                <div>
                  <span className="font-medium text-sm">Motif:</span>
                  <div className="text-sm">{advance.motif}</div>
                </div>
              )}

              <Separator />

              <Button
                variant="outline"
                size="sm"
                onClick={() => loadInstallments(advance.id)}
              >
                <Calendar className="h-4 w-4 mr-2" />
                Voir le planning des échéances
              </Button>
            </div>
          </CardContent>
        </Card>
      ))}

      {/* Dialog pour afficher les échéances */}
      {selectedAdvanceId && (
        <Dialog open={!!selectedAdvanceId} onOpenChange={() => setSelectedAdvanceId(null)}>
          <DialogContent className="max-w-2xl">
            <DialogHeader>
              <DialogTitle>Échéances de l'avance</DialogTitle>
              <DialogDescription>
                Planning détaillé des retenues mensuelles
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-2 max-h-96 overflow-y-auto">
              {installments.map((installment, index) => (
                <div
                  key={installment.id}
                  className="flex justify-between items-center p-3 border rounded-lg"
                >
                  <div>
                    <div className="font-medium">
                      Mois {index + 1} - {format(new Date(installment.mois_echeance), 'MMMM yyyy', { locale: fr })}
                    </div>
                    <div className="text-sm text-muted-foreground">
                      {installment.montant.toFixed(2)} MAD
                    </div>
                  </div>
                  <div className="text-right">
                    {getPaymentStatusBadge(installment.statut_paiement)}
                    {installment.date_paiement && (
                      <div className="text-xs text-muted-foreground mt-1">
                        Payé le {format(new Date(installment.date_paiement), 'dd/MM/yyyy', { locale: fr })}
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </DialogContent>
        </Dialog>
      )}

      {advances.length === 0 && (
        <Card>
          <CardContent className="text-center py-8">
            <DollarSign className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
            <h3 className="text-lg font-medium mb-2">Aucune avance sur salaire</h3>
            <p className="text-muted-foreground mb-4">
              Aucune avance n'a encore été accordée à cet employé.
            </p>
            <Button onClick={() => setNewAdvanceOpen(true)}>
              <Plus className="h-4 w-4 mr-2" />
              Créer la première avance
            </Button>
          </CardContent>
        </Card>
      )}
    </div>
  );
}