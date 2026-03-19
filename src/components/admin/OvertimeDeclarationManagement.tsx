import React, { useState, useEffect, useCallback } from 'react';
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { useToast } from "@/hooks/use-toast";
import { Plus, Edit, Trash2, Check, X } from "lucide-react";
import { format } from "date-fns";
import { fr } from "date-fns/locale/fr"; // Corrected import
import axios from 'axios';

interface Profile {
  id: string;
  nom: string;
  prenom: string;
  email: string;
  poste?: string;
}

interface OvertimeDeclaration {
  id: string;
  profile_id: string;
  date_debut: string;
  date_fin: string;
  heures_max_autorisees: number;
  type_autorisation: string;
  statut: string;
  motif?: string;
  commentaires?: string;
  created_at: string;
  profiles: Profile;
}

const OvertimeDeclarationManagement: React.FC = () => {
  const [declarations, setDeclarations] = useState<OvertimeDeclaration[]>([]);
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [loading, setLoading] = useState(true);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editingDeclaration, setEditingDeclaration] = useState<OvertimeDeclaration | null>(null);
  const { toast } = useToast();

  const [formData, setFormData] = useState({
    profile_id: '',
    date_debut: '',
    date_fin: '',
    heures_max_autorisees: '',
    type_autorisation: 'ponctuelle',
    motif: '',
    commentaires: ''
  });

  const loadData = useCallback(async () => {
    try {
      setLoading(true);
      
      // Charger les profils
      const profilesResponse = await axios.get('/api/profiles');
      setProfiles(profilesResponse.data || []);

      // Charger les déclarations d'heures sup
      const declarationsResponse = await axios.get('/api/declarations_heures_sup');
      setDeclarations(declarationsResponse.data || []);
    } catch (error) {
      console.error('Erreur lors du chargement:', error);
      toast({
        title: "Erreur",
        description: "Impossible de charger les données",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  }, [toast]); // Added 'toast' to dependencies

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    try {
      const dataToSubmit = {
        profile_id: formData.profile_id,
        date_debut: formData.date_debut,
        date_fin: formData.date_fin,
        heures_max_autorisees: parseFloat(formData.heures_max_autorisees),
        type_autorisation: formData.type_autorisation,
        motif: formData.motif || null,
        commentaires: formData.commentaires || null,
        statut: 'en_attente'
      };

      if (editingDeclaration) {
        await axios.put(`/api/declarations_heures_sup/${editingDeclaration.id}`, dataToSubmit);
        
        toast({
          title: "Succès",
          description: "Déclaration modifiée avec succès",
        });
      } else {
        await axios.post('/api/declarations_heures_sup', dataToSubmit);
        
        toast({
          title: "Succès",
          description: "Déclaration créée avec succès",
        });
      }

      setDialogOpen(false);
      resetForm();
      loadData();
    } catch (error) {
      console.error('Erreur lors de la sauvegarde:', error);
      toast({
        title: "Erreur",
        description: "Impossible de sauvegarder la déclaration",
        variant: "destructive",
      });
    }
  };

  const handleApprove = async (id: string) => {
    try {
      await axios.patch(`/api/declarations_heures_sup/${id}/approve`);
      
      toast({
        title: "Succès",
        description: "Déclaration approuvée",
      });
      loadData();
    } catch (error) {
      console.error('Erreur:', error);
      toast({
        title: "Erreur",
        description: "Impossible d'approuver la déclaration",
        variant: "destructive",
      });
    }
  };

  const handleReject = async (id: string) => {
    try {
      await axios.patch(`/api/declarations_heures_sup/${id}/reject`);
      
      toast({
        title: "Succès",
        description: "Déclaration refusée",
      });
      loadData();
    } catch (error) {
      console.error('Erreur:', error);
      toast({
        title: "Erreur",
        description: "Impossible de refuser la déclaration",
        variant: "destructive",
      });
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await axios.delete(`/api/declarations_heures_sup/${id}`);
      
      toast({
        title: "Succès",
        description: "Déclaration supprimée",
      });
      loadData();
    } catch (error) {
      console.error('Erreur:', error);
      toast({
        title: "Erreur",
        description: "Impossible de supprimer la déclaration",
        variant: "destructive",
      });
    }
  };

  const openEditDialog = (declaration: OvertimeDeclaration) => {
    setEditingDeclaration(declaration);
    setFormData({
      profile_id: declaration.profile_id,
      date_debut: declaration.date_debut,
      date_fin: declaration.date_fin,
      heures_max_autorisees: declaration.heures_max_autorisees.toString(),
      type_autorisation: declaration.type_autorisation,
      motif: declaration.motif || '',
      commentaires: declaration.commentaires || ''
    });
    setDialogOpen(true);
  };

  const resetForm = () => {
    setFormData({
      profile_id: '',
      date_debut: '',
      date_fin: '',
      heures_max_autorisees: '',
      type_autorisation: 'ponctuelle',
      motif: '',
      commentaires: ''
    });
    setEditingDeclaration(null);
  };

  const getStatusBadge = (statut: string) => {
    switch (statut) {
      case 'approuve':
        return <Badge variant="default" className="bg-green-500">Approuvée</Badge>;
      case 'refuse':
        return <Badge variant="destructive">Refusée</Badge>;
      case 'en_attente':
        return <Badge variant="secondary">En attente</Badge>;
      default:
        return <Badge variant="outline">{statut}</Badge>;
    }
  };

  if (loading) {
    return <div className="p-6">Chargement...</div>;
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold">Déclarations d'heures supplémentaires</h2>
          <p className="text-muted-foreground">
            Gérez les autorisations d'heures supplémentaires pour vos employés
          </p>
        </div>
        
        <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
          <DialogTrigger asChild>
            <Button onClick={() => { resetForm(); setDialogOpen(true); }}>
              <Plus className="h-4 w-4 mr-2" />
              Nouvelle déclaration
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-md">
            <DialogHeader>
              <DialogTitle>
                {editingDeclaration ? 'Modifier' : 'Nouvelle'} déclaration d'heures sup
              </DialogTitle>
            </DialogHeader>
            
            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <Label htmlFor="profile_id">Employé</Label>
                <Select 
                  value={formData.profile_id} 
                  onValueChange={(value) => setFormData({...formData, profile_id: value})}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Sélectionner un employé" />
                  </SelectTrigger>
                  <SelectContent>
                    {profiles.map((profile) => (
                      <SelectItem key={profile.id} value={profile.id}>
                        {profile.nom} {profile.prenom} - {profile.poste}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label htmlFor="date_debut">Date début</Label>
                  <Input
                    id="date_debut"
                    type="date"
                    value={formData.date_debut}
                    onChange={(e) => setFormData({...formData, date_debut: e.target.value})}
                    required
                  />
                </div>
                <div>
                  <Label htmlFor="date_fin">Date fin</Label>
                  <Input
                    id="date_fin"
                    type="date"
                    value={formData.date_fin}
                    onChange={(e) => setFormData({...formData, date_fin: e.target.value})}
                    required
                  />
                </div>
              </div>
              
              <div>
                <Label htmlFor="heures_max_autorisees">Heures max autorisées</Label>
                <Input
                  id="heures_max_autorisees"
                  type="number"
                  step="0.5"
                  min="0"
                  value={formData.heures_max_autorisees}
                  onChange={(e) => setFormData({...formData, heures_max_autorisees: e.target.value})}
                  required
                />
              </div>
              
              <div>
                <Label htmlFor="type_autorisation">Type d'autorisation</Label>
                <Select 
                  value={formData.type_autorisation} 
                  onValueChange={(value) => setFormData({...formData, type_autorisation: value})}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="ponctuelle">Ponctuelle</SelectItem>
                    <SelectItem value="recurrente">Récurrente</SelectItem>
                    <SelectItem value="urgence">Urgence</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              
              <div>
                <Label htmlFor="motif">Motif</Label>
                <Textarea
                  id="motif"
                  value={formData.motif}
                  onChange={(e) => setFormData({...formData, motif: e.target.value})}
                  placeholder="Raison de la demande d'heures supplémentaires"
                />
              </div>
              
              <div className="flex justify-end gap-2">
                <Button type="button" variant="outline" onClick={() => setDialogOpen(false)}>
                  Annuler
                </Button>
                <Button type="submit">
                  {editingDeclaration ? 'Modifier' : 'Créer'}
                </Button>
              </div>
            </form>
          </DialogContent>
        </Dialog>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Liste des déclarations</CardTitle>
          <CardDescription>
            {declarations.length} déclaration(s) d'heures supplémentaires
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Employé</TableHead>
                <TableHead>Période</TableHead>
                <TableHead>Heures max</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Statut</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {declarations.map((declaration) => (
                <TableRow key={declaration.id}>
                  <TableCell>
                    <div>
                      <div className="font-medium">
                        {declaration.profiles.nom} {declaration.profiles.prenom}
                      </div>
                      <div className="text-sm text-muted-foreground">
                        {declaration.profiles.poste}
                      </div>
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="text-sm">
                      {format(new Date(declaration.date_debut), 'dd MMM', { locale: fr })} - {' '}
                      {format(new Date(declaration.date_fin), 'dd MMM yyyy', { locale: fr })}
                    </div>
                  </TableCell>
                  <TableCell>{declaration.heures_max_autorisees}h</TableCell>
                  <TableCell className="capitalize">{declaration.type_autorisation}</TableCell>
                  <TableCell>{getStatusBadge(declaration.statut)}</TableCell>
                  <TableCell>
                    <div className="flex gap-2">
                      {declaration.statut === 'en_attente' && (
                        <>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => handleApprove(declaration.id)}
                          >
                            <Check className="h-4 w-4" />
                          </Button>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => handleReject(declaration.id)}
                          >
                            <X className="h-4 w-4" />
                          </Button>
                        </>
                      )}
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => openEditDialog(declaration)}
                      >
                        <Edit className="h-4 w-4" />
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => handleDelete(declaration.id)}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
};

export default OvertimeDeclarationManagement;