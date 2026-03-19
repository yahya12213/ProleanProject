import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Switch } from '@/components/ui/switch';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { Plus, Edit, Trash2, Settings, BookOpen } from 'lucide-react';
import { supabase } from '@/integrations/supabase/client';
import { toast } from 'sonner';
import CorpsFormationFamillesManagement from './CorpsFormationFamillesManagement';
import CorpsFormationFormationsManagement from './CorpsFormationFormationsManagement';

interface CorpsFormation {
  id: string;
  nom: string;
  description: string | null;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

const CorpsFormationManagement: React.FC = () => {
  const [corpsFormations, setCorpsFormations] = useState<CorpsFormation[]>([]);
  const [loading, setLoading] = useState(true);
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [editingCorps, setEditingCorps] = useState<CorpsFormation | null>(null);
  const [selectedCorpsForFamilies, setSelectedCorpsForFamilies] = useState<CorpsFormation | null>(null);
  const [selectedCorpsForFormations, setSelectedCorpsForFormations] = useState<CorpsFormation | null>(null);
  const [formData, setFormData] = useState({
    nom: '',
    description: '',
    is_active: true
  });

  useEffect(() => {
    loadCorpsFormations();
  }, []);

  const loadCorpsFormations = async () => {
    try {
      const { data, error } = await supabase
        .from('corps_formation')
        .select('*')
        .order('nom');

      if (error) throw error;
      setCorpsFormations(data || []);
    } catch (error) {
      console.error('Erreur lors du chargement des corps de formation:', error);
      toast.error('Erreur lors du chargement des corps de formation');
    } finally {
      setLoading(false);
    }
  };

  const resetForm = () => {
    setFormData({
      nom: '',
      description: '',
      is_active: true
    });
    setEditingCorps(null);
  };

  const handleEdit = (corps: CorpsFormation) => {
    setEditingCorps(corps);
    setFormData({
      nom: corps.nom,
      description: corps.description || '',
      is_active: corps.is_active
    });
    setIsDialogOpen(true);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!formData.nom.trim()) {
      toast.error('Le nom est requis');
      return;
    }

    try {
      if (editingCorps) {
        const { error } = await supabase
          .from('corps_formation')
          .update(formData)
          .eq('id', editingCorps.id);

        if (error) throw error;
        toast.success('Corps de formation modifié avec succès');
      } else {
        const { error } = await supabase
          .from('corps_formation')
          .insert([formData]);

        if (error) throw error;
        toast.success('Corps de formation créé avec succès');
      }

      await loadCorpsFormations();
      setIsDialogOpen(false);
      resetForm();
    } catch (error) {
      console.error('Erreur lors de la sauvegarde:', error);
      toast.error('Erreur lors de la sauvegarde');
    }
  };

  const handleDelete = async (corps: CorpsFormation) => {
    if (!confirm(`Êtes-vous sûr de vouloir supprimer le corps de formation "${corps.nom}" ?`)) {
      return;
    }

    try {
      const { error } = await supabase
        .from('corps_formation')
        .delete()
        .eq('id', corps.id);

      if (error) throw error;
      toast.success('Corps de formation supprimé');
      await loadCorpsFormations();
    } catch (error) {
      console.error('Erreur lors de la suppression:', error);
      toast.error('Erreur lors de la suppression');
    }
  };

  if (loading) {
    return <div className="flex justify-center items-center h-64">Chargement...</div>;
  }

  if (selectedCorpsForFamilies) {
    return (
      <CorpsFormationFamillesManagement
        corpsFormation={selectedCorpsForFamilies}
        onBack={() => setSelectedCorpsForFamilies(null)}
      />
    );
  }

  if (selectedCorpsForFormations) {
    return (
      <CorpsFormationFormationsManagement
        corpsFormation={selectedCorpsForFormations}
        onBack={() => setSelectedCorpsForFormations(null)}
      />
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-bold">Gestion des Corps de Formation</h2>
        <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
          <DialogTrigger asChild>
            <Button onClick={resetForm}>
              <Plus className="h-4 w-4 mr-2" />
              Nouveau Corps de Formation
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>
                {editingCorps ? 'Modifier le Corps de Formation' : 'Nouveau Corps de Formation'}
              </DialogTitle>
            </DialogHeader>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <Label htmlFor="nom">Nom *</Label>
                <Input
                  id="nom"
                  value={formData.nom}
                  onChange={(e) => setFormData({ ...formData, nom: e.target.value })}
                  placeholder="Nom du corps de formation"
                  required
                />
              </div>
              <div>
                <Label htmlFor="description">Description</Label>
                <Textarea
                  id="description"
                  value={formData.description}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                  placeholder="Description du corps de formation"
                />
              </div>
              <div className="flex items-center space-x-2">
                <Switch
                  id="is_active"
                  checked={formData.is_active}
                  onCheckedChange={(checked) => setFormData({ ...formData, is_active: checked })}
                />
                <Label htmlFor="is_active">Actif</Label>
              </div>
              <div className="flex justify-end gap-2">
                <Button type="button" variant="outline" onClick={() => setIsDialogOpen(false)}>
                  Annuler
                </Button>
                <Button type="submit">
                  {editingCorps ? 'Modifier' : 'Créer'}
                </Button>
              </div>
            </form>
          </DialogContent>
        </Dialog>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Liste des Corps de Formation</CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Nom</TableHead>
                <TableHead>Description</TableHead>
                <TableHead>Statut</TableHead>
                <TableHead>Date de création</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {corpsFormations.map((corps) => (
                <TableRow key={corps.id}>
                  <TableCell className="font-medium">{corps.nom}</TableCell>
                  <TableCell>{corps.description || '-'}</TableCell>
                  <TableCell>
                    <Badge variant={corps.is_active ? "default" : "secondary"}>
                      {corps.is_active ? 'Actif' : 'Inactif'}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    {new Date(corps.created_at).toLocaleDateString('fr-FR')}
                  </TableCell>
                  <TableCell>
                    <div className="flex gap-2">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => setSelectedCorpsForFormations(corps)}
                        title="Gérer les formations"
                      >
                        <BookOpen className="h-4 w-4" />
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => setSelectedCorpsForFamilies(corps)}
                        title="Gérer les familles"
                      >
                        <Settings className="h-4 w-4" />
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => handleEdit(corps)}
                        title="Modifier"
                      >
                        <Edit className="h-4 w-4" />
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => handleDelete(corps)}
                        title="Supprimer"
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

export default CorpsFormationManagement;