import React, { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Plus, Edit, Trash2, Filter, FileText, ArrowLeft } from 'lucide-react';
import { supabase } from '@/integrations/supabase/client';
import { toast } from 'sonner';
import { FormationDocumentsManagement } from './FormationDocumentsManagement';

interface Formation {
  id: string;
  titre: string;
  description?: string;
  prix?: number;
  horaire: string;
  is_active: boolean;
  type_formation: 'physique';
  corps_formation_id?: string;
}

interface CorpsFormation {
  id: string;
  nom: string;
  description: string | null;
}

interface CorpsFormationFormationsManagementProps {
  corpsFormation: CorpsFormation;
  onBack: () => void;
}


const horaireOptions = [
  { value: 'matin', label: 'Matin' },
  { value: 'soir', label: 'Soir' },
  { value: 'toute_la_journee', label: 'Toute la journée' }
];

const CorpsFormationFormationsManagement: React.FC<CorpsFormationFormationsManagementProps> = ({
  corpsFormation,
  onBack
}) => {
  const [formations, setFormations] = useState<Formation[]>([]);
  const [loading, setLoading] = useState(true);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [editingFormation, setEditingFormation] = useState<Formation | null>(null);
  const [filteredFormations, setFilteredFormations] = useState<Formation[]>([]);
  const [filters, setFilters] = useState({
    prix_min: '',
    prix_max: '',
    horaire: 'all',
    statut: 'all'
  });
  const [showDocumentsManagement, setShowDocumentsManagement] = useState(false);
  const [selectedFormation, setSelectedFormation] = useState<Formation | null>(null);

  const [formData, setFormData] = useState({
    titre: '',
    description: '',
    prix: 0,
    horaire: 'matin',
    is_active: true
  });

  useEffect(() => {
    loadFormations();
  }, [corpsFormation.id]);

  const loadFormations = async () => {
    try {
      setLoading(true);
      const { data, error } = await supabase
        .from('formations')
        .select('*')
        .eq('type_formation', 'physique')
        .eq('corps_formation_id', corpsFormation.id)
        .order('titre');

      if (error) throw error;
      const formationsData = data?.map(item => ({
        id: item.id,
        titre: item.titre,
        description: item.description,
        prix: item.prix || 0,
        horaire: item.horaire || 'matin',
        is_active: item.is_active,
        type_formation: 'physique' as const,
        corps_formation_id: item.corps_formation_id
      })) || [];
      
      setFormations(formationsData);
      setFilteredFormations(formationsData);
    } catch (error) {
      console.error('Error loading formations:', error);
      toast.error('Impossible de charger les formations');
    } finally {
      setLoading(false);
    }
  };

  const resetForm = () => {
    setFormData({
      titre: '',
      description: '',
      prix: 0,
      horaire: 'matin',
      is_active: true
    });
    setEditingFormation(null);
  };

  const handleEdit = (formation: Formation) => {
    setFormData({
      titre: formation.titre,
      description: formation.description || '',
      prix: formation.prix || 0,
      horaire: formation.horaire,
      is_active: formation.is_active
    });
    setEditingFormation(formation);
    setIsModalOpen(true);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!formData.titre.trim()) {
      toast.error('Le titre est requis');
      return;
    }

    try {
      const dataToSave = {
        ...formData,
        duree_heures: 0,
        niveau: 'debutant',
        type_formation: 'physique' as const,
        corps_formation_id: corpsFormation.id
      };

      if (editingFormation) {
        const { error } = await supabase
          .from('formations')
          .update(dataToSave)
          .eq('id', editingFormation.id);
        
        if (error) throw error;
        toast.success('Formation mise à jour avec succès');
      } else {
        const { error } = await supabase
          .from('formations')
          .insert([dataToSave]);
        
        if (error) throw error;
        toast.success('Formation créée avec succès');
      }

      setIsModalOpen(false);
      resetForm();
      loadFormations();
    } catch (error) {
      console.error('Error saving formation:', error);
      toast.error('Impossible de sauvegarder la formation');
    }
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Êtes-vous sûr de vouloir supprimer cette formation ?')) return;

    try {
      const { error } = await supabase
        .from('formations')
        .delete()
        .eq('id', id);

      if (error) {
        if (error.code === '23503') {
          toast.error('Cette formation ne peut pas être supprimée car elle est utilisée dans des classes existantes.');
          return;
        }
        throw error;
      }

      toast.success('Formation supprimée avec succès');
      loadFormations();
    } catch (error) {
      console.error('Error deleting formation:', error);
      toast.error('Impossible de supprimer la formation');
    }
  };


  const applyFilters = () => {
    let filtered = formations;

    if (filters.prix_min) {
      filtered = filtered.filter(formation => formation.prix >= parseFloat(filters.prix_min));
    }

    if (filters.prix_max) {
      filtered = filtered.filter(formation => formation.prix <= parseFloat(filters.prix_max));
    }

    if (filters.horaire && filters.horaire !== 'all') {
      filtered = filtered.filter(formation => formation.horaire === filters.horaire);
    }

    if (filters.statut && filters.statut !== 'all') {
      const isActive = filters.statut === 'actif';
      filtered = filtered.filter(formation => formation.is_active === isActive);
    }

    setFilteredFormations(filtered);
  };

  useEffect(() => {
    applyFilters();
  }, [formations, filters]);

  if (loading) {
    return <div className="flex justify-center items-center h-64">Chargement...</div>;
  }

  if (showDocumentsManagement && selectedFormation) {
    return (
      <FormationDocumentsManagement
        formationId={selectedFormation.id}
        formationTitre={selectedFormation.titre}
        onBack={() => {
          setShowDocumentsManagement(false);
          setSelectedFormation(null);
        }}
      />
    );
  }

  return (
    <div className="space-y-6">
      {/* Header with breadcrumb */}
      <div className="flex items-center gap-4">
        <Button variant="outline" onClick={onBack}>
          <ArrowLeft className="h-4 w-4 mr-2" />
          Retour
        </Button>
        <div>
          <h2 className="text-2xl font-bold">Formations - {corpsFormation.nom}</h2>
          <p className="text-muted-foreground">{corpsFormation.description}</p>
        </div>
      </div>

      {/* Statistics Card */}
      <Card>
        <CardHeader>
          <CardTitle>Statistiques</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-primary">{formations.length}</div>
              <div className="text-sm text-muted-foreground">Total Formations</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-green-600">
                {formations.filter(f => f.is_active).length}
              </div>
              <div className="text-sm text-muted-foreground">Actives</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-orange-600">
                {formations.filter(f => !f.is_active).length}
              </div>
              <div className="text-sm text-muted-foreground">Inactives</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-blue-600">
                {formations.reduce((sum, f) => sum + (f.prix || 0), 0).toLocaleString()} DH
              </div>
              <div className="text-sm text-muted-foreground">Prix Total</div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Filters */}
      <Card>
        <CardContent className="pt-6">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div>
              <Label>Prix minimum</Label>
              <Input
                type="number"
                placeholder="0"
                value={filters.prix_min}
                onChange={(e) => setFilters({ ...filters, prix_min: e.target.value })}
              />
            </div>

            <div>
              <Label>Prix maximum</Label>
              <Input
                type="number"
                placeholder="10000"
                value={filters.prix_max}
                onChange={(e) => setFilters({ ...filters, prix_max: e.target.value })}
              />
            </div>

            <div>
              <Label>Horaire</Label>
              <Select value={filters.horaire} onValueChange={(value) => setFilters({ ...filters, horaire: value })}>
                <SelectTrigger>
                  <SelectValue placeholder="Tous les horaires" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">Tous les horaires</SelectItem>
                  {horaireOptions.map((option) => (
                    <SelectItem key={option.value} value={option.value}>
                      {option.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div>
              <Label>Statut</Label>
              <Select value={filters.statut} onValueChange={(value) => setFilters({ ...filters, statut: value })}>
                <SelectTrigger>
                  <SelectValue placeholder="Tous les statuts" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">Tous les statuts</SelectItem>
                  <SelectItem value="actif">Actif</SelectItem>
                  <SelectItem value="inactif">Inactif</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="flex items-end">
              <Button 
                variant="outline" 
                onClick={() => setFilters({ prix_min: '', prix_max: '', horaire: 'all', statut: 'all' })}
                className="w-full"
              >
                <Filter className="h-4 w-4 mr-2" />
                Réinitialiser
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Add Formation Button */}
      <div className="flex justify-end">
        <Dialog open={isModalOpen} onOpenChange={setIsModalOpen}>
          <DialogTrigger asChild>
            <Button onClick={resetForm}>
              <Plus className="h-4 w-4 mr-2" />
              Ajouter une formation
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-2xl">
            <DialogHeader>
              <DialogTitle>
                {editingFormation ? 'Modifier la formation' : 'Ajouter une formation'}
              </DialogTitle>
            </DialogHeader>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <Label htmlFor="titre">Titre de la formation *</Label>
                <Input
                    id="titre"
                    value={formData.titre}
                    onChange={(e) => setFormData({ ...formData, titre: e.target.value })}
                    required
                  />
              </div>

              <div>
                <Label htmlFor="prix">Prix (DH)</Label>
                <Input
                  id="prix"
                  type="number"
                  step="0.01"
                  value={formData.prix}
                  onChange={(e) => setFormData({ ...formData, prix: parseFloat(e.target.value) || 0 })}
                />
              </div>

              <div>
                <Label htmlFor="horaire">Horaire</Label>
                <Select
                  value={formData.horaire}
                  onValueChange={(value) => setFormData({ ...formData, horaire: value })}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {horaireOptions.map((option) => (
                      <SelectItem key={option.value} value={option.value}>
                        {option.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div>
                <Label htmlFor="description">Description</Label>
                <Textarea
                  id="description"
                  value={formData.description}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                  rows={3}
                />
              </div>

              <div>
                <Label htmlFor="statut">Statut</Label>
                <Select
                  value={formData.is_active ? 'true' : 'false'}
                  onValueChange={(value) => setFormData({ ...formData, is_active: value === 'true' })}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="true">Active</SelectItem>
                    <SelectItem value="false">Inactive</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="flex justify-end space-x-2">
                <Button type="button" variant="outline" onClick={() => setIsModalOpen(false)}>
                  Annuler
                </Button>
                <Button type="submit">
                  {editingFormation ? 'Modifier' : 'Ajouter'}
                </Button>
              </div>
            </form>
          </DialogContent>
        </Dialog>
      </div>

      {/* Formations Table */}
      <Card>
        <CardHeader>
          <CardTitle>Liste des Formations ({filteredFormations.length})</CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Titre</TableHead>
                <TableHead>Prix (DH)</TableHead>
                <TableHead>Horaire</TableHead>
                <TableHead>Statut</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredFormations.map((formation) => (
                <TableRow key={formation.id}>
                  <TableCell className="font-medium">{formation.titre}</TableCell>
                  <TableCell>{formation.prix?.toLocaleString() || 0} DH</TableCell>
                  <TableCell>
                    {horaireOptions.find(opt => opt.value === formation.horaire)?.label || formation.horaire}
                  </TableCell>
                  <TableCell>
                    <Badge variant={formation.is_active ? "default" : "secondary"}>
                      {formation.is_active ? 'Active' : 'Inactive'}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <div className="flex gap-2">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => {
                          setSelectedFormation(formation);
                          setShowDocumentsManagement(true);
                        }}
                        title="Gérer les documents"
                      >
                        <FileText className="h-4 w-4" />
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => handleEdit(formation)}
                        title="Modifier"
                      >
                        <Edit className="h-4 w-4" />
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => handleDelete(formation.id)}
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

export default CorpsFormationFormationsManagement;