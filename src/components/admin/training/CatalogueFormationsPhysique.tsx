import React, { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Badge } from '@/components/ui/badge';
import { Plus, Edit, Trash2, Filter, FileText } from 'lucide-react';
import { supabase } from '@/integrations/supabase/client';
import { useToast } from '@/hooks/use-toast';
import { FormationDocumentsManagement } from './FormationDocumentsManagement';

interface Formation {
  id: string;
  titre: string;
  reference: string;
  description?: string;
  duree_heures: number;
  prix?: number;
  niveau: string;
  horaire: string;
  is_active: boolean;
  type_formation: 'physique';
  corps_formation_id?: string;
}

interface CorpsFormation {
  id: string;
  nom: string;
}

const niveauOptions = [
  { value: 'debutant', label: 'Débutant' },
  { value: 'intermediaire', label: 'Intermédiaire' },
  { value: 'avance', label: 'Avancé' },
  { value: 'expert', label: 'Expert' }
];

const horaireOptions = [
  { value: 'matin', label: 'Matin' },
  { value: 'soir', label: 'Soir' },
  { value: 'toute_la_journee', label: 'Toute la journée' }
];

interface CatalogueFormationsPhysiqueProps {
  selectedSegmentId: string;
}

export function CatalogueFormationsPhysique({ selectedSegmentId }: CatalogueFormationsPhysiqueProps) {
  const [formations, setFormations] = useState<Formation[]>([]);
  const [corpsFormations, setCorpsFormations] = useState<CorpsFormation[]>([]);
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
  const { toast } = useToast();

  const [formData, setFormData] = useState({
    titre: '',
    prix: 0,
    horaire: 'matin',
    is_active: true,
    type_formation: 'physique' as const,
    corps_formation_id: ''
  });

  useEffect(() => {
    if (selectedSegmentId) {
      loadFormations();
      loadCorpsFormations();
    }
  }, [selectedSegmentId]);

  const loadFormations = async () => {
    try {
      setLoading(true);
      const { data, error } = await supabase
        .from('formations')
        .select(`
          *,
          corps_formation:corps_formation_id (
            id,
            nom
          )
        `)
        .eq('type_formation', 'physique')
        .order('titre');

      if (error) throw error;
      const formationsData = data?.map(item => ({
        id: item.id,
        titre: item.titre,
        reference: item.reference || '',
        description: item.description,
        duree_heures: item.duree_heures,
        prix: item.prix || 0,
        niveau: item.niveau,
        horaire: item.horaire || 'matin',
        is_active: item.is_active,
        type_formation: 'physique' as const,
        corps_formation_id: item.corps_formation_id
      })) || [];
      
      setFormations(formationsData);
      setFilteredFormations(formationsData);
    } catch (error) {
      console.error('Error loading formations:', error);
      toast({
        title: "Erreur",
        description: "Impossible de charger les formations",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const loadCorpsFormations = async () => {
    try {
      const { data, error } = await supabase
        .from('corps_formation')
        .select('id, nom')
        .eq('is_active', true)
        .order('nom');

      if (error) throw error;
      setCorpsFormations(data || []);
    } catch (error) {
      console.error('Error loading corps formations:', error);
      toast({
        title: "Erreur",
        description: "Impossible de charger les corps de formation",
        variant: "destructive"
      });
    }
  };

  const resetForm = () => {
    setFormData({
      titre: '',
      prix: 0,
      horaire: 'matin',
      is_active: true,
      type_formation: 'physique' as const,
      corps_formation_id: ''
    });
    setEditingFormation(null);
  };

  const handleEdit = (formation: Formation) => {
    setFormData({
      titre: formation.titre,
      prix: formation.prix || 0,
      horaire: formation.horaire,
      is_active: formation.is_active,
      type_formation: 'physique' as const,
      corps_formation_id: formation.corps_formation_id || ''
    });
    setEditingFormation(formation);
    setIsModalOpen(true);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    try {
      if (editingFormation) {
        const { error } = await supabase
          .from('formations')
          .update(formData)
          .eq('id', editingFormation.id);
        
        if (error) throw error;
        
        toast({
          title: "Succès",
          description: "Formation mise à jour avec succès"
        });
      } else {
        const { error } = await supabase
          .from('formations')
          .insert([{
            ...formData,
            niveau: 'debutant',
            duree_heures: 0
          }]);
        
        if (error) throw error;
        
        toast({
          title: "Succès",
          description: "Formation créée avec succès"
        });
      }

      setIsModalOpen(false);
      resetForm();
      loadFormations();
    } catch (error) {
      console.error('Error saving formation:', error);
      toast({
        title: "Erreur",
        description: "Impossible de sauvegarder la formation",
        variant: "destructive"
      });
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
        // Vérifier si c'est une erreur de contrainte de clé étrangère
        if (error.code === '23503') {
          toast({
            title: "Erreur",
            description: "Cette formation ne peut pas être supprimée car elle est utilisée dans des classes existantes. Veuillez d'abord supprimer les classes associées.",
            variant: "destructive"
          });
          return;
        }
        throw error;
      }

      toast({
        title: "Succès",
        description: "Formation supprimée avec succès"
      });
      
      loadFormations();
    } catch (error) {
      console.error('Error deleting formation:', error);
      toast({
        title: "Erreur",
        description: "Impossible de supprimer la formation",
        variant: "destructive"
      });
    }
  };

  const getNiveauColor = (niveau: string) => {
    switch (niveau) {
      case 'debutant': return 'bg-green-100 text-green-800';
      case 'intermediaire': return 'bg-yellow-100 text-yellow-800';
      case 'avance': return 'bg-orange-100 text-orange-800';
      case 'expert': return 'bg-red-100 text-red-800';
      default: return 'bg-gray-100 text-gray-800';
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
    return <div className="p-4">Chargement...</div>;
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
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h3 className="text-lg font-semibold">Catalogue des formations physiques</h3>
      </div>

      {/* Filtres */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4 p-4 bg-muted/50 rounded-lg">
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
              <SelectItem value="matin">Matin</SelectItem>
              <SelectItem value="soir">Soir</SelectItem>
              <SelectItem value="toute_la_journee">Toute la journée</SelectItem>
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

      <div className="flex justify-end">
        <Dialog open={isModalOpen} onOpenChange={setIsModalOpen}>
          <DialogTrigger asChild>
            <Button onClick={resetForm}>
              <Plus className="h-4 w-4 mr-2" />
              Ajouter une formation
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-md">
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
                <Label htmlFor="corps_formation">Corps de Formation</Label>
                <Select
                  value={formData.corps_formation_id}
                  onValueChange={(value) => setFormData({ ...formData, corps_formation_id: value })}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Sélectionner un corps de formation" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="">Aucun</SelectItem>
                    {corpsFormations.map((corps) => (
                      <SelectItem key={corps.id} value={corps.id}>
                        {corps.nom}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
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

      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Titre de la formation</TableHead>
            <TableHead>Corps de Formation</TableHead>
            <TableHead>Prix (DH)</TableHead>
            <TableHead>Horaire</TableHead>
            <TableHead>Statut</TableHead>
            <TableHead>Livrables</TableHead>
            <TableHead>Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {filteredFormations.map((formation) => (
            <TableRow key={formation.id}>
              <TableCell className="font-medium">{formation.titre}</TableCell>
              <TableCell>
                {corpsFormations.find(c => c.id === formation.corps_formation_id)?.nom || '-'}
              </TableCell>
              <TableCell>{formation.prix ? `${formation.prix.toFixed(2)}` : '-'}</TableCell>
              <TableCell>
                {horaireOptions.find(opt => opt.value === formation.horaire)?.label || formation.horaire}
              </TableCell>
              <TableCell>
                <Badge variant={formation.is_active ? "default" : "secondary"}>
                  {formation.is_active ? 'Active' : 'Inactive'}
                </Badge>
              </TableCell>
              <TableCell>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => {
                    setSelectedFormation(formation);
                    setShowDocumentsManagement(true);
                  }}
                >
                  <FileText className="h-4 w-4" />
                </Button>
              </TableCell>
              <TableCell>
                <div className="flex space-x-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => handleEdit(formation)}
                  >
                    <Edit className="h-4 w-4" />
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => handleDelete(formation.id)}
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}