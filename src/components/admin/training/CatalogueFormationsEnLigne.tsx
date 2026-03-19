import React, { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Badge } from '@/components/ui/badge';
import { Plus, Edit, Trash2, Eye, FileText } from 'lucide-react';
import { supabase } from '@/integrations/supabase/client';
import { useToast } from '@/hooks/use-toast';

interface Formation {
  id: string;
  titre: string;
  description?: string;
  duree_heures: number;
  prix?: number;
  niveau: string;
  is_active: boolean;
  type_formation: string;
  plateforme_id?: string;
  plateformes?: { nom: string };
}

interface Plateforme {
  id: string;
  nom: string;
}

export function CatalogueFormationsEnLigne() {
  const [formations, setFormations] = useState<Formation[]>([]);
  const [plateformes, setPlateformes] = useState<Plateforme[]>([]);
  const [loading, setLoading] = useState(true);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [editingFormation, setEditingFormation] = useState<Formation | null>(null);
  const { toast } = useToast();

  const [formData, setFormData] = useState({
    titre: '',
    description: '',
    duree_heures: 0,
    prix: 0,
    niveau: 'debutant',
    is_active: true,
    type_formation: 'en_ligne' as 'physique' | 'en_ligne',
    plateforme_id: ''
  });

  const niveauOptions = [
    { value: 'debutant', label: 'Débutant' },
    { value: 'intermediaire', label: 'Intermédiaire' },
    { value: 'avance', label: 'Avancé' },
    { value: 'expert', label: 'Expert' }
  ];

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      
      // Load formations en ligne
      const { data: formationsData, error: formationsError } = await supabase
        .from('formations')
        .select(`
          *,
          plateformes:plateforme_id(nom)
        `)
        .eq('type_formation', 'en_ligne')
        .order('titre');

      // Load plateformes
      const { data: plateformesData, error: plateformesError } = await supabase
        .from('plateformes')
        .select('*')
        .eq('is_active', true)
        .order('nom');

      if (formationsError) throw formationsError;
      if (plateformesError) throw plateformesError;

      setFormations(formationsData || []);
      setPlateformes(plateformesData || []);
    } catch (error) {
      console.error('Error loading data:', error);
      toast({
        title: "Erreur",
        description: "Impossible de charger les données",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const resetForm = () => {
    setFormData({
      titre: '',
      description: '',
      duree_heures: 0,
      prix: 0,
      niveau: 'debutant',
      is_active: true,
      type_formation: 'en_ligne',
      plateforme_id: ''
    });
    setEditingFormation(null);
  };

  const handleEdit = (formation: Formation) => {
    setFormData({
      titre: formation.titre,
      description: formation.description || '',
      duree_heures: formation.duree_heures,
      prix: formation.prix || 0,
      niveau: formation.niveau,
      is_active: formation.is_active,
      type_formation: formation.type_formation as 'physique' | 'en_ligne',
      plateforme_id: formation.plateforme_id || ''
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
          .insert([formData]);
        
        if (error) throw error;
        
        toast({
          title: "Succès",
          description: "Formation créée avec succès"
        });
      }

      setIsModalOpen(false);
      resetForm();
      loadData();
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

      if (error) throw error;

      toast({
        title: "Succès",
        description: "Formation supprimée avec succès"
      });
      
      loadData();
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

  if (loading) {
    return <div className="p-4">Chargement...</div>;
  }

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h3 className="text-lg font-semibold">Catalogue des formations en ligne</h3>
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
                <Label htmlFor="plateforme">Plateforme *</Label>
                <Select
                  value={formData.plateforme_id}
                  onValueChange={(value) => setFormData({ ...formData, plateforme_id: value })}
                  required
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Sélectionner une plateforme" />
                  </SelectTrigger>
                  <SelectContent>
                    {plateformes.map((plateforme) => (
                      <SelectItem key={plateforme.id} value={plateforme.id}>
                        {plateforme.nom}
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
                />
              </div>

              <div>
                <Label htmlFor="duree_heures">Durée (heures) *</Label>
                <Input
                  id="duree_heures"
                  type="number"
                  value={formData.duree_heures}
                  onChange={(e) => setFormData({ ...formData, duree_heures: parseInt(e.target.value) || 0 })}
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
                <Label htmlFor="niveau">Niveau</Label>
                <Select
                  value={formData.niveau}
                  onValueChange={(value) => setFormData({ ...formData, niveau: value })}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {niveauOptions.map((option) => (
                      <SelectItem key={option.value} value={option.value}>
                        {option.label}
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
            <TableHead>Nom de formation</TableHead>
            <TableHead>Plateforme</TableHead>
            <TableHead>Durée</TableHead>
            <TableHead>Prix (DH)</TableHead>
            <TableHead>Niveau</TableHead>
            <TableHead>Statut</TableHead>
            <TableHead>Livrables</TableHead>
            <TableHead>Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {formations.map((formation) => (
            <TableRow key={formation.id}>
              <TableCell className="font-medium">{formation.titre}</TableCell>
              <TableCell>{formation.plateformes?.nom || '-'}</TableCell>
              <TableCell>{formation.duree_heures}h</TableCell>
              <TableCell>{formation.prix ? `${formation.prix.toFixed(2)}` : '-'}</TableCell>
              <TableCell>
                <Badge className={getNiveauColor(formation.niveau)}>
                  {niveauOptions.find(opt => opt.value === formation.niveau)?.label || formation.niveau}
                </Badge>
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
                  onClick={() => {/* TODO: Navigate to formation documents */}}
                >
                  <FileText className="h-4 w-4" />
                </Button>
              </TableCell>
              <TableCell>
                <div className="flex space-x-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => {/* TODO: Navigate to documents management */}}
                  >
                    <Eye className="h-4 w-4" />
                  </Button>
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