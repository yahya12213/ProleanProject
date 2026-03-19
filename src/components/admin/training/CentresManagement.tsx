import React, { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Badge } from '@/components/ui/badge';
import { Plus, Edit, Trash2, Filter } from 'lucide-react';
import { supabase } from '@/integrations/supabase/client';
import { useToast } from '@/hooks/use-toast';

interface Centre {
  id: string;
  nom: string;
  ville_id: string;
  segment_id: string;
  adresse?: string;
  telephone?: string;
  email?: string;
  capacite?: number;
  is_active: boolean;
  villes?: { nom_ville: string };
  segments?: { nom: string; couleur: string };
}

interface Ville {
  id: string;
  nom_ville: string;
}

interface Segment {
  id: string;
  nom: string;
  couleur: string;
}

interface CentresManagementProps {
  selectedSegmentId: string;
}

export function CentresManagement({ selectedSegmentId }: CentresManagementProps) {
  const [centres, setCentres] = useState<Centre[]>([]);
  const [villes, setVilles] = useState<Ville[]>([]);
  const [segments, setSegments] = useState<Segment[]>([]);
  const [loading, setLoading] = useState(true);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [editingCentre, setEditingCentre] = useState<Centre | null>(null);
  const [filteredCentres, setFilteredCentres] = useState<Centre[]>([]);
  const [filters, setFilters] = useState({
    ville: 'all',
    statut: 'all'
  });
  const { toast } = useToast();

  const [formData, setFormData] = useState({
    nom: '',
    ville_id: '',
    segment_id: ''
  });

  useEffect(() => {
    if (selectedSegmentId) {
      loadData();
    }
  }, [selectedSegmentId]);

  const loadData = async () => {
    try {
      setLoading(true);
      
      // Load centres with related data (filtered by segment)
      const { data: centresData, error: centresError } = await supabase
        .from('centres')
        .select(`
          *,
          villes:ville_id(nom_ville),
          segments:segment_id(nom, couleur)
        `)
        .eq('segment_id', selectedSegmentId)
        .order('nom');

      // Load villes (filtered by segment)
      const { data: villesData, error: villesError } = await supabase
        .from('villes')
        .select('*')
        .eq('segment_id', selectedSegmentId)
        .order('nom_ville');

      // Load current segment only
      const { data: segmentsData, error: segmentsError } = await supabase
        .from('segments')
        .select('*')
        .eq('id', selectedSegmentId);

      if (centresError) throw centresError;
      if (villesError) throw villesError;
      if (segmentsError) throw segmentsError;

      setCentres(centresData || []);
      setVilles(villesData || []);
      setSegments(segmentsData || []);
      setFilteredCentres(centresData || []);
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
      nom: '',
      ville_id: '',
      segment_id: selectedSegmentId
    });
    setEditingCentre(null);
  };

  const handleEdit = (centre: Centre) => {
    setFormData({
      nom: centre.nom,
      ville_id: centre.ville_id,
      segment_id: centre.segment_id
    });
    setEditingCentre(centre);
    setIsModalOpen(true);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    try {
      if (editingCentre) {
        const { error } = await supabase
          .from('centres')
          .update(formData)
          .eq('id', editingCentre.id);
        
        if (error) throw error;
        
        toast({
          title: "Succès",
          description: "Centre mis à jour avec succès"
        });
      } else {
        const { error } = await supabase
          .from('centres')
          .insert([{
            ...formData,
            is_active: true,
            capacite: 0
          }]);
        
        if (error) throw error;
        
        toast({
          title: "Succès",
          description: "Centre créé avec succès"
        });
      }

      setIsModalOpen(false);
      resetForm();
      loadData();
    } catch (error) {
      console.error('Error saving centre:', error);
      toast({
        title: "Erreur",
        description: "Impossible de sauvegarder le centre",
        variant: "destructive"
      });
    }
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Êtes-vous sûr de vouloir supprimer ce centre ?')) return;

    try {
      const { error } = await supabase
        .from('centres')
        .delete()
        .eq('id', id);

      if (error) throw error;

      toast({
        title: "Succès",
        description: "Centre supprimé avec succès"
      });
      
      loadData();
    } catch (error) {
      console.error('Error deleting centre:', error);
      toast({
        title: "Erreur",
        description: "Impossible de supprimer le centre",
        variant: "destructive"
      });
    }
  };

  const applyFilters = () => {
    let filtered = centres;

    if (filters.ville && filters.ville !== 'all') {
      filtered = filtered.filter(centre => centre.ville_id === filters.ville);
    }

    if (filters.statut && filters.statut !== 'all') {
      const isActive = filters.statut === 'actif';
      filtered = filtered.filter(centre => centre.is_active === isActive);
    }

    setFilteredCentres(filtered);
  };

  useEffect(() => {
    applyFilters();
  }, [centres, filters]);

  if (loading) {
    return <div className="p-4">Chargement...</div>;
  }

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h3 className="text-lg font-semibold">Liste des centres</h3>
      </div>

      {/* Filtres */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 p-4 bg-muted/50 rounded-lg">
        <div>
          <Label>Filtrer par ville</Label>
          <Select value={filters.ville} onValueChange={(value) => setFilters({ ...filters, ville: value })}>
            <SelectTrigger>
              <SelectValue placeholder="Toutes les villes" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">Toutes les villes</SelectItem>
              {villes.map((ville) => (
                <SelectItem key={ville.id} value={ville.id}>
                  {ville.nom_ville}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <div>
          <Label>Filtrer par statut</Label>
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
            onClick={() => setFilters({ ville: 'all', statut: 'all' })}
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
              Ajouter un centre
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-md">
            <DialogHeader>
              <DialogTitle>
                {editingCentre ? 'Modifier le centre' : 'Ajouter un centre'}
              </DialogTitle>
            </DialogHeader>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <Label htmlFor="nom">Nom du centre *</Label>
                <Input
                  id="nom"
                  value={formData.nom}
                  onChange={(e) => setFormData({ ...formData, nom: e.target.value })}
                  required
                />
              </div>

              <div>
                <Label htmlFor="ville">Ville *</Label>
                <Select
                  value={formData.ville_id}
                  onValueChange={(value) => setFormData({ ...formData, ville_id: value })}
                  required
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Sélectionner une ville" />
                  </SelectTrigger>
                  <SelectContent>
                    {villes.map((ville) => (
                      <SelectItem key={ville.id} value={ville.id}>
                        {ville.nom_ville}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>


              <div className="flex justify-end space-x-2">
                <Button type="button" variant="outline" onClick={() => setIsModalOpen(false)}>
                  Annuler
                </Button>
                <Button type="submit">
                  {editingCentre ? 'Modifier' : 'Ajouter'}
                </Button>
              </div>
            </form>
          </DialogContent>
        </Dialog>
      </div>

      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Nom du Centre</TableHead>
            <TableHead>Ville</TableHead>
            <TableHead>Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {filteredCentres.map((centre) => (
            <TableRow key={centre.id}>
              <TableCell className="font-medium">{centre.nom}</TableCell>
              <TableCell>
                <div className="flex items-center gap-2">
                  <span>{centre.villes?.nom_ville}</span>
                  <Badge variant={centre.is_active ? "default" : "secondary"}>
                    {centre.is_active ? "Actif" : "Inactif"}
                  </Badge>
                </div>
              </TableCell>
              <TableCell>
                <div className="flex space-x-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => handleEdit(centre)}
                  >
                    <Edit className="h-4 w-4" />
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => handleDelete(centre.id)}
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