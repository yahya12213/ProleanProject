import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Badge } from '@/components/ui/badge';
import { Plus, Edit, Trash2, Users, Filter } from 'lucide-react';
import { supabase } from '@/integrations/supabase/client';
import { useToast } from '@/hooks/use-toast';

interface Classe {
  id: string;
  nom_classe: string;
  formation_id: string;
  centre_id: string;
  nombre_places: number;
  date_debut: string;
  date_fin: string;
  formateur?: string;
  statut: 'programmee' | 'en_cours' | 'terminee' | 'annulee';
  is_active: boolean;
  formations?: { titre: string };
  centres?: { nom: string; villes?: { nom_ville: string } };
}

interface Formation {
  id: string;
  titre: string;
}

interface Centre {
  id: string;
  nom: string;
  villes?: { nom_ville: string };
}

interface GroupeClasse {
  id: string;
  nom: string;
  description?: string;
  corps_formation_id: string;
  is_active: boolean;
}

interface ClassesManagementProps {
  selectedSegmentId: string;
}

export function ClassesManagement({ selectedSegmentId }: ClassesManagementProps) {
  const navigate = useNavigate();
  const [classes, setClasses] = useState<Classe[]>([]);
  const [formations, setFormations] = useState<Formation[]>([]);
  const [centres, setCentres] = useState<Centre[]>([]);
  const [groupesClasses, setGroupesClasses] = useState<GroupeClasse[]>([]);
  const [loading, setLoading] = useState(true);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [editingClasse, setEditingClasse] = useState<Classe | null>(null);
  const [filteredClasses, setFilteredClasses] = useState<Classe[]>([]);
  const [filters, setFilters] = useState({
    centre: 'all',
    statut: 'all',
    date_debut: '',
    date_fin: ''
  });
  const { toast } = useToast();

  const [formData, setFormData] = useState({
    nom_classe: '',
    centre_id: '',
    nombre_places: 0,
    date_debut: '',
    date_fin: '',
    statut: 'active' as 'active' | 'inactive' | 'fini'
  });

  useEffect(() => {
    if (selectedSegmentId) {
      loadData();
    }
  }, [selectedSegmentId]);

  const loadData = async () => {
    try {
      setLoading(true);
      
      // Get centre IDs for the selected segment first
      const { data: segmentCentres } = await supabase
        .from('centres')
        .select('id')
        .eq('segment_id', selectedSegmentId);
      
      const centreIds = segmentCentres?.map(c => c.id) || [];
      
      // Load classes with related data (filtered by segment centres)
      const { data: classesData, error: classesError } = await supabase
        .from('classes')
        .select(`
          *,
          formations:formation_id(titre),
          centres:centre_id(nom, villes:ville_id(nom_ville))
        `)
        .in('centre_id', centreIds)
        .order('date_debut', { ascending: false });

      // Load formations physiques
      const { data: formationsData, error: formationsError } = await supabase
        .from('formations')
        .select('*')
        .eq('type_formation', 'physique')
        .eq('is_active', true)
        .order('titre');

      // Load centres (filtered by segment)
      const { data: centresData, error: centresError } = await supabase
        .from('centres')
        .select(`
          *,
          villes:ville_id(nom_ville)
        `)
        .eq('is_active', true)
        .eq('segment_id', selectedSegmentId)
        .order('nom');

      if (classesError) throw classesError;
      if (formationsError) throw formationsError;
      if (centresError) throw centresError;

      setClasses(classesData || []);
      setFormations(formationsData || []);
      setCentres(centresData || []);
      setFilteredClasses(classesData || []);
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
      nom_classe: '',
      centre_id: '',
      nombre_places: 0,
      date_debut: '',
      date_fin: '',
      statut: 'active' as 'active' | 'inactive' | 'fini'
    });
    setEditingClasse(null);
  };

  const handleEdit = (classe: Classe) => {
    setFormData({
      nom_classe: classe.nom_classe,
      centre_id: classe.centre_id,
      nombre_places: classe.nombre_places,
      date_debut: classe.date_debut,
      date_fin: classe.date_fin,
      statut: classe.is_active ? 'active' : 'inactive'
    });
    setEditingClasse(classe);
    setIsModalOpen(true);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    try {
      if (editingClasse) {
        const { error } = await supabase
          .from('classes')
          .update({
            nom_classe: formData.nom_classe,
            centre_id: formData.centre_id,
            nombre_places: formData.nombre_places,
            date_debut: formData.date_debut,
            date_fin: formData.date_fin,
            is_active: formData.statut === 'active'
          })
          .eq('id', editingClasse.id);
        
        if (error) throw error;
        
        toast({
          title: "Succès",
          description: "Classe mise à jour avec succès"
        });
      } else {
        const { error } = await supabase
          .from('classes')
          .insert([{
            nom_classe: formData.nom_classe,
            centre_id: formData.centre_id,
            nombre_places: formData.nombre_places,
            date_debut: formData.date_debut,
            date_fin: formData.date_fin,
            formation_id: formations[0]?.id || '', // Use first available formation as required field
            is_active: formData.statut === 'active'
          }]);
        
        if (error) throw error;
        
        toast({
          title: "Succès",
          description: "Classe créée avec succès"
        });
      }

      setIsModalOpen(false);
      resetForm();
      loadData();
    } catch (error) {
      console.error('Error saving classe:', error);
      toast({
        title: "Erreur",
        description: "Impossible de sauvegarder la classe",
        variant: "destructive"
      });
    }
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Êtes-vous sûr de vouloir supprimer cette classe ?')) return;

    try {
      const { error } = await supabase
        .from('classes')
        .delete()
        .eq('id', id);

      if (error) throw error;

      toast({
        title: "Succès",
        description: "Classe supprimée avec succès"
      });
      
      loadData();
    } catch (error) {
      console.error('Error deleting classe:', error);
      toast({
        title: "Erreur",
        description: "Impossible de supprimer la classe",
        variant: "destructive"
      });
    }
  };

  const getStatutColor = (statut: string, dateDebut: string, dateFin: string) => {
    const today = new Date().toISOString().split('T')[0];
    
    if (statut === 'annulee') return 'bg-red-100 text-red-800';
    
    if (dateDebut > today) return 'bg-gray-100 text-gray-800'; // Programmée
    if (dateDebut <= today && dateFin >= today) return 'bg-yellow-100 text-yellow-800'; // En cours
    if (dateFin < today) return 'bg-green-100 text-green-800'; // Terminée
    
    return 'bg-gray-100 text-gray-800';
  };

  const getStatutLabel = (statut: string, dateDebut: string, dateFin: string) => {
    const today = new Date().toISOString().split('T')[0];
    
    if (statut === 'annulee') return 'Annulée';
    
    if (dateDebut > today) return 'Programmée';
    if (dateDebut <= today && dateFin >= today) return 'En cours';
    if (dateFin < today) return 'Terminée';
    
    return 'Programmée';
  };

  const applyFilters = () => {
    let filtered = classes;

    if (filters.centre && filters.centre !== 'all') {
      filtered = filtered.filter(classe => classe.centre_id === filters.centre);
    }

    if (filters.statut && filters.statut !== 'all') {
      filtered = filtered.filter(classe => {
        const today = new Date().toISOString().split('T')[0];
        switch (filters.statut) {
          case 'programmee':
            return classe.date_debut > today;
          case 'en_cours':
            return classe.date_debut <= today && classe.date_fin >= today;
          case 'terminee':
            return classe.date_fin < today;
          default:
            return true;
        }
      });
    }

    if (filters.date_debut) {
      filtered = filtered.filter(classe => classe.date_debut >= filters.date_debut);
    }

    if (filters.date_fin) {
      filtered = filtered.filter(classe => classe.date_fin <= filters.date_fin);
    }

    setFilteredClasses(filtered);
  };

  useEffect(() => {
    applyFilters();
  }, [classes, filters]);

  if (loading) {
    return <div className="p-4">Chargement...</div>;
  }

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h3 className="text-lg font-semibold">Sessions de formation</h3>
      </div>

      {/* Filtres */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4 p-4 bg-muted/50 rounded-lg">
        <div>
          <Label>Centre</Label>
          <Select value={filters.centre} onValueChange={(value) => setFilters({ ...filters, centre: value })}>
            <SelectTrigger>
              <SelectValue placeholder="Tous les centres" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">Tous les centres</SelectItem>
              {centres.map((centre) => (
                <SelectItem key={centre.id} value={centre.id}>
                  {centre.nom}
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
              <SelectItem value="programmee">Programmée</SelectItem>
              <SelectItem value="en_cours">En cours</SelectItem>
              <SelectItem value="terminee">Terminée</SelectItem>
            </SelectContent>
          </Select>
        </div>

        <div>
          <Label>Date début à partir de</Label>
          <Input
            type="date"
            value={filters.date_debut}
            onChange={(e) => setFilters({ ...filters, date_debut: e.target.value })}
          />
        </div>

        <div>
          <Label>Date fin jusqu'au</Label>
          <Input
            type="date"
            value={filters.date_fin}
            onChange={(e) => setFilters({ ...filters, date_fin: e.target.value })}
          />
        </div>

        <div className="flex items-end">
          <Button 
            variant="outline" 
            onClick={() => setFilters({ centre: 'all', statut: 'all', date_debut: '', date_fin: '' })}
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
              Programmer une classe
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-md">
            <DialogHeader>
              <DialogTitle>
                {editingClasse ? 'Modifier la classe' : 'Programmer une classe'}
              </DialogTitle>
            </DialogHeader>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <Label htmlFor="centre">Centre de formation *</Label>
                <Select
                  value={formData.centre_id}
                  onValueChange={(value) => setFormData({ ...formData, centre_id: value })}
                  required
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Sélectionner un centre" />
                  </SelectTrigger>
                  <SelectContent>
                    {centres.map((centre) => (
                      <SelectItem key={centre.id} value={centre.id}>
                        {centre.nom} - {centre.villes?.nom_ville}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>


              <div>
                <Label htmlFor="nom_classe">Nom de classe *</Label>
                <Input
                  id="nom_classe"
                  value={formData.nom_classe}
                  onChange={(e) => setFormData({ ...formData, nom_classe: e.target.value })}
                  required
                />
              </div>

              <div>
                <Label htmlFor="nombre_places">Nombre de places *</Label>
                <Input
                  id="nombre_places"
                  type="number"
                  value={formData.nombre_places}
                  onChange={(e) => setFormData({ ...formData, nombre_places: parseInt(e.target.value) || 0 })}
                  required
                />
              </div>

              <div>
                <Label htmlFor="date_debut">Date de début *</Label>
                <Input
                  id="date_debut"
                  type="date"
                  value={formData.date_debut}
                  onChange={(e) => setFormData({ ...formData, date_debut: e.target.value })}
                  required
                />
              </div>

              <div>
                <Label htmlFor="date_fin">Date de fin *</Label>
                <Input
                  id="date_fin"
                  type="date"
                  value={formData.date_fin}
                  onChange={(e) => setFormData({ ...formData, date_fin: e.target.value })}
                  required
                />
              </div>

              <div>
                <Label htmlFor="statut">Statut</Label>
                <Select
                  value={formData.statut}
                  onValueChange={(value) => setFormData({ ...formData, statut: value as 'active' | 'inactive' | 'fini' })}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="active">Active</SelectItem>
                    <SelectItem value="inactive">Inactive</SelectItem>
                    <SelectItem value="fini">Fini</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="flex justify-end space-x-2">
                <Button type="button" variant="outline" onClick={() => setIsModalOpen(false)}>
                  Annuler
                </Button>
                <Button type="submit">
                  {editingClasse ? 'Modifier' : 'Programmer'}
                </Button>
              </div>
            </form>
          </DialogContent>
        </Dialog>
      </div>

      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Nom de classe</TableHead>
            <TableHead>Centre</TableHead>
            <TableHead>Dates</TableHead>
            <TableHead>Places</TableHead>
            <TableHead>Statut</TableHead>
            <TableHead>Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {filteredClasses.map((classe) => (
            <TableRow key={classe.id}>
              <TableCell className="font-medium">{classe.nom_classe}</TableCell>
              <TableCell>
                <div>
                  <div className="font-medium">{classe.centres?.nom}</div>
                  <div className="text-sm text-muted-foreground">{classe.centres?.villes?.nom_ville}</div>
                </div>
              </TableCell>
              <TableCell>
                <div className="text-sm">
                  <div>Du {new Date(classe.date_debut).toLocaleDateString()}</div>
                  <div>Au {new Date(classe.date_fin).toLocaleDateString()}</div>
                </div>
              </TableCell>
              <TableCell>
                <span className="font-medium">0/{classe.nombre_places}</span>
              </TableCell>
              <TableCell>
                <Badge variant={classe.is_active ? "default" : "secondary"}>
                  {classe.is_active ? 'Active' : 'Inactive'}
                </Badge>
              </TableCell>
              <TableCell>
                <div className="flex space-x-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => {
                      // Save current context before navigating
                      localStorage.setItem('selectedSegment', selectedSegmentId);
                      navigate(`/administration/classe/${classe.id}/inscriptions`);
                    }}
                  >
                    <Users className="h-4 w-4" />
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => handleEdit(classe)}
                  >
                    <Edit className="h-4 w-4" />
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => handleDelete(classe.id)}
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