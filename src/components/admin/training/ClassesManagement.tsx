import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Badge } from '@/components/ui/badge';
import { Plus, Edit, Trash2, Users, Filter, Lock } from 'lucide-react';
import { supabase } from '@/integrations/supabase/client';
import { useToast } from '@/hooks/use-toast';

interface Classe {
  id: string;
  nom_classe: string;
  formation_id: string;
  centre_id: string;
  groupe_classe_id?: string;
  date_debut: string;
  date_fin: string;
  nombre_places: number;
  formateur?: string;
  statut: string;
  is_active: boolean;
}

interface Formation {
  id: string;
  titre: string;
  corps_formation_id?: string;
}

interface Centre {
  id: string;
  nom: string;
  segment_id: string;
}

interface GroupeClasse {
  id: string;
  nom: string;
  description?: string;
  corps_formation_id: string;
  is_active: boolean;
  corps_formation?: {
    id: string;
    nom: string;
  };
}

interface ClassesManagementProps {
  selectedSegmentId: string;
}

// Composant pour le bouton d'édition
const EditClasseButton = ({ classe, onEdit, canModifyClasse }: { 
  classe: Classe; 
  onEdit: (classe: Classe) => void;
  canModifyClasse: (classe: Classe) => Promise<boolean>;
}) => {
  const [canEdit, setCanEdit] = useState(true);
  const [isChecking, setIsChecking] = useState(false);

  useEffect(() => {
    const checkPermissions = async () => {
      setIsChecking(true);
      const canModify = await canModifyClasse(classe);
      setCanEdit(canModify);
      setIsChecking(false);
    };
    
    checkPermissions();
  }, [classe, canModifyClasse]);

  if (isChecking) {
    return (
      <Button variant="ghost" size="sm" disabled>
        <Edit className="h-4 w-4" />
      </Button>
    );
  }

  return (
    <Button
      variant="ghost"
      size="sm"
      onClick={() => onEdit(classe)}
      disabled={!canEdit}
      title={!canEdit ? "Classe terminée - Modification restreinte aux administrateurs" : "Modifier la classe"}
    >
      {!canEdit && <Lock className="h-3 w-3 mr-1" />}
      <Edit className="h-4 w-4" />
    </Button>
  );
};

// Composant pour le bouton de suppression
const DeleteClasseButton = ({ classe, onDelete, canModifyClasse }: { 
  classe: Classe; 
  onDelete: (id: string) => void;
  canModifyClasse: (classe: Classe) => Promise<boolean>;
}) => {
  const [canDelete, setCanDelete] = useState(true);
  const [isChecking, setIsChecking] = useState(false);

  useEffect(() => {
    const checkPermissions = async () => {
      setIsChecking(true);
      const canModify = await canModifyClasse(classe);
      setCanDelete(canModify);
      setIsChecking(false);
    };
    
    checkPermissions();
  }, [classe, canModifyClasse]);

  if (isChecking) {
    return (
      <Button variant="ghost" size="sm" disabled>
        <Trash2 className="h-4 w-4" />
      </Button>
    );
  }

  return (
    <Button
      variant="ghost"
      size="sm"
      onClick={() => onDelete(classe.id)}
      disabled={!canDelete}
      title={!canDelete ? "Classe terminée - Suppression restreinte aux administrateurs" : "Supprimer la classe"}
    >
      {!canDelete && <Lock className="h-3 w-3 mr-1" />}
      <Trash2 className="h-4 w-4" />
    </Button>
  );
};

export function ClassesManagement({ selectedSegmentId }: ClassesManagementProps) {
  const navigate = useNavigate();
  const { toast } = useToast();
  
  const [classes, setClasses] = useState<Classe[]>([]);
  const [formations, setFormations] = useState<Formation[]>([]);
  const [centres, setCentres] = useState<Centre[]>([]);
  const [groupesClasses, setGroupesClasses] = useState<GroupeClasse[]>([]);
  const [loading, setLoading] = useState(true);
  const [showDialog, setShowDialog] = useState(false);
  const [editingClasse, setEditingClasse] = useState<Classe | null>(null);
  const [filteredClasses, setFilteredClasses] = useState<Classe[]>([]);
  
  const [filters, setFilters] = useState({
    centre: '',
    statut: '',
    date_debut: '',
    date_fin: ''
  });

  const [formData, setFormData] = useState({
    nom_classe: '',
    formation_id: '',
    centre_id: '',
    groupe_classe_id: '',
    date_debut: '',
    date_fin: '',
    nombre_places: 0,
    formateur: ''
  });

  useEffect(() => {
    if (selectedSegmentId) {
      loadData();
    }
  }, [selectedSegmentId]);

  const loadData = async () => {
    try {
      console.log('Début du chargement des données pour le segment:', selectedSegmentId);
      
      // Charger les données de base
      const [classesResult, formationsResult, centresResult] = await Promise.all([
        supabase
          .from('classes')
          .select('*')
          .eq('is_active', true),
        supabase
          .from('formations')
          .select('*')
          .eq('is_active', true),
        supabase
          .from('centres')
          .select('*')
          .eq('is_active', true)
          .eq('segment_id', selectedSegmentId)
      ]);

      if (classesResult.error) {
        console.error('Erreur classes:', classesResult.error);
        throw classesResult.error;
      }
      if (formationsResult.error) {
        console.error('Erreur formations:', formationsResult.error);
        throw formationsResult.error;
      }
      if (centresResult.error) {
        console.error('Erreur centres:', centresResult.error);
        throw centresResult.error;
      }

      console.log('Données de base chargées avec succès');

      // Charger les groupes de classes séparément avec gestion d'erreur spécifique
      let groupesClassesData: GroupeClasse[] = [];
      try {
        const groupesResult = await supabase
          .from('groupes_classes')
          .select('*')
          .eq('is_active', true);

        if (groupesResult.error) {
          console.error('Erreur groupes_classes:', groupesResult.error);
          throw groupesResult.error;
        }

        groupesClassesData = groupesResult.data || [];

        // Charger les corps de formation pour chaque groupe
        if (groupesClassesData.length > 0) {
          const corpsFormationIds = groupesClassesData
            .map(g => g.corps_formation_id)
            .filter(id => id);

          if (corpsFormationIds.length > 0) {
            const { data: corpsFormationData, error: corpsError } = await supabase
              .from('corps_formation')
              .select('id, nom')
              .in('id', corpsFormationIds);

            if (!corpsError && corpsFormationData) {
              // Associer les corps de formation aux groupes
              groupesClassesData = groupesClassesData.map(groupe => ({
                ...groupe,
                corps_formation: corpsFormationData.find(cf => cf.id === groupe.corps_formation_id)
              }));
            }
          }
        }
      } catch (error) {
        console.error('Erreur lors du chargement des groupes de classes:', error);
        // On continue sans les groupes de classes
        groupesClassesData = [];
      }

      // Filter classes by selected segment through centres
      const centreIds = centresResult.data?.map(c => c.id) || [];
      const filteredClasses = classesResult.data?.filter(classe => 
        centreIds.includes(classe.centre_id)
      ) || [];

      console.log('Données filtrées:', {
        classes: filteredClasses.length,
        formations: formationsResult.data?.length || 0,
        centres: centresResult.data?.length || 0,
        groupes: groupesClassesData.length
      });

      setClasses(filteredClasses);
      setFormations(formationsResult.data || []);
      setCentres(centresResult.data || []);
      setGroupesClasses(groupesClassesData);
      setFilteredClasses(filteredClasses);
    } catch (error) {
      console.error('Erreur lors du chargement des données:', error);
      toast({
        title: "Erreur",
        description: `Impossible de charger les données: ${error.message || 'Erreur inconnue'}`,
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const resetForm = () => {
    setFormData({
      nom_classe: '',
      formation_id: '',
      centre_id: '',
      groupe_classe_id: '',
      date_debut: '',
      date_fin: '',
      nombre_places: 0,
      formateur: ''
    });
    setEditingClasse(null);
  };

  const handleEdit = (classe: Classe) => {
    setFormData({
      nom_classe: classe.nom_classe,
      formation_id: '',
      centre_id: classe.centre_id,
      groupe_classe_id: classe.groupe_classe_id || '',
      date_debut: classe.date_debut,
      date_fin: classe.date_fin,
      nombre_places: classe.nombre_places,
      formateur: ''
    });
    setEditingClasse(classe);
    setShowDialog(true);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    try {
      if (editingClasse) {
        const { error } = await supabase
          .from('classes')
          .update({
            nom_classe: formData.nom_classe,
            formation_id: null,
            centre_id: formData.centre_id,
            groupe_classe_id: formData.groupe_classe_id || null,
            date_debut: formData.date_debut,
            date_fin: formData.date_fin,
            nombre_places: formData.nombre_places,
            formateur: null
          })
          .eq('id', editingClasse.id);

        if (error) throw error;

        toast({
          title: "Succès",
          description: "Classe mise à jour avec succès",
        });
      } else {
        const { data, error } = await supabase
          .from('classes')
          .insert([{
            nom_classe: formData.nom_classe,
            formation_id: null,
            centre_id: formData.centre_id,
            groupe_classe_id: formData.groupe_classe_id || null,
            date_debut: formData.date_debut,
            date_fin: formData.date_fin,
            nombre_places: formData.nombre_places,
            formateur: null
          }]);

        if (error) throw error;

        toast({
          title: "Succès",
          description: "Classe créée avec succès",
        });
      }

      setShowDialog(false);
      resetForm();
      loadData();
    } catch (error) {
      console.error('Erreur lors de la sauvegarde:', error);
      toast({
        title: "Erreur",
        description: "Impossible de sauvegarder la classe",
        variant: "destructive",
      });
    }
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Êtes-vous sûr de vouloir supprimer cette classe ?')) return;

    try {
      const { error } = await supabase
        .from('classes')
        .update({ is_active: false })
        .eq('id', id);

      if (error) throw error;

      toast({
        title: "Succès",
        description: "Classe supprimée avec succès",
      });
      
      loadData();
    } catch (error) {
      console.error('Erreur lors de la suppression:', error);
      toast({
        title: "Erreur",
        description: "Impossible de supprimer la classe",
        variant: "destructive",
      });
    }
  };

  const getStatutColor = (classe: Classe) => {
    const today = new Date().toISOString().split('T')[0];
    let statut = classe.statut;
    
    // Calculer le statut automatique basé sur les dates
    if (statut !== 'annulee') {
      if (classe.date_debut > today) {
        statut = 'programmee';
      } else if (classe.date_debut <= today && classe.date_fin >= today) {
        statut = 'en_cours';
      } else if (classe.date_fin < today) {
        statut = 'terminee';
      }
    }
    
    switch (statut) {
      case 'programmee': return 'bg-blue-100 text-blue-800';
      case 'en_cours': return 'bg-yellow-100 text-yellow-800';
      case 'terminee': return 'bg-green-100 text-green-800';
      case 'annulee': return 'bg-red-100 text-red-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  const getStatutLabel = (classe: Classe) => {
    const today = new Date().toISOString().split('T')[0];
    let statut = classe.statut;
    
    // Calculer le statut automatique basé sur les dates
    if (statut !== 'annulee') {
      if (classe.date_debut > today) {
        statut = 'programmee';
      } else if (classe.date_debut <= today && classe.date_fin >= today) {
        statut = 'en_cours';
      } else if (classe.date_fin < today) {
        statut = 'terminee';
      }
    }
    
    switch (statut) {
      case 'programmee': return 'Programmée';
      case 'en_cours': return 'En cours';
      case 'terminee': return 'Terminée';
      case 'annulee': return 'Annulée';
      default: return 'Inconnue';
    }
  };

  const canModifyClasse = async (classe: Classe) => {
    const today = new Date().toISOString().split('T')[0];
    
    // Si la classe n'est pas terminée, autoriser la modification
    if (classe.date_fin >= today || classe.statut === 'annulee') {
      return true;
    }
    
    // Vérifier les permissions pour les classes terminées
    try {
      const { data, error } = await supabase.rpc('can_modify_finished_class', {
        classe_id: classe.id
      });
      
      if (error) {
        console.error('Erreur lors de la vérification des permissions:', error);
        return false;
      }
      
      return data;
    } catch (error) {
      console.error('Erreur lors de la vérification des permissions:', error);
      return false;
    }
  };

  const applyFilters = () => {
    let filtered = classes;

    if (filters.centre) {
      filtered = filtered.filter(classe => classe.centre_id === filters.centre);
    }

    if (filters.statut) {
      filtered = filtered.filter(classe => classe.statut === filters.statut);
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
        <h3 className="text-lg font-semibold">Gestion des Classes</h3>
        <Dialog open={showDialog} onOpenChange={setShowDialog}>
          <DialogTrigger asChild>
            <Button onClick={resetForm}>
              <Plus className="h-4 w-4 mr-2" />
              Nouvelle Classe
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-2xl">
            <DialogHeader>
              <DialogTitle>
                {editingClasse ? 'Modifier la classe' : 'Créer une nouvelle classe'}
              </DialogTitle>
            </DialogHeader>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="nom_classe">Nom de la classe</Label>
                  <Input
                    id="nom_classe"
                    value={formData.nom_classe}
                    onChange={(e) => setFormData(prev => ({ ...prev, nom_classe: e.target.value }))}
                    required
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="groupe_classe_id">Groupe de Classes</Label>
                  <Select value={formData.groupe_classe_id} onValueChange={(value) => setFormData(prev => ({ ...prev, groupe_classe_id: value }))}>
                    <SelectTrigger>
                      <SelectValue placeholder="Sélectionner un groupe de classes" />
                    </SelectTrigger>
                    <SelectContent>
                      {groupesClasses.map((groupe) => (
                        <SelectItem key={groupe.id} value={groupe.id}>
                          {groupe.nom} ({groupe.corps_formation?.nom})
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>


                <div className="space-y-2">
                  <Label htmlFor="centre_id">Centre</Label>
                  <Select value={formData.centre_id} onValueChange={(value) => setFormData(prev => ({ ...prev, centre_id: value }))}>
                    <SelectTrigger>
                      <SelectValue placeholder="Sélectionner un centre" />
                    </SelectTrigger>
                    <SelectContent>
                      {centres.map((centre) => (
                        <SelectItem key={centre.id} value={centre.id}>
                          {centre.nom}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="date_debut">Date de début</Label>
                  <Input
                    id="date_debut"
                    type="date"
                    value={formData.date_debut}
                    onChange={(e) => setFormData(prev => ({ ...prev, date_debut: e.target.value }))}
                    required
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="date_fin">Date de fin</Label>
                  <Input
                    id="date_fin"
                    type="date"
                    value={formData.date_fin}
                    onChange={(e) => setFormData(prev => ({ ...prev, date_fin: e.target.value }))}
                    required
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="nombre_places">Nombre de places</Label>
                  <Input
                    id="nombre_places"
                    type="number"
                    value={formData.nombre_places}
                    onChange={(e) => setFormData(prev => ({ ...prev, nombre_places: parseInt(e.target.value) || 0 }))}
                    required
                  />
                </div>

              </div>

              <div className="flex justify-end space-x-2">
                <Button type="button" variant="outline" onClick={() => setShowDialog(false)}>
                  Annuler
                </Button>
                <Button type="submit">
                  {editingClasse ? 'Modifier' : 'Créer'}
                </Button>
              </div>
            </form>
          </DialogContent>
        </Dialog>
      </div>

      {/* Filtres */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 p-4 bg-muted/50 rounded-lg">
        <div className="space-y-2">
          <Label>Centre</Label>
          <Select value={filters.centre} onValueChange={(value) => setFilters(prev => ({ ...prev, centre: value === 'all' ? '' : value }))}>
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

        <div className="space-y-2">
          <Label>Statut</Label>
          <Select value={filters.statut} onValueChange={(value) => setFilters(prev => ({ ...prev, statut: value === 'all' ? '' : value }))}>
            <SelectTrigger>
              <SelectValue placeholder="Tous les statuts" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">Tous les statuts</SelectItem>
              <SelectItem value="programmee">Programmée</SelectItem>
              <SelectItem value="en_cours">En cours</SelectItem>
              <SelectItem value="terminee">Terminée</SelectItem>
              <SelectItem value="annulee">Annulée</SelectItem>
            </SelectContent>
          </Select>
        </div>

        <div className="space-y-2">
          <Label>Date début</Label>
          <Input
            type="date"
            value={filters.date_debut}
            onChange={(e) => setFilters(prev => ({ ...prev, date_debut: e.target.value }))}
          />
        </div>

        <div className="space-y-2">
          <Label>Date fin</Label>
          <Input
            type="date"
            value={filters.date_fin}
            onChange={(e) => setFilters(prev => ({ ...prev, date_fin: e.target.value }))}
          />
        </div>
      </div>

      {/* Tableau des classes */}
      <div className="border rounded-lg">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Nom de la classe</TableHead>
              <TableHead>Groupe</TableHead>
              <TableHead>Centre</TableHead>
              <TableHead>Date début</TableHead>
              <TableHead>Date fin</TableHead>
              <TableHead>Places</TableHead>
              <TableHead>Statut</TableHead>
              <TableHead>Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {filteredClasses.map((classe) => {
              const centre = centres.find(c => c.id === classe.centre_id);
              const groupe = groupesClasses.find(g => g.id === classe.groupe_classe_id);
              const { color, label } = {
                color: getStatutColor(classe),
                label: getStatutLabel(classe)
              };
              
              return (
                <TableRow key={classe.id}>
                  <TableCell className="font-medium">{classe.nom_classe}</TableCell>
                  <TableCell>{groupe?.nom || 'Aucun groupe'}</TableCell>
                  <TableCell>{centre?.nom || 'N/A'}</TableCell>
                  <TableCell>{new Date(classe.date_debut).toLocaleDateString()}</TableCell>
                  <TableCell>{new Date(classe.date_fin).toLocaleDateString()}</TableCell>
                  <TableCell>{classe.nombre_places}</TableCell>
                  <TableCell>
                    <Badge className={color}>
                      {label}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center space-x-2">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => navigate(`/administration/classe/${classe.id}/inscriptions`)}
                        title="Voir les inscriptions"
                      >
                        <Users className="h-4 w-4" />
                      </Button>
                      <EditClasseButton 
                        classe={classe} 
                        onEdit={handleEdit}
                        canModifyClasse={canModifyClasse}
                      />
                      <DeleteClasseButton 
                        classe={classe} 
                        onDelete={handleDelete}
                        canModifyClasse={canModifyClasse}
                      />
                    </div>
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </div>

      {filteredClasses.length === 0 && (
        <div className="text-center py-8 text-muted-foreground">
          Aucune classe trouvée pour ce segment.
        </div>
      )}
    </div>
  );
}