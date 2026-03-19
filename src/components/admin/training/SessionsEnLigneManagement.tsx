import React, { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Badge } from '@/components/ui/badge';
import { Plus, Edit, Trash2, Users } from 'lucide-react';
import { supabase } from '@/integrations/supabase/client';
import { useToast } from '@/hooks/use-toast';

interface SessionEnLigne {
  id: string;
  nom_session: string;
  formation_id: string;
  plateforme_id: string;
  nombre_places: number;
  date_debut: string;
  date_fin: string;
  formateur?: string;
  url_session?: string;
  statut: 'programmee' | 'en_cours' | 'terminee' | 'annulee';
  is_active: boolean;
  formations?: { titre: string };
  plateformes?: { nom: string };
}

interface Formation {
  id: string;
  titre: string;
}

interface Plateforme {
  id: string;
  nom: string;
}

export function SessionsEnLigneManagement() {
  const [sessions, setSessions] = useState<SessionEnLigne[]>([]);
  const [formations, setFormations] = useState<Formation[]>([]);
  const [plateformes, setPlateformes] = useState<Plateforme[]>([]);
  const [loading, setLoading] = useState(true);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [editingSession, setEditingSession] = useState<SessionEnLigne | null>(null);
  const { toast } = useToast();

  const [formData, setFormData] = useState({
    nom_session: '',
    formation_id: '',
    plateforme_id: '',
    nombre_places: 0,
    date_debut: '',
    date_fin: '',
    formateur: '',
    url_session: '',
    is_active: true
  });

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      
      // Load sessions with related data
      const { data: sessionsData, error: sessionsError } = await supabase
        .from('sessions_en_ligne')
        .select(`
          *,
          formations:formation_id(titre),
          plateformes:plateforme_id(nom)
        `)
        .order('date_debut', { ascending: false });

      // Load formations en ligne
      const { data: formationsData, error: formationsError } = await supabase
        .from('formations')
        .select('*')
        .eq('type_formation', 'en_ligne')
        .eq('is_active', true)
        .order('titre');

      // Load plateformes
      const { data: plateformesData, error: plateformesError } = await supabase
        .from('plateformes')
        .select('*')
        .eq('is_active', true)
        .order('nom');

      if (sessionsError) throw sessionsError;
      if (formationsError) throw formationsError;
      if (plateformesError) throw plateformesError;

      setSessions(sessionsData || []);
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
      nom_session: '',
      formation_id: '',
      plateforme_id: '',
      nombre_places: 0,
      date_debut: '',
      date_fin: '',
      formateur: '',
      url_session: '',
      is_active: true
    });
    setEditingSession(null);
  };

  const handleEdit = (session: SessionEnLigne) => {
    setFormData({
      nom_session: session.nom_session,
      formation_id: session.formation_id,
      plateforme_id: session.plateforme_id,
      nombre_places: session.nombre_places,
      date_debut: session.date_debut,
      date_fin: session.date_fin,
      formateur: session.formateur || '',
      url_session: session.url_session || '',
      is_active: session.is_active
    });
    setEditingSession(session);
    setIsModalOpen(true);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    try {
      if (editingSession) {
        const { error } = await supabase
          .from('sessions_en_ligne')
          .update(formData)
          .eq('id', editingSession.id);
        
        if (error) throw error;
        
        toast({
          title: "Succès",
          description: "Session mise à jour avec succès"
        });
      } else {
        const { error } = await supabase
          .from('sessions_en_ligne')
          .insert([formData]);
        
        if (error) throw error;
        
        toast({
          title: "Succès",
          description: "Session créée avec succès"
        });
      }

      setIsModalOpen(false);
      resetForm();
      loadData();
    } catch (error) {
      console.error('Error saving session:', error);
      toast({
        title: "Erreur",
        description: "Impossible de sauvegarder la session",
        variant: "destructive"
      });
    }
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Êtes-vous sûr de vouloir supprimer cette session ?')) return;

    try {
      const { error } = await supabase
        .from('sessions_en_ligne')
        .delete()
        .eq('id', id);

      if (error) throw error;

      toast({
        title: "Succès",
        description: "Session supprimée avec succès"
      });
      
      loadData();
    } catch (error) {
      console.error('Error deleting session:', error);
      toast({
        title: "Erreur",
        description: "Impossible de supprimer la session",
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

  if (loading) {
    return <div className="p-4">Chargement...</div>;
  }

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h3 className="text-lg font-semibold">Sessions en ligne</h3>
        <Dialog open={isModalOpen} onOpenChange={setIsModalOpen}>
          <DialogTrigger asChild>
            <Button onClick={resetForm}>
              <Plus className="h-4 w-4 mr-2" />
              Programmer une session
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-md">
            <DialogHeader>
              <DialogTitle>
                {editingSession ? 'Modifier la session' : 'Programmer une session'}
              </DialogTitle>
            </DialogHeader>
            <form onSubmit={handleSubmit} className="space-y-4">
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
                <Label htmlFor="formation">Formation *</Label>
                <Select
                  value={formData.formation_id}
                  onValueChange={(value) => setFormData({ ...formData, formation_id: value })}
                  required
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Sélectionner une formation" />
                  </SelectTrigger>
                  <SelectContent>
                    {formations.map((formation) => (
                      <SelectItem key={formation.id} value={formation.id}>
                        {formation.titre}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div>
                <Label htmlFor="nom_session">Nom de la session *</Label>
                <Input
                  id="nom_session"
                  value={formData.nom_session}
                  onChange={(e) => setFormData({ ...formData, nom_session: e.target.value })}
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
                <Label htmlFor="formateur">Formateur</Label>
                <Input
                  id="formateur"
                  value={formData.formateur}
                  onChange={(e) => setFormData({ ...formData, formateur: e.target.value })}
                />
              </div>

              <div>
                <Label htmlFor="url_session">URL de la session</Label>
                <Input
                  id="url_session"
                  type="url"
                  value={formData.url_session}
                  onChange={(e) => setFormData({ ...formData, url_session: e.target.value })}
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
                  {editingSession ? 'Modifier' : 'Programmer'}
                </Button>
              </div>
            </form>
          </DialogContent>
        </Dialog>
      </div>

      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Formation</TableHead>
            <TableHead>Plateforme</TableHead>
            <TableHead>Dates</TableHead>
            <TableHead>Places</TableHead>
            <TableHead>Formateur</TableHead>
            <TableHead>Statut</TableHead>
            <TableHead>Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {sessions.map((session) => (
            <TableRow key={session.id}>
              <TableCell>
                <div>
                  <div className="font-medium">{session.formations?.titre}</div>
                  <div className="text-sm text-muted-foreground">{session.nom_session}</div>
                </div>
              </TableCell>
              <TableCell>{session.plateformes?.nom}</TableCell>
              <TableCell>
                <div className="text-sm">
                  <div>Du {new Date(session.date_debut).toLocaleDateString()}</div>
                  <div>Au {new Date(session.date_fin).toLocaleDateString()}</div>
                </div>
              </TableCell>
              <TableCell>
                <span className="font-medium">0/{session.nombre_places}</span>
              </TableCell>
              <TableCell>{session.formateur || '-'}</TableCell>
              <TableCell>
                <Badge className={getStatutColor(session.statut, session.date_debut, session.date_fin)}>
                  {getStatutLabel(session.statut, session.date_debut, session.date_fin)}
                </Badge>
              </TableCell>
              <TableCell>
                <div className="flex space-x-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => {/* TODO: Navigate to inscriptions management */}}
                  >
                    <Users className="h-4 w-4" />
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => handleEdit(session)}
                  >
                    <Edit className="h-4 w-4" />
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => handleDelete(session.id)}
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