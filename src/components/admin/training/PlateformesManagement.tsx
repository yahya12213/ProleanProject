import React, { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Badge } from '@/components/ui/badge';
import { Plus, Edit, Trash2 } from 'lucide-react';
import { supabase } from '@/integrations/supabase/client';
import { useToast } from '@/hooks/use-toast';

interface Plateforme {
  id: string;
  nom: string;
  description?: string;
  url_plateforme?: string;
  contact_email?: string;
  is_active: boolean;
}

export function PlateformesManagement() {
  const [plateformes, setPlateformes] = useState<Plateforme[]>([]);
  const [loading, setLoading] = useState(true);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [editingPlateforme, setEditingPlateforme] = useState<Plateforme | null>(null);
  const { toast } = useToast();

  const [formData, setFormData] = useState({
    nom: '',
    description: '',
    url_plateforme: '',
    contact_email: '',
    is_active: true
  });

  useEffect(() => {
    loadPlateformes();
  }, []);

  const loadPlateformes = async () => {
    try {
      setLoading(true);
      const { data, error } = await supabase
        .from('plateformes')
        .select('*')
        .order('nom');

      if (error) throw error;
      setPlateformes(data || []);
    } catch (error) {
      console.error('Error loading plateformes:', error);
      toast({
        title: "Erreur",
        description: "Impossible de charger les plateformes",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const resetForm = () => {
    setFormData({
      nom: '',
      description: '',
      url_plateforme: '',
      contact_email: '',
      is_active: true
    });
    setEditingPlateforme(null);
  };

  const handleEdit = (plateforme: Plateforme) => {
    setFormData({
      nom: plateforme.nom,
      description: plateforme.description || '',
      url_plateforme: plateforme.url_plateforme || '',
      contact_email: plateforme.contact_email || '',
      is_active: plateforme.is_active
    });
    setEditingPlateforme(plateforme);
    setIsModalOpen(true);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    try {
      if (editingPlateforme) {
        const { error } = await supabase
          .from('plateformes')
          .update(formData)
          .eq('id', editingPlateforme.id);
        
        if (error) throw error;
        
        toast({
          title: "Succès",
          description: "Plateforme mise à jour avec succès"
        });
      } else {
        const { error } = await supabase
          .from('plateformes')
          .insert([formData]);
        
        if (error) throw error;
        
        toast({
          title: "Succès",
          description: "Plateforme créée avec succès"
        });
      }

      setIsModalOpen(false);
      resetForm();
      loadPlateformes();
    } catch (error) {
      console.error('Error saving plateforme:', error);
      toast({
        title: "Erreur",
        description: "Impossible de sauvegarder la plateforme",
        variant: "destructive"
      });
    }
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Êtes-vous sûr de vouloir supprimer cette plateforme ?')) return;

    try {
      const { error } = await supabase
        .from('plateformes')
        .delete()
        .eq('id', id);

      if (error) throw error;

      toast({
        title: "Succès",
        description: "Plateforme supprimée avec succès"
      });
      
      loadPlateformes();
    } catch (error) {
      console.error('Error deleting plateforme:', error);
      toast({
        title: "Erreur",
        description: "Impossible de supprimer la plateforme",
        variant: "destructive"
      });
    }
  };

  if (loading) {
    return <div className="p-4">Chargement...</div>;
  }

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h3 className="text-lg font-semibold">Liste des plateformes</h3>
        <Dialog open={isModalOpen} onOpenChange={setIsModalOpen}>
          <DialogTrigger asChild>
            <Button onClick={resetForm}>
              <Plus className="h-4 w-4 mr-2" />
              Ajouter une plateforme
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-md">
            <DialogHeader>
              <DialogTitle>
                {editingPlateforme ? 'Modifier la plateforme' : 'Ajouter une plateforme'}
              </DialogTitle>
            </DialogHeader>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <Label htmlFor="nom">Nom de la plateforme *</Label>
                <Input
                  id="nom"
                  value={formData.nom}
                  onChange={(e) => setFormData({ ...formData, nom: e.target.value })}
                  required
                />
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
                <Label htmlFor="url_plateforme">URL de la plateforme</Label>
                <Input
                  id="url_plateforme"
                  type="url"
                  value={formData.url_plateforme}
                  onChange={(e) => setFormData({ ...formData, url_plateforme: e.target.value })}
                />
              </div>

              <div>
                <Label htmlFor="contact_email">Email de contact</Label>
                <Input
                  id="contact_email"
                  type="email"
                  value={formData.contact_email}
                  onChange={(e) => setFormData({ ...formData, contact_email: e.target.value })}
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
                    <SelectItem value="true">Actif</SelectItem>
                    <SelectItem value="false">Inactif</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="flex justify-end space-x-2">
                <Button type="button" variant="outline" onClick={() => setIsModalOpen(false)}>
                  Annuler
                </Button>
                <Button type="submit">
                  {editingPlateforme ? 'Modifier' : 'Ajouter'}
                </Button>
              </div>
            </form>
          </DialogContent>
        </Dialog>
      </div>

      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Nom</TableHead>
            <TableHead>Description</TableHead>
            <TableHead>URL</TableHead>
            <TableHead>Contact</TableHead>
            <TableHead>Statut</TableHead>
            <TableHead>Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {plateformes.map((plateforme) => (
            <TableRow key={plateforme.id}>
              <TableCell className="font-medium">{plateforme.nom}</TableCell>
              <TableCell>{plateforme.description || '-'}</TableCell>
              <TableCell>
                {plateforme.url_plateforme ? (
                  <a 
                    href={plateforme.url_plateforme} 
                    target="_blank" 
                    rel="noopener noreferrer"
                    className="text-primary hover:underline"
                  >
                    Visiter
                  </a>
                ) : '-'}
              </TableCell>
              <TableCell>{plateforme.contact_email || '-'}</TableCell>
              <TableCell>
                <Badge variant={plateforme.is_active ? "default" : "secondary"}>
                  {plateforme.is_active ? 'Actif' : 'Inactif'}
                </Badge>
              </TableCell>
              <TableCell>
                <div className="flex space-x-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => handleEdit(plateforme)}
                  >
                    <Edit className="h-4 w-4" />
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => handleDelete(plateforme.id)}
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