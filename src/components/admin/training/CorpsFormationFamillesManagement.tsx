import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Switch } from '@/components/ui/switch';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { Plus, Edit, Trash2, ArrowLeft, FileText, Award, CreditCard, Shield, User, Briefcase } from 'lucide-react';
import { supabase } from '@/integrations/supabase/client';
import { toast } from 'sonner';
interface CorpsFormation {
  id: string;
  nom: string;
  description: string | null;
  is_active: boolean;
}
interface CorpsFormationFamille {
  id: string;
  corps_formation_id: string;
  famille_nom: string;
  famille_description: string | null;
  famille_icone: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}
interface CorpsFormationFamillesManagementProps {
  corpsFormation: CorpsFormation;
  onBack: () => void;
}
const iconOptions = [{
  value: 'FileText',
  label: 'Document',
  icon: FileText
}, {
  value: 'Award',
  label: 'Récompense',
  icon: Award
}, {
  value: 'CreditCard',
  label: 'Carte',
  icon: CreditCard
}, {
  value: 'Shield',
  label: 'Badge',
  icon: Shield
}, {
  value: 'User',
  label: 'Profil',
  icon: User
}, {
  value: 'Briefcase',
  label: 'Portfolio',
  icon: Briefcase
}];
const CorpsFormationFamillesManagement: React.FC<CorpsFormationFamillesManagementProps> = ({
  corpsFormation,
  onBack
}) => {
  const [familles, setFamilles] = useState<CorpsFormationFamille[]>([]);
  const [loading, setLoading] = useState(true);
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [editingFamille, setEditingFamille] = useState<CorpsFormationFamille | null>(null);
  const [formData, setFormData] = useState({
    famille_nom: '',
    famille_description: '',
    famille_icone: 'FileText',
    is_active: true
  });
  useEffect(() => {
    loadFamilles();
  }, [corpsFormation.id]);
  const loadFamilles = async () => {
    try {
      const {
        data,
        error
      } = await supabase.from('corps_formation_familles').select('*').eq('corps_formation_id', corpsFormation.id).order('famille_nom');
      if (error) throw error;
      setFamilles(data || []);
    } catch (error) {
      console.error('Erreur lors du chargement des familles:', error);
      toast.error('Erreur lors du chargement des familles');
    } finally {
      setLoading(false);
    }
  };
  const resetForm = () => {
    setFormData({
      famille_nom: '',
      famille_description: '',
      famille_icone: 'FileText',
      is_active: true
    });
    setEditingFamille(null);
  };
  const handleEdit = (famille: CorpsFormationFamille) => {
    setEditingFamille(famille);
    setFormData({
      famille_nom: famille.famille_nom,
      famille_description: famille.famille_description || '',
      famille_icone: famille.famille_icone,
      is_active: famille.is_active
    });
    setIsDialogOpen(true);
  };
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.famille_nom.trim()) {
      toast.error('Le nom de la famille est requis');
      return;
    }
    try {
      if (editingFamille) {
        const {
          error
        } = await supabase.from('corps_formation_familles').update(formData).eq('id', editingFamille.id);
        if (error) throw error;
        toast.success('Famille modifiée avec succès');
      } else {
        const {
          error
        } = await supabase.from('corps_formation_familles').insert([{
          ...formData,
          corps_formation_id: corpsFormation.id
        }]);
        if (error) throw error;
        toast.success('Famille créée avec succès');
      }
      await loadFamilles();
      setIsDialogOpen(false);
      resetForm();
    } catch (error) {
      console.error('Erreur lors de la sauvegarde:', error);
      toast.error('Erreur lors de la sauvegarde');
    }
  };
  const handleDelete = async (famille: CorpsFormationFamille) => {
    if (!confirm(`Êtes-vous sûr de vouloir supprimer la famille "${famille.famille_nom}" ?`)) {
      return;
    }
    try {
      const {
        error
      } = await supabase.from('corps_formation_familles').delete().eq('id', famille.id);
      if (error) throw error;
      toast.success('Famille supprimée');
      await loadFamilles();
    } catch (error) {
      console.error('Erreur lors de la suppression:', error);
      toast.error('Erreur lors de la suppression');
    }
  };
  const getIconComponent = (iconName: string) => {
    const iconOption = iconOptions.find(option => option.value === iconName);
    const IconComponent = iconOption?.icon || FileText;
    return <IconComponent className="h-4 w-4" />;
  };
  if (loading) {
    return <div className="flex justify-center items-center h-64">Chargement...</div>;
  }
  return <div className="space-y-6">
      <div className="flex items-center gap-4">
        <Button variant="outline" onClick={onBack}>
          <ArrowLeft className="h-4 w-4 mr-2" />
          Retour
        </Button>
        <div>
          <h2 className="text-2xl font-bold">Type de Livrables</h2>
          <p className="text-muted-foreground">Corps de formation: {corpsFormation.nom}</p>
        </div>
      </div>

      <div className="flex justify-between items-center">
        <h3 className="text-xl font-semibold">Gestion des Types</h3>
        <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
          <DialogTrigger asChild>
            <Button onClick={resetForm}>
              <Plus className="h-4 w-4 mr-2" />
              Nouveau Type
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>
                {editingFamille ? 'Modifier la Famille' : 'Nouvelle Famille'}
              </DialogTitle>
            </DialogHeader>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <Label htmlFor="famille_nom">Nom de la famille *</Label>
                <Input id="famille_nom" value={formData.famille_nom} onChange={e => setFormData({
                ...formData,
                famille_nom: e.target.value
              })} placeholder="ex: Badge, Certificat, Attestation" required />
              </div>
              <div>
                <Label htmlFor="famille_description">Description</Label>
                <Textarea id="famille_description" value={formData.famille_description} onChange={e => setFormData({
                ...formData,
                famille_description: e.target.value
              })} placeholder="Description de cette famille de documents" />
              </div>
              <div>
                <Label htmlFor="famille_icone">Icône</Label>
                <Select value={formData.famille_icone} onValueChange={value => setFormData({
                ...formData,
                famille_icone: value
              })}>
                  <SelectTrigger>
                    <SelectValue placeholder="Choisir une icône" />
                  </SelectTrigger>
                  <SelectContent>
                    {iconOptions.map(option => <SelectItem key={option.value} value={option.value}>
                        <div className="flex items-center gap-2">
                          <option.icon className="h-4 w-4" />
                          {option.label}
                        </div>
                      </SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
              <div className="flex items-center space-x-2">
                <Switch id="is_active" checked={formData.is_active} onCheckedChange={checked => setFormData({
                ...formData,
                is_active: checked
              })} />
                <Label htmlFor="is_active">Active</Label>
              </div>
              <div className="flex justify-end gap-2">
                <Button type="button" variant="outline" onClick={() => setIsDialogOpen(false)}>
                  Annuler
                </Button>
                <Button type="submit">
                  {editingFamille ? 'Modifier' : 'Créer'}
                </Button>
              </div>
            </form>
          </DialogContent>
        </Dialog>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Liste des type de Livrables</CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Icône</TableHead>
                <TableHead>Nom</TableHead>
                <TableHead>Description</TableHead>
                <TableHead>Statut</TableHead>
                <TableHead>Date de création</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {familles.map(famille => <TableRow key={famille.id}>
                  <TableCell>{getIconComponent(famille.famille_icone)}</TableCell>
                  <TableCell className="font-medium">{famille.famille_nom}</TableCell>
                  <TableCell>{famille.famille_description || '-'}</TableCell>
                  <TableCell>
                    <Badge variant={famille.is_active ? "default" : "secondary"}>
                      {famille.is_active ? 'Active' : 'Inactive'}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    {new Date(famille.created_at).toLocaleDateString('fr-FR')}
                  </TableCell>
                  <TableCell>
                    <div className="flex gap-2">
                      <Button variant="outline" size="sm" onClick={() => handleEdit(famille)}>
                        <Edit className="h-4 w-4" />
                      </Button>
                      <Button variant="outline" size="sm" onClick={() => handleDelete(famille)}>
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>)}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>;
};
export default CorpsFormationFamillesManagement;