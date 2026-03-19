import React, { useState, useEffect } from 'react';
import { Calendar, Plus, Edit2, Trash2, AlertTriangle } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger } from '@/components/ui/alert-dialog';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { Checkbox } from '@/components/ui/checkbox';
import { useToast } from '@/hooks/use-toast';
import { format } from 'date-fns';
import fr from 'date-fns/locale/fr';
import { queryAPI } from '@/services/database';

interface JourFerie {
  id: string;
  nom: string;
  date_debut: string;
  date_fin: string;
  type_conge: string;
  description?: string;
  is_recurrent: boolean;
  is_active: boolean;
  created_at: string;
}

const HolidayManagement: React.FC = () => {
  const [holidays, setHolidays] = useState<JourFerie[]>([]);
  const [loading, setLoading] = useState(true);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editingHoliday, setEditingHoliday] = useState<JourFerie | null>(null);
  const [formData, setFormData] = useState({
    nom: '',
    date_debut: '',
    date_fin: '',
    type_conge: 'ferie',
    description: '',
    is_recurrent: false
  });
  const { toast } = useToast();

  useEffect(() => {
    loadHolidays();
  }, [loadHolidays]);

  const loadHolidays = async () => {
    try {
      const result = await queryAPI('/api/holidays');
      setHolidays(result || []);
    } catch (error) {
      console.error('Erreur lors du chargement des jours fériés:', error);
      toast({
        title: "Erreur",
        description: "Impossible de charger les jours fériés",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const dataToSubmit = {
        ...formData,
        date_fin: formData.date_fin || formData.date_debut
      };

      if (editingHoliday) {
        await queryAPI(`/api/holidays/${editingHoliday.id}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(dataToSubmit)
        });
        toast({
          title: "Succès",
          description: "Jour férié modifié avec succès",
        });
      } else {
        await queryAPI('/api/holidays', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(dataToSubmit)
        });
        toast({
          title: "Succès",
          description: "Jour férié ajouté avec succès",
        });
      }

      resetForm();
      setDialogOpen(false);
      loadHolidays();
    } catch (error) {
      console.error('Erreur lors de la sauvegarde:', error);
      toast({
        title: "Erreur",
        description: "Impossible de sauvegarder le jour férié",
        variant: "destructive",
      });
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await queryAPI(`/api/holidays/${id}`, {
        method: 'DELETE'
      });
      toast({
        title: "Succès",
        description: "Jour férié désactivé avec succès",
      });
      loadHolidays();
    } catch (error) {
      console.error('Erreur lors de la suppression:', error);
      toast({
        title: "Erreur",
        description: "Impossible de désactiver le jour férié",
        variant: "destructive",
      });
    }
  };

  const resetForm = () => {
    setFormData({
      nom: '',
      date_debut: '',
      date_fin: '',
      type_conge: 'ferie',
      description: '',
      is_recurrent: false
    });
    setEditingHoliday(null);
  };

  const openEditDialog = (holiday: JourFerie) => {
    setEditingHoliday(holiday);
    setFormData({
      nom: holiday.nom,
      date_debut: holiday.date_debut,
      date_fin: holiday.date_fin,
      type_conge: holiday.type_conge,
      description: holiday.description || '',
      is_recurrent: holiday.is_recurrent
    });
    setDialogOpen(true);
  };

  const getTypeLabel = (type: string) => {
    switch (type) {
      case 'ferie': return 'Jour férié';
      case 'collectif': return 'Congé collectif';
      case 'pont': return 'Pont';
      default: return type;
    }
  };

  const getTypeBadgeVariant = (type: string) => {
    switch (type) {
      case 'ferie': return 'default';
      case 'collectif': return 'secondary';
      case 'pont': return 'outline';
      default: return 'default';
    }
  };

  if (loading) {
    return (
      <Card>
        <CardContent className="p-6">
          <div className="animate-pulse space-y-4">
            <div className="h-4 bg-muted rounded w-1/4"></div>
            <div className="h-32 bg-muted rounded"></div>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Calendar className="h-5 w-5" />
          Gestion des Jours Fériés et Congés Collectifs
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="mb-4">
          <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
            <DialogTrigger asChild>
              <Button onClick={resetForm} className="flex items-center gap-2">
                <Plus className="h-4 w-4" />
                Ajouter un jour férié
              </Button>
            </DialogTrigger>
            <DialogContent className="sm:max-w-[500px]">
              <DialogHeader>
                <DialogTitle>
                  {editingHoliday ? 'Modifier le jour férié' : 'Ajouter un jour férié'}
                </DialogTitle>
              </DialogHeader>
              <form onSubmit={handleSubmit} className="space-y-4">
                <div>
                  <Label htmlFor="nom">Nom *</Label>
                  <Input
                    id="nom"
                    value={formData.nom}
                    onChange={(e) => setFormData({ ...formData, nom: e.target.value })}
                    placeholder="Ex: Fête du Travail"
                    required
                  />
                </div>

                <div>
                  <Label htmlFor="type_conge">Type *</Label>
                  <Select
                    value={formData.type_conge}
                    onValueChange={(value) => 
                      setFormData({ ...formData, type_conge: value })
                    }
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="ferie">Jour férié</SelectItem>
                      <SelectItem value="collectif">Congé collectif</SelectItem>
                      <SelectItem value="pont">Pont</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="grid grid-cols-2 gap-4">
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
                    <Label htmlFor="date_fin">Date de fin</Label>
                    <Input
                      id="date_fin"
                      type="date"
                      value={formData.date_fin}
                      onChange={(e) => setFormData({ ...formData, date_fin: e.target.value })}
                      placeholder="Optionnel (si différent du début)"
                    />
                  </div>
                </div>

                <div>
                  <Label htmlFor="description">Description</Label>
                  <Textarea
                    id="description"
                    value={formData.description}
                    onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                    placeholder="Description optionnelle"
                    rows={3}
                  />
                </div>

                <div className="flex items-center space-x-2">
                  <Checkbox
                    id="is_recurrent"
                    checked={formData.is_recurrent}
                    onCheckedChange={(checked) => 
                      setFormData({ ...formData, is_recurrent: checked as boolean })
                    }
                  />
                  <Label htmlFor="is_recurrent">
                    Récurrent (se répète chaque année)
                  </Label>
                </div>

                <div className="flex justify-end gap-2">
                  <Button type="button" variant="outline" onClick={() => setDialogOpen(false)}>
                    Annuler
                  </Button>
                  <Button type="submit">
                    {editingHoliday ? 'Modifier' : 'Ajouter'}
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
              <TableHead>Type</TableHead>
              <TableHead>Date début</TableHead>
              <TableHead>Date fin</TableHead>
              <TableHead>Récurrent</TableHead>
              <TableHead>Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {holidays.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} className="text-center text-muted-foreground">
                  Aucun jour férié configuré
                </TableCell>
              </TableRow>
            ) : (
              holidays.map((holiday) => (
                <TableRow key={holiday.id}>
                  <TableCell className="font-medium">{holiday.nom}</TableCell>
                  <TableCell>
                    <Badge variant={getTypeBadgeVariant(holiday.type_conge)}>
                      {getTypeLabel(holiday.type_conge)}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    {format(new Date(holiday.date_debut), 'dd/MM/yyyy', { locale: fr })}
                  </TableCell>
                  <TableCell>
                    {holiday.date_fin !== holiday.date_debut 
                      ? format(new Date(holiday.date_fin), 'dd/MM/yyyy', { locale: fr })
                      : '-'
                    }
                  </TableCell>
                  <TableCell>
                    {holiday.is_recurrent ? (
                      <Badge variant="outline">Oui</Badge>
                    ) : (
                      <Badge variant="secondary">Non</Badge>
                    )}
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => openEditDialog(holiday)}
                      >
                        <Edit2 className="h-4 w-4" />
                      </Button>
                      <AlertDialog>
                        <AlertDialogTrigger asChild>
                          <Button variant="outline" size="sm">
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </AlertDialogTrigger>
                        <AlertDialogContent>
                          <AlertDialogHeader>
                            <AlertDialogTitle>Confirmer la suppression</AlertDialogTitle>
                            <AlertDialogDescription>
                              Êtes-vous sûr de vouloir supprimer le jour férié "{holiday.nom}" ?
                              Cette action ne peut pas être annulée.
                            </AlertDialogDescription>
                          </AlertDialogHeader>
                          <AlertDialogFooter>
                            <AlertDialogCancel>Annuler</AlertDialogCancel>
                            <AlertDialogAction
                              onClick={() => handleDelete(holiday.id)}
                              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                            >
                              Supprimer
                            </AlertDialogAction>
                          </AlertDialogFooter>
                        </AlertDialogContent>
                      </AlertDialog>
                    </div>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
};

export default HolidayManagement;