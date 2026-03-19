import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { useToast } from '@/hooks/use-toast';
import { supabase } from '@/integrations/supabase/client';
import { Plus, Edit, Trash2, Ruler } from 'lucide-react';

interface FormatDocument {
  id: string;
  nom: string;
  largeur_mm: number;
  hauteur_mm: number;
  is_predefined: boolean;
  is_active: boolean;
  created_at: string;
}

const FormatsManagement = () => {
  const [formats, setFormats] = useState<FormatDocument[]>([]);
  const [selectedFormat, setSelectedFormat] = useState<FormatDocument | null>(null);
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [loading, setLoading] = useState(true);
  const { toast } = useToast();

  const [formData, setFormData] = useState({
    nom: '',
    largeur_mm: 0,
    hauteur_mm: 0
  });

  useEffect(() => {
    loadFormats();
  }, []);

  const loadFormats = async () => {
    try {
      setLoading(true);
      
      const { data, error } = await supabase
        .from('formats_documents')
        .select('*')
        .eq('is_active', true)
        .order('is_predefined', { ascending: false })
        .order('nom');

      if (error) throw error;
      setFormats(data || []);
    } catch (error: any) {
      toast({
        title: "Erreur de chargement",
        description: error.message,
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (formData.largeur_mm <= 0 || formData.hauteur_mm <= 0) {
      toast({
        title: "Erreur de validation",
        description: "Les dimensions doivent être supérieures à 0",
        variant: "destructive"
      });
      return;
    }

    try {
      if (selectedFormat) {
        // Mise à jour
        const { error } = await supabase
          .from('formats_documents')
          .update(formData)
          .eq('id', selectedFormat.id);

        if (error) throw error;
        
        toast({
          title: "Format mis à jour",
          description: "Le format a été mis à jour avec succès"
        });
      } else {
        // Création
        const { error } = await supabase
          .from('formats_documents')
          .insert([{ ...formData, is_predefined: false }]);

        if (error) throw error;
        
        toast({
          title: "Format créé",
          description: "Le format a été créé avec succès"
        });
      }

      setIsDialogOpen(false);
      setSelectedFormat(null);
      resetForm();
      loadFormats();
    } catch (error: any) {
      toast({
        title: "Erreur",
        description: error.message,
        variant: "destructive"
      });
    }
  };

  const handleEdit = (format: FormatDocument) => {
    if (format.is_predefined) {
      toast({
        title: "Modification interdite",
        description: "Les formats prédéfinis ne peuvent pas être modifiés",
        variant: "destructive"
      });
      return;
    }

    setSelectedFormat(format);
    setFormData({
      nom: format.nom,
      largeur_mm: format.largeur_mm,
      hauteur_mm: format.hauteur_mm
    });
    setIsDialogOpen(true);
  };

  const handleDelete = async (format: FormatDocument) => {
    if (format.is_predefined) {
      toast({
        title: "Suppression interdite",
        description: "Les formats prédéfinis ne peuvent pas être supprimés",
        variant: "destructive"
      });
      return;
    }

    if (!confirm('Êtes-vous sûr de vouloir supprimer ce format ?')) return;

    try {
      const { error } = await supabase
        .from('formats_documents')
        .update({ is_active: false })
        .eq('id', format.id);

      if (error) throw error;
      
      toast({
        title: "Format supprimé",
        description: "Le format a été supprimé avec succès"
      });
      loadFormats();
    } catch (error: any) {
      toast({
        title: "Erreur de suppression",
        description: error.message,
        variant: "destructive"
      });
    }
  };

  const resetForm = () => {
    setFormData({
      nom: '',
      largeur_mm: 0,
      hauteur_mm: 0
    });
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('fr-FR', {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric'
    });
  };

  if (loading) {
    return <div className="flex justify-center p-8">Chargement...</div>;
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-bold">Gestion des Formats</h2>
        <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
          <DialogTrigger asChild>
            <Button onClick={() => { resetForm(); setSelectedFormat(null); }}>
              <Plus className="h-4 w-4 mr-2" />
              Nouveau Format
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>
                {selectedFormat ? 'Modifier le Format' : 'Créer un Nouveau Format'}
              </DialogTitle>
            </DialogHeader>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <Label htmlFor="nom">Nom du format</Label>
                <Input
                  id="nom"
                  value={formData.nom}
                  onChange={(e) => setFormData(prev => ({ ...prev, nom: e.target.value }))}
                  placeholder="Ex: Carte de visite, A3, etc."
                  required
                />
              </div>
              
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label htmlFor="largeur">Largeur (mm)</Label>
                  <Input
                    id="largeur"
                    type="number"
                    min="1"
                    step="0.1"
                    value={formData.largeur_mm}
                    onChange={(e) => setFormData(prev => ({ ...prev, largeur_mm: Number(e.target.value) }))}
                    required
                  />
                </div>
                <div>
                  <Label htmlFor="hauteur">Hauteur (mm)</Label>
                  <Input
                    id="hauteur"
                    type="number"
                    min="1"
                    step="0.1"
                    value={formData.hauteur_mm}
                    onChange={(e) => setFormData(prev => ({ ...prev, hauteur_mm: Number(e.target.value) }))}
                    required
                  />
                </div>
              </div>

              <div className="text-sm text-muted-foreground">
                Ratio: {formData.largeur_mm && formData.hauteur_mm 
                  ? (formData.largeur_mm / formData.hauteur_mm).toFixed(2)
                  : '-'
                }
              </div>

              <div className="flex justify-end space-x-2 pt-4">
                <Button type="button" variant="outline" onClick={() => setIsDialogOpen(false)}>
                  Annuler
                </Button>
                <Button type="submit">
                  {selectedFormat ? 'Mettre à jour' : 'Créer'}
                </Button>
              </div>
            </form>
          </DialogContent>
        </Dialog>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Ruler className="h-5 w-5" />
            Formats Disponibles
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Nom</TableHead>
                <TableHead>Dimensions</TableHead>
                <TableHead>Ratio</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Créé le</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {formats.map((format) => (
                <TableRow key={format.id}>
                  <TableCell className="font-medium">{format.nom}</TableCell>
                  <TableCell>
                    {format.largeur_mm} × {format.hauteur_mm} mm
                  </TableCell>
                  <TableCell>
                    {(format.largeur_mm / format.hauteur_mm).toFixed(2)}
                  </TableCell>
                  <TableCell>
                    <Badge variant={format.is_predefined ? 'default' : 'secondary'}>
                      {format.is_predefined ? 'Prédéfini' : 'Personnalisé'}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {formatDate(format.created_at)}
                  </TableCell>
                  <TableCell>
                    <div className="flex space-x-2">
                      <Button 
                        size="sm" 
                        variant="outline" 
                        onClick={() => handleEdit(format)}
                        disabled={format.is_predefined}
                      >
                        <Edit className="h-4 w-4" />
                      </Button>
                      <Button 
                        size="sm" 
                        variant="outline" 
                        onClick={() => handleDelete(format)}
                        disabled={format.is_predefined}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          
          {formats.length === 0 && (
            <div className="py-8 text-center">
              <p className="text-muted-foreground">Aucun format trouvé</p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
};

export default FormatsManagement;