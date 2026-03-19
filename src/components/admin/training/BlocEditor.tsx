import React, { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Badge } from '@/components/ui/badge';
import { Plus, Edit, Trash2, Move, Type, Image, FileText, MousePointer } from 'lucide-react';
import { supabase } from '@/integrations/supabase/client';
import { useToast } from '@/hooks/use-toast';
import FullScreenBlocEditor from './FullScreenBlocEditor';
import { normalizeCSSStyles } from '@/lib/pdf-font-utils';

interface DocumentBloc {
  id: string;
  nom_bloc: string;
  type_contenu: string;
  face: string;
  position_x: number;
  position_y: number;
  largeur: number;
  hauteur: number;
  styles_css: any;
  ordre_affichage: number;
}

interface BlocEditorProps {
  modeleId: string;
  blocs: DocumentBloc[];
  onBlocsChange: (blocs: DocumentBloc[]) => void;
  imageRectoUrl?: string;
  imageVersoUrl?: string;
}

const typeContenuOptions = [
  { value: 'texte', label: 'Texte', icon: Type },
  { value: 'image', label: 'Image', icon: Image },
  { value: 'date', label: 'Date', icon: FileText },
  { value: 'numero', label: 'Numéro', icon: FileText }
];

const champsPredefinisOptions = [
  { value: 'nom', label: 'Nom' },
  { value: 'prenom', label: 'Prénom' },
  { value: 'cin', label: 'CIN' },
  { value: 'date_naissance', label: 'Date de naissance' },
  { value: 'lieu_naissance', label: 'Lieu de naissance' },
  { value: 'telephone', label: 'Téléphone' },
  { value: 'email', label: 'Email' },
  { value: 'adresse', label: 'Adresse' },
  { value: 'photo_url', label: 'Photo' },
  { value: 'date_formation', label: 'Date de formation' },
  { value: 'date_delivrance', label: 'Date de délivrance' },
  { value: 'date_expiration', label: 'Date d\'expiration' }
];

const BlocEditor: React.FC<BlocEditorProps> = ({ modeleId, blocs, onBlocsChange, imageRectoUrl, imageVersoUrl }) => {
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [editingBloc, setEditingBloc] = useState<DocumentBloc | null>(null);
  const [loading, setLoading] = useState(false);
  const [isFullScreenEditorOpen, setIsFullScreenEditorOpen] = useState(false);
  const { toast } = useToast();

  const [formData, setFormData] = useState({
    nom_bloc: '',
    type_contenu: 'texte',
    face: 'recto',
    position_x: 0,
    position_y: 0,
    largeur: 100,
    hauteur: 30,
    champ_source: '',
    styles_css: {
      fontSize: 14, // ⚠️ IMPORTANT: Stocker en points, pas en pixels
      fontFamily: 'Arial',
      fontWeight: 'normal',
      color: '#000000',
      textAlign: 'left',
      backgroundColor: 'transparent',
      verticalAlign: 'middle' // Ajout du vertical align par défaut
    }
  });

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);

    try {
      const blocData = {
        modele_id: modeleId,
        nom_bloc: formData.nom_bloc,
        type_contenu: formData.type_contenu,
        face: formData.face,
        position_x: formData.position_x,
        position_y: formData.position_y,
        largeur: formData.largeur,
        hauteur: formData.hauteur,
      styles_css: {
        ...normalizeCSSStyles(formData.styles_css), // Normalisation selon les règles jsPDF
        champ_source: formData.champ_source
      },
        ordre_affichage: blocs.length + 1
      };

      if (editingBloc) {
        const { error } = await supabase
          .from('document_blocs')
          .update(blocData)
          .eq('id', editingBloc.id);

        if (error) throw error;

        const updatedBlocs = blocs.map(bloc => 
          bloc.id === editingBloc.id 
            ? { ...bloc, ...blocData } 
            : bloc
        );
        onBlocsChange(updatedBlocs);

        toast({
          title: "Bloc mis à jour",
          description: "Le bloc a été mis à jour avec succès"
        });
      } else {
        const { data, error } = await supabase
          .from('document_blocs')
          .insert([blocData])
          .select()
          .single();

        if (error) throw error;

        onBlocsChange([...blocs, data]);

        toast({
          title: "Bloc créé",
          description: "Le bloc a été créé avec succès"
        });
      }

      setIsDialogOpen(false);
      resetForm();
    } catch (error: any) {
      toast({
        title: "Erreur",
        description: error.message,
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const handleEdit = (bloc: DocumentBloc) => {
    setEditingBloc(bloc);
    setFormData({
      nom_bloc: bloc.nom_bloc,
      type_contenu: bloc.type_contenu,
      face: bloc.face,
      position_x: bloc.position_x,
      position_y: bloc.position_y,
      largeur: bloc.largeur,
      hauteur: bloc.hauteur,
      champ_source: bloc.styles_css?.champ_source || '',
      styles_css: normalizeCSSStyles(bloc.styles_css) // Utiliser la normalisation
    });
    setIsDialogOpen(true);
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Êtes-vous sûr de vouloir supprimer ce bloc ?')) return;

    try {
      const { error } = await supabase
        .from('document_blocs')
        .delete()
        .eq('id', id);

      if (error) throw error;

      const updatedBlocs = blocs.filter(bloc => bloc.id !== id);
      onBlocsChange(updatedBlocs);

      toast({
        title: "Bloc supprimé",
        description: "Le bloc a été supprimé avec succès"
      });
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
      nom_bloc: '',
      type_contenu: 'texte',
      face: 'recto',
      position_x: 0,
      position_y: 0,
      largeur: 100,
      hauteur: 30,
      champ_source: '',
    styles_css: {
      fontSize: 14, // En points, pas en pixels
      fontFamily: 'Arial',
      fontWeight: 'normal',
      color: '#000000',
      textAlign: 'left',
      backgroundColor: 'transparent',
      verticalAlign: 'middle'
    }
    });
    setEditingBloc(null);
  };

  const getTypeIcon = (type: string) => {
    const option = typeContenuOptions.find(opt => opt.value === type);
    return option ? option.icon : Type;
  };

  const handlePositionSelected = (x: number, y: number) => {
    setFormData(prev => ({
      ...prev,
      position_x: x,
      position_y: y
    }));
    setIsFullScreenEditorOpen(false);
  };

  const handleBlocUpdate = async (updatedBloc: DocumentBloc) => {
    try {
      const { error } = await supabase
        .from('document_blocs')
        .update({
          position_x: updatedBloc.position_x,
          position_y: updatedBloc.position_y,
          largeur: updatedBloc.largeur,
          hauteur: updatedBloc.hauteur
        })
        .eq('id', updatedBloc.id);

      if (error) throw error;

      const updatedBlocs = blocs.map(bloc => 
        bloc.id === updatedBloc.id ? updatedBloc : bloc
      );
      onBlocsChange(updatedBlocs);
    } catch (error: any) {
      toast({
        title: "Erreur de mise à jour",
        description: error.message,
        variant: "destructive"
      });
    }
  };

  const getCurrentImageUrl = () => {
    const face = formData.face as 'recto' | 'verso';
    return face === 'recto' ? imageRectoUrl : imageVersoUrl;
  };

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h4 className="text-lg font-medium">Configuration des Blocs</h4>
        <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
          <DialogTrigger asChild>
            <Button onClick={resetForm}>
              <Plus className="h-4 w-4 mr-2" />
              Ajouter un Bloc
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-3xl max-h-[90vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle>
                {editingBloc ? 'Modifier le Bloc' : 'Créer un Nouveau Bloc'}
              </DialogTitle>
            </DialogHeader>

            <form onSubmit={handleSubmit} className="space-y-6">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label>Nom du bloc</Label>
                  <Input
                    value={formData.nom_bloc}
                    onChange={(e) => setFormData(prev => ({ ...prev, nom_bloc: e.target.value }))}
                    placeholder="ex: Nom candidat"
                    required
                  />
                </div>

                <div>
                  <Label>Type de contenu</Label>
                  <Select 
                    value={formData.type_contenu} 
                    onValueChange={(value) => setFormData(prev => ({ ...prev, type_contenu: value }))}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {typeContenuOptions.map((option) => (
                        <SelectItem key={option.value} value={option.value}>
                          <div className="flex items-center gap-2">
                            <option.icon className="h-4 w-4" />
                            {option.label}
                          </div>
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                <div>
                  <Label>Face du document</Label>
                  <Select 
                    value={formData.face} 
                    onValueChange={(value) => setFormData(prev => ({ ...prev, face: value }))}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="recto">Recto</SelectItem>
                      <SelectItem value="verso">Verso</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div>
                  <Label>Champ source</Label>
                  <Select 
                    value={formData.champ_source} 
                    onValueChange={(value) => setFormData(prev => ({ ...prev, champ_source: value }))}
                  >
                    <SelectTrigger>
                      <SelectValue placeholder="Sélectionner un champ" />
                    </SelectTrigger>
                    <SelectContent>
                      {champsPredefinisOptions.map((option) => (
                        <SelectItem key={option.value} value={option.value}>
                          {option.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>

              {/* Position et dimensions */}
              <div className="space-y-4">
                <div className="flex justify-between items-center">
                  <h5 className="font-medium">Position et Dimensions</h5>
                  <Button 
                    type="button" 
                    variant="outline" 
                    size="sm"
                    onClick={() => setIsFullScreenEditorOpen(true)}
                    disabled={!getCurrentImageUrl()}
                  >
                    <MousePointer className="h-4 w-4 mr-2" />
                    Mode édition plein écran
                  </Button>
                </div>
                
                {!getCurrentImageUrl() && (
                  <div className="text-sm text-amber-600 bg-amber-50 p-3 rounded-lg border border-amber-200">
                    💡 Uploadez d'abord une image (onglet Images) pour utiliser le positionnement visuel
                  </div>
                )}
                
                <div className="grid grid-cols-4 gap-4">
                  <div>
                    <Label>Position X (px)</Label>
                    <Input
                      type="number"
                      value={formData.position_x}
                      onChange={(e) => setFormData(prev => ({ ...prev, position_x: parseInt(e.target.value) || 0 }))}
                    />
                  </div>
                  <div>
                    <Label>Position Y (px)</Label>
                    <Input
                      type="number"
                      value={formData.position_y}
                      onChange={(e) => setFormData(prev => ({ ...prev, position_y: parseInt(e.target.value) || 0 }))}
                    />
                  </div>
                  <div>
                    <Label>Largeur (px)</Label>
                    <Input
                      type="number"
                      value={formData.largeur}
                      onChange={(e) => setFormData(prev => ({ ...prev, largeur: parseInt(e.target.value) || 100 }))}
                    />
                  </div>
                  <div>
                    <Label>Hauteur (px)</Label>
                    <Input
                      type="number"
                      value={formData.hauteur}
                      onChange={(e) => setFormData(prev => ({ ...prev, hauteur: parseInt(e.target.value) || 30 }))}
                    />
                  </div>
                </div>
              </div>

              {/* Styles CSS */}
              <div className="space-y-4">
                <h5 className="font-medium">Styles</h5>
                <div className="grid grid-cols-3 gap-4">
                  <div>
                    <Label>Taille de police (points)</Label>
                    <Input
                      type="number"
                      min="6"
                      max="72"
                      value={formData.styles_css.fontSize}
                      onChange={(e) => setFormData(prev => ({ 
                        ...prev, 
                        styles_css: { ...prev.styles_css, fontSize: Number(e.target.value) || 14 }
                      }))}
                      placeholder="14"
                    />
                  </div>
                  <div>
                    <Label>Police</Label>
                    <Select 
                      value={formData.styles_css.fontFamily} 
                      onValueChange={(value) => setFormData(prev => ({ 
                        ...prev, 
                        styles_css: { ...prev.styles_css, fontFamily: value }
                      }))}
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="Arial">Arial</SelectItem>
                        <SelectItem value="Times New Roman">Times New Roman</SelectItem>
                        <SelectItem value="Helvetica">Helvetica</SelectItem>
                        <SelectItem value="Georgia">Georgia</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div>
                    <Label>Graisse</Label>
                    <Select 
                      value={formData.styles_css.fontWeight} 
                      onValueChange={(value) => setFormData(prev => ({ 
                        ...prev, 
                        styles_css: { ...prev.styles_css, fontWeight: value }
                      }))}
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="normal">Normal</SelectItem>
                        <SelectItem value="bold">Gras</SelectItem>
                        <SelectItem value="lighter">Léger</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div>
                    <Label>Couleur</Label>
                    <Input
                      type="color"
                      value={formData.styles_css.color}
                      onChange={(e) => setFormData(prev => ({ 
                        ...prev, 
                        styles_css: { ...prev.styles_css, color: e.target.value }
                      }))}
                    />
                  </div>
                  <div>
                    <Label>Alignement</Label>
                    <Select 
                      value={formData.styles_css.textAlign} 
                      onValueChange={(value) => setFormData(prev => ({ 
                        ...prev, 
                        styles_css: { ...prev.styles_css, textAlign: value }
                      }))}
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="left">Gauche</SelectItem>
                        <SelectItem value="center">Centre</SelectItem>
                        <SelectItem value="right">Droite</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div>
                    <Label>Fond</Label>
                    <Input
                      type="color"
                      value={formData.styles_css.backgroundColor === 'transparent' ? '#ffffff' : formData.styles_css.backgroundColor}
                      onChange={(e) => setFormData(prev => ({ 
                        ...prev, 
                        styles_css: { ...prev.styles_css, backgroundColor: e.target.value }
                      }))}
                    />
                  </div>
                </div>
              </div>

              <div className="flex justify-end space-x-2">
                <Button type="button" variant="outline" onClick={() => setIsDialogOpen(false)}>
                  Annuler
                </Button>
                <Button type="submit" disabled={loading}>
                  {loading ? 'Sauvegarde...' : (editingBloc ? 'Mettre à jour' : 'Créer')}
                </Button>
              </div>
            </form>
          </DialogContent>
        </Dialog>
      </div>

      <div className="grid gap-4">
        {blocs.map((bloc) => {
          const TypeIcon = getTypeIcon(bloc.type_contenu);
          return (
            <Card key={bloc.id}>
              <CardHeader className="pb-3">
                <div className="flex justify-between items-start">
                  <div className="flex items-center gap-3">
                    <TypeIcon className="h-5 w-5 text-muted-foreground" />
                    <div>
                      <CardTitle className="text-base">{bloc.nom_bloc}</CardTitle>
                      <div className="flex gap-2 mt-1">
                        <Badge variant="outline" className="text-xs">
                          {bloc.type_contenu}
                        </Badge>
                        <Badge variant="outline" className="text-xs">
                          {bloc.face}
                        </Badge>
                        {bloc.styles_css?.champ_source && (
                          <Badge variant="secondary" className="text-xs">
                            {champsPredefinisOptions.find(opt => opt.value === bloc.styles_css.champ_source)?.label || bloc.styles_css.champ_source}
                          </Badge>
                        )}
                      </div>
                    </div>
                  </div>
                  <div className="flex space-x-1">
                    <Button size="sm" variant="outline" onClick={() => handleEdit(bloc)}>
                      <Edit className="h-4 w-4" />
                    </Button>
                    <Button size="sm" variant="outline" onClick={() => handleDelete(bloc.id)}>
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="pt-0">
                <div className="grid grid-cols-4 gap-4 text-sm text-muted-foreground">
                  <div>
                    <span className="font-medium">Position:</span><br />
                    X: {bloc.position_x}px, Y: {bloc.position_y}px
                  </div>
                  <div>
                    <span className="font-medium">Dimensions:</span><br />
                    {bloc.largeur}px × {bloc.hauteur}px
                  </div>
                  <div>
                    <span className="font-medium">Police:</span><br />
                    {bloc.styles_css?.fontFamily} {bloc.styles_css?.fontSize}
                  </div>
                  <div>
                    <span className="font-medium">Style:</span><br />
                    {bloc.styles_css?.fontWeight}, {bloc.styles_css?.textAlign}
                  </div>
                </div>
              </CardContent>
            </Card>
          );
        })}

        {blocs.length === 0 && (
          <Card>
            <CardContent className="py-8 text-center">
              <p className="text-muted-foreground">Aucun bloc configuré</p>
              <p className="text-sm text-muted-foreground mt-1">
                Cliquez sur "Ajouter un Bloc" pour commencer
              </p>
            </CardContent>
          </Card>
        )}
      </div>

      {/* Éditeur plein écran simplifié */}
      <FullScreenBlocEditor
        isOpen={isFullScreenEditorOpen}
        onClose={() => setIsFullScreenEditorOpen(false)}
        imageUrl={getCurrentImageUrl() || ''}
        face={formData.face as 'recto' | 'verso'}
        blocs={blocs.filter(bloc => bloc.face === formData.face)}
        modeleId={modeleId}
        onBlocsUpdate={(updatedBlocs) => {
          // Merge updated blocs with existing blocs from other faces
          const otherFaceBlocs = blocs.filter(bloc => bloc.face !== formData.face);
          onBlocsChange([...otherFaceBlocs, ...updatedBlocs]);
        }}
      />
    </div>
  );
};

export default BlocEditor;