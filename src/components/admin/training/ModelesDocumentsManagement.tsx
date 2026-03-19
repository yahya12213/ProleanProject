import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import FormatsManagement from './FormatsManagement';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { useToast } from '@/hooks/use-toast';
import { supabase } from '@/integrations/supabase/client';
import { Plus, Edit, Trash2, Upload, FileImage, Save, Eye, ArrowLeft, FolderOpen, FileText, Copy } from 'lucide-react';
import UnifiedBlocEditor from './UnifiedBlocEditor';

interface ModeleDocument {
  id: string;
  nom_modele: string;
  formation_id: string;
  type_document: string;
  format_page: string;
  orientation: string;
  image_recto_url?: string;
  image_verso_url?: string;
  variables_disponibles: any;
  is_active: boolean;
  created_at: string;
  groupe?: string;
  famille?: string;
}

interface GroupeDocument {
  id: string;
  nom: string;
  description?: string;
  created_at: string;
  is_active: boolean;
}

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

interface Formation {
  id: string;
  titre: string;
}

const ModelesDocumentsManagement = () => {
  const [modeles, setModeles] = useState<ModeleDocument[]>([]);
  const [groupes, setGroupes] = useState<GroupeDocument[]>([]);
  const [formations, setFormations] = useState<Formation[]>([]);
  const [selectedModele, setSelectedModele] = useState<ModeleDocument | null>(null);
  const [blocs, setBlocs] = useState<DocumentBloc[]>([]);
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [loading, setLoading] = useState(true);
  const [currentView, setCurrentView] = useState<'groups' | 'families' | 'documents'>('groups');
  const [selectedGroup, setSelectedGroup] = useState<GroupeDocument | null>(null);
  const [selectedFamily, setSelectedFamily] = useState<string>('');
  const [newGroupDialog, setNewGroupDialog] = useState(false);
  const [editGroupDialog, setEditGroupDialog] = useState(false);
  const [editingGroup, setEditingGroup] = useState<GroupeDocument | null>(null);
  const [newGroupName, setNewGroupName] = useState('');
  const [editGroupName, setEditGroupName] = useState('');
  const [newFamilyDialog, setNewFamilyDialog] = useState(false);
  const [newFamilyName, setNewFamilyName] = useState('');
  const [editFamilyDialog, setEditFamilyDialog] = useState(false);
  const [editingFamily, setEditingFamily] = useState<string>('');
  const [editFamilyName, setEditFamilyName] = useState('');
  const { toast } = useToast();

  const [formData, setFormData] = useState({
    nom_modele: '',
    type_document: 'certificat' as 'certificat' | 'badge' | 'attestation' | 'diplome',
    format_page: 'A4',
    orientation: 'portrait',
    image_recto_url: '',
    image_verso_url: '',
    fichier_url: '',
    famille: 'Général'
  });

  const [formats, setFormats] = useState<any[]>([]);
  const [currentTab, setCurrentTab] = useState<'groupes' | 'formats'>('groupes');

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      
      // Charger les groupes depuis la base
      const { data: groupesData, error: groupesError } = await supabase
        .from('groupes_documents')
        .select('*')
        .eq('is_active', true)
        .order('nom');

      if (groupesError) throw groupesError;
      setGroupes(groupesData || []);
      
      // Charger les modèles
      const { data: modelesData, error: modelesError } = await supabase
        .from('modeles_documents')
        .select('*')
        .order('created_at', { ascending: false });

      if (modelesError) throw modelesError;
      setModeles(modelesData || []);

      // Charger les formats
      const { data: formatsData, error: formatsError } = await supabase
        .from('formats_documents')
        .select('*')
        .eq('is_active', true)
        .order('nom');

      if (formatsError) throw formatsError;
      setFormats(formatsData || []);

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

  const loadBlocs = async (modeleId: string) => {
    try {
      const { data, error } = await supabase
        .from('document_blocs')
        .select('*')
        .eq('modele_id', modeleId)
        .eq('is_active', true)
        .order('ordre_affichage');

      if (error) throw error;
      setBlocs(data || []);
    } catch (error: any) {
      toast({
        title: "Erreur de chargement des blocs",
        description: error.message,
        variant: "destructive"
      });
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    try {
      if (selectedModele) {
        // Mise à jour du modèle
        const { error: updateError } = await supabase
          .from('modeles_documents')
          .update(formData)
          .eq('id', selectedModele.id);

        if (updateError) throw updateError;
        
        // Sauvegarder les blocs (nouveaux et modifiés)
        await handleSaveBlocs(selectedModele.id);
        
        toast({
          title: "Modèle mis à jour",
          description: "Le modèle et ses blocs ont été mis à jour avec succès"
        });
      } else {
        // Création
        const { data, error } = await supabase
          .from('modeles_documents')
          .insert([formData])
          .select()
          .single();

        if (error) throw error;
        
        // Si c'est une nouvelle création et qu'elle réussit, définir comme modèle sélectionné
        if (data) {
          setSelectedModele(data);
        }
        
        toast({
          title: "Modèle créé",
          description: "Le modèle a été créé avec succès"
        });
      }

      // Pour une modification, fermer le dialog
      if (selectedModele) {
        setIsDialogOpen(false);
        setSelectedModele(null);
        resetForm();
      }
      
      loadData();
    } catch (error: any) {
      toast({
        title: "Erreur",
        description: error.message,
        variant: "destructive"
      });
    }
  };

  const handleSaveBlocs = async (modeleId: string) => {
    try {
      // 1. Récupérer tous les blocs existants en base pour ce modèle
      const { data: blocsEnBase, error: fetchError } = await supabase
        .from('document_blocs')
        .select('id')
        .eq('modele_id', modeleId);

      if (fetchError) throw fetchError;

      // 2. Identifier les blocs à supprimer (présents en base mais absents de l'état local)
      const idsExistantsEnBase = blocsEnBase?.map(b => b.id) || [];
      const idsEnEtatLocal = blocs.filter(bloc => !bloc.id.startsWith('temp_')).map(b => b.id);
      const idsASupprimer = idsExistantsEnBase.filter(id => !idsEnEtatLocal.includes(id));

      // 3. Supprimer les blocs qui ne sont plus dans l'état local
      if (idsASupprimer.length > 0) {
        const { error: deleteError } = await supabase
          .from('document_blocs')
          .delete()
          .in('id', idsASupprimer);

        if (deleteError) throw deleteError;
        console.log(`✅ ${idsASupprimer.length} bloc(s) supprimé(s) de la base`);
      }

      // 4. Séparer les blocs temporaires des blocs existants
      const newBlocs = blocs.filter(bloc => bloc.id.startsWith('temp_'));
      const existingBlocs = blocs.filter(bloc => !bloc.id.startsWith('temp_'));

      // 5. Insérer les nouveaux blocs
      if (newBlocs.length > 0) {
        const newBlocsData = newBlocs.map(bloc => ({
          nom_bloc: bloc.nom_bloc,
          type_contenu: bloc.type_contenu,
          face: bloc.face,
          position_x: bloc.position_x,
          position_y: bloc.position_y,
          largeur: bloc.largeur,
          hauteur: bloc.hauteur,
          styles_css: bloc.styles_css,
          ordre_affichage: bloc.ordre_affichage,
          modele_id: modeleId
        }));

        const { data: insertedBlocs, error: insertError } = await supabase
          .from('document_blocs')
          .insert(newBlocsData)
          .select();

        if (insertError) throw insertError;

        // Remplacer les IDs temporaires par les vrais IDs
        if (insertedBlocs) {
          const updatedBlocs = [...existingBlocs, ...insertedBlocs];
          setBlocs(updatedBlocs);
        }
      }

      // 6. Mettre à jour les blocs existants modifiés
      for (const bloc of existingBlocs) {
        const { error: updateError } = await supabase
          .from('document_blocs')
          .update({
            nom_bloc: bloc.nom_bloc,
            type_contenu: bloc.type_contenu,
            face: bloc.face,
            position_x: bloc.position_x,
            position_y: bloc.position_y,
            largeur: bloc.largeur,
            hauteur: bloc.hauteur,
            styles_css: bloc.styles_css,
            ordre_affichage: bloc.ordre_affichage
          })
          .eq('id', bloc.id);

        if (updateError) throw updateError;
      }

      toast({
        title: "Blocs sauvegardés",
        description: "Tous les blocs ont été sauvegardés avec succès"
      });

    } catch (error: any) {
      console.error('Erreur lors de la sauvegarde des blocs:', error);
      toast({
        title: "Erreur de sauvegarde",
        description: error.message,
        variant: "destructive"
      });
      throw error;
    }
  };

  const handleEdit = (modele: ModeleDocument) => {
    setSelectedModele(modele);
    setFormData({
      nom_modele: modele.nom_modele,
      type_document: modele.type_document as 'certificat' | 'badge' | 'attestation' | 'diplome',
      format_page: modele.format_page,
      orientation: modele.orientation,
      image_recto_url: modele.image_recto_url || '',
      image_verso_url: modele.image_verso_url || '',
      fichier_url: '',
      famille: modele.famille || modele.groupe || 'Général'
    });
    loadBlocs(modele.id);
    setIsDialogOpen(true);
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Êtes-vous sûr de vouloir supprimer ce modèle ?')) return;

    try {
      const { error } = await supabase
        .from('modeles_documents')
        .delete()
        .eq('id', id);

      if (error) throw error;
      
      toast({
        title: "Modèle supprimé",
        description: "Le modèle a été supprimé avec succès"
      });
      loadData();
    } catch (error: any) {
      toast({
        title: "Erreur de suppression",
        description: error.message,
        variant: "destructive"
      });
    }
  };

  const handleDuplicate = async (modele: ModeleDocument) => {
    try {
      // Créer une copie du modèle avec un nouveau nom
      const duplicatedName = `${modele.nom_modele} (Copie)`;
      
      const { data: newModele, error: modeleError } = await supabase
        .from('modeles_documents')
        .insert({
          nom_modele: duplicatedName,
          type_document: modele.type_document as 'certificat' | 'badge' | 'attestation' | 'diplome',
          format_page: modele.format_page,
          orientation: modele.orientation,
          image_recto_url: modele.image_recto_url || null,
          image_verso_url: modele.image_verso_url || null,
          variables_disponibles: modele.variables_disponibles,
          famille: modele.famille || null,
          groupe: modele.groupe || null,
          is_active: true
        })
        .select()
        .single();

      if (modeleError) throw modeleError;

      // Dupliquer tous les blocs associés
      const { data: originalBlocs, error: blocsError } = await supabase
        .from('document_blocs')
        .select('*')
        .eq('modele_id', modele.id)
        .eq('is_active', true);

      if (blocsError) throw blocsError;

      if (originalBlocs && originalBlocs.length > 0) {
        const newBlocs = originalBlocs.map(bloc => ({
          nom_bloc: bloc.nom_bloc,
          type_contenu: bloc.type_contenu,
          face: bloc.face,
          position_x: bloc.position_x,
          position_y: bloc.position_y,
          largeur: bloc.largeur,
          hauteur: bloc.hauteur,
          styles_css: bloc.styles_css,
          ordre_affichage: bloc.ordre_affichage,
          modele_id: newModele.id
        }));

        const { error: insertBlocsError } = await supabase
          .from('document_blocs')
          .insert(newBlocs);

        if (insertBlocsError) throw insertBlocsError;
      }

      toast({
        title: "Modèle dupliqué",
        description: `Le modèle "${duplicatedName}" a été créé avec succès`
      });
      
      loadData(); // Recharger les données
    } catch (error: any) {
      toast({
        title: "Erreur de duplication",
        description: error.message,
        variant: "destructive"
      });
    }
  };

  const resetForm = () => {
    setFormData({
      nom_modele: '',
      type_document: 'certificat' as 'certificat' | 'badge' | 'attestation' | 'diplome',
      format_page: 'A4',
      orientation: 'portrait',
      image_recto_url: '',
      image_verso_url: '',
      fichier_url: '',
      famille: selectedFamily || 'Général'
    });
    setBlocs([]);
  };

  const handleFileUpload = async (file: File, type: 'recto' | 'verso') => {
    try {
      const fileExt = file.name.split('.').pop();
      const fileName = `${Date.now()}_${type}.${fileExt}`;
      const filePath = `templates/${fileName}`;

      const { error: uploadError } = await supabase.storage
        .from('document-templates')
        .upload(filePath, file);

      if (uploadError) throw uploadError;

      const { data } = supabase.storage
        .from('document-templates')
        .getPublicUrl(filePath);

      setFormData(prev => ({
        ...prev,
        [`image_${type}_url`]: data.publicUrl
      }));

      toast({
        title: "Image uploadée",
        description: `L'image ${type} a été uploadée avec succès`
      });
    } catch (error: any) {
      toast({
        title: "Erreur d'upload",
        description: error.message,
        variant: "destructive"
      });
    }
  };

  // Fonctions pour la gestion des groupes et familles
  const getFamiliesByGroup = (group: string) => {
    const familiesSet = new Set<string>();
    modeles.forEach(modele => {
      if ((modele.groupe || 'Général') === group) {
        familiesSet.add(modele.famille || 'Général');
      }
    });
    return Array.from(familiesSet);
  };

  const getModelesByFamily = (family: string) => {
    return modeles.filter(modele => (modele.famille || modele.groupe || 'Général') === family);
  };

  const handleCreateGroup = async () => {
    if (!newGroupName.trim()) return;
    
    try {
      const { error } = await supabase
        .from('groupes_documents')
        .insert([{ nom: newGroupName }]);

      if (error) throw error;
      
      await loadData(); // Recharger les données
      setNewGroupDialog(false);
      setNewGroupName('');
      
      toast({
        title: "Groupe créé",
        description: `Le groupe "${newGroupName}" a été créé`
      });
    } catch (error: any) {
      toast({
        title: "Erreur de création",
        description: error.message,
        variant: "destructive"
      });
    }
  };

  const handleEditGroup = (groupe: GroupeDocument) => {
    setEditingGroup(groupe);
    setEditGroupName(groupe.nom);
    setEditGroupDialog(true);
  };

  const handleUpdateGroup = async () => {
    if (!editingGroup || !editGroupName.trim()) return;
    
    try {
      // Mettre à jour le nom du groupe dans la table des groupes
      const { error: groupError } = await supabase
        .from('groupes_documents')
        .update({ nom: editGroupName })
        .eq('id', editingGroup.id);

      if (groupError) throw groupError;

      // Mettre à jour tous les documents de ce groupe
      const { error: modeleError } = await supabase
        .from('modeles_documents')
        .update({ famille: editGroupName })
        .eq('famille', editingGroup.nom);

      if (modeleError) throw modeleError;
      
      await loadData(); // Recharger les données
      setEditGroupDialog(false);
      setEditingGroup(null);
      setEditGroupName('');
      
      toast({
        title: "Groupe mis à jour",
        description: `Le groupe a été renommé en "${editGroupName}"`
      });
    } catch (error: any) {
      toast({
        title: "Erreur de mise à jour",
        description: error.message,
        variant: "destructive"
      });
    }
  };

  const handleCreateFamily = async () => {
    if (!newFamilyName.trim() || !selectedGroup) return;
    
    try {
      // Créer un modèle fictif pour cette famille dans ce groupe
      const { error } = await supabase
        .from('modeles_documents')
        .insert([{
          nom_modele: `_family_placeholder_${newFamilyName}`,
          type_document: 'certificat',
          format_page: 'A4',
          orientation: 'portrait',
          groupe: selectedGroup.nom,
          famille: newFamilyName,
          is_active: false // Marquer comme inactif pour qu'il n'apparaisse pas dans les listes
        }]);

      if (error) throw error;
      
      await loadData();
      setNewFamilyDialog(false);
      setNewFamilyName('');
      
      toast({
        title: "Famille créée",
        description: `La famille "${newFamilyName}" a été créée dans le groupe "${selectedGroup.nom}"`
      });
    } catch (error: any) {
      toast({
        title: "Erreur de création",
        description: error.message,
        variant: "destructive"
      });
    }
  };

  const handleEditFamily = (famille: string) => {
    setEditingFamily(famille);
    setEditFamilyName(famille);
    setEditFamilyDialog(true);
  };

  const handleUpdateFamily = async () => {
    if (!editingFamily || !editFamilyName.trim() || !selectedGroup) return;
    
    try {
      // Mettre à jour tous les documents de cette famille
      const { error } = await supabase
        .from('modeles_documents')
        .update({ famille: editFamilyName })
        .eq('groupe', selectedGroup.nom)
        .eq('famille', editingFamily);

      if (error) throw error;
      
      await loadData();
      setEditFamilyDialog(false);
      setEditingFamily('');
      setEditFamilyName('');
      
      toast({
        title: "Famille mise à jour",
        description: `La famille a été renommée en "${editFamilyName}"`
      });
    } catch (error: any) {
      toast({
        title: "Erreur de mise à jour",
        description: error.message,
        variant: "destructive"
      });
    }
  };

  const handleDeleteFamily = async (famille: string) => {
    if (!selectedGroup) return;
    
    const familyModeles = getModelesByFamily(famille);
    
    if (familyModeles.length > 0) {
      if (!confirm(`Cette famille contient ${familyModeles.length} document(s). Les documents seront déplacés vers la famille "Général". Continuer ?`)) {
        return;
      }
      
      try {
        // Déplacer les documents vers "Général"
        const { error } = await supabase
          .from('modeles_documents')
          .update({ famille: 'Général' })
          .eq('groupe', selectedGroup.nom)
          .eq('famille', famille);

        if (error) throw error;
      } catch (error: any) {
        toast({
          title: "Erreur",
          description: error.message,
          variant: "destructive"
        });
        return;
      }
    } else {
      if (!confirm('Êtes-vous sûr de vouloir supprimer cette famille ?')) return;
    }

    try {
      // La famille sera automatiquement supprimée quand il n'y aura plus de documents
      await loadData();
      
      toast({
        title: "Famille supprimée",
        description: "La famille a été supprimée avec succès"
      });
    } catch (error: any) {
      toast({
        title: "Erreur de suppression",
        description: error.message,
        variant: "destructive"
      });
    }
  };

  const handleDeleteGroup = async (groupe: GroupeDocument) => {
    const familiesInGroup = getFamiliesByGroup(groupe.nom);
    let totalModeles = 0;
    familiesInGroup.forEach(family => {
      totalModeles += getModelesByFamily(family).length;
    });
    
    if (totalModeles > 0) {
      if (!confirm(`Ce groupe contient ${totalModeles} document(s) dans ${familiesInGroup.length} famille(s). Les documents seront déplacés vers le groupe "Général". Continuer ?`)) {
        return;
      }
      
      // Déplacer les documents vers "Général"
      try {
        const { error } = await supabase
          .from('modeles_documents')
          .update({ groupe: 'Général', famille: 'Général' })
          .eq('groupe', groupe.nom);

        if (error) throw error;
      } catch (error: any) {
        toast({
          title: "Erreur",
          description: error.message,
          variant: "destructive"
        });
        return;
      }
    } else {
      if (!confirm('Êtes-vous sûr de vouloir supprimer ce groupe ?')) return;
    }

    try {
      const { error } = await supabase
        .from('groupes_documents')
        .delete()
        .eq('id', groupe.id);

      if (error) throw error;
      
      await loadData(); // Recharger les données
      
      toast({
        title: "Groupe supprimé",
        description: "Le groupe a été supprimé avec succès"
      });
    } catch (error: any) {
      toast({
        title: "Erreur de suppression",
        description: error.message,
        variant: "destructive"
      });
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('fr-FR', {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  if (loading) {
    return <div className="flex justify-center p-8">Chargement...</div>;
  }

  return (
    <div className="space-y-6">
      <h2 className="text-2xl font-bold">Gestion des Modèles de Documents</h2>
      
      <Tabs value={currentTab} onValueChange={(value) => setCurrentTab(value as 'groupes' | 'formats')}>
        <TabsList>
          <TabsTrigger value="groupes">Familles & Documents</TabsTrigger>
          <TabsTrigger value="formats">Formats</TabsTrigger>
        </TabsList>
        
        <TabsContent value="formats">
          <FormatsManagement />
        </TabsContent>
        
        <TabsContent value="groupes">
          <div className="space-y-6">
            {/* Navigation Header */}
            <div className="flex justify-between items-center">
              <div className="flex items-center space-x-4">
                 {(currentView === 'families' || currentView === 'documents') && (
                  <Button variant="outline" onClick={() => {
                    if (currentView === 'documents') {
                      setCurrentView('families');
                      setSelectedFamily('');
                    } else {
                      setCurrentView('groups');
                      setSelectedGroup(null);
                    }
                  }}>
                    <ArrowLeft className="h-4 w-4 mr-2" />
                    {currentView === 'documents' ? 'Retour aux familles' : 'Retour aux groupes'}
                  </Button>
                )}
                 <h3 className="text-xl font-semibold">
                  {currentView === 'groups' 
                    ? 'Groupes de Documents' 
                    : currentView === 'families'
                    ? `Familles - ${selectedGroup?.nom}`
                    : `Documents - ${selectedFamily}`
                  }
                </h3>
              </div>
              
               <div className="flex space-x-2">
                {currentView === 'groups' ? (
                  <Dialog open={newGroupDialog} onOpenChange={setNewGroupDialog}>
                    <DialogTrigger asChild>
                      <Button>
                        <Plus className="h-4 w-4 mr-2" />
                        Nouveau Groupe
                      </Button>
                    </DialogTrigger>
                    <DialogContent>
                      <DialogHeader>
                        <DialogTitle>Créer un Nouveau Groupe</DialogTitle>
                      </DialogHeader>
                      <div className="space-y-4">
                        <div>
                          <Label htmlFor="group-name">Nom du groupe</Label>
                          <Input
                            id="group-name"
                            value={newGroupName}
                            onChange={(e) => setNewGroupName(e.target.value)}
                            placeholder="Ex: CACES, RH, Formations..."
                          />
                        </div>
                        <div className="flex justify-end space-x-2">
                          <Button variant="outline" onClick={() => setNewGroupDialog(false)}>
                            Annuler
                          </Button>
                          <Button onClick={handleCreateGroup}>
                            Créer
                          </Button>
                        </div>
                      </div>
                    </DialogContent>
                  </Dialog>
                ) : currentView === 'families' ? (
                  <>
                    <Dialog open={newFamilyDialog} onOpenChange={setNewFamilyDialog}>
                      <DialogTrigger asChild>
                        <Button>
                          <Plus className="h-4 w-4 mr-2" />
                          Nouvelle Famille
                        </Button>
                      </DialogTrigger>
                      <DialogContent>
                        <DialogHeader>
                          <DialogTitle>Créer une Nouvelle Famille</DialogTitle>
                        </DialogHeader>
                        <div className="space-y-4">
                          <div>
                            <Label htmlFor="family-name">Nom de la famille</Label>
                            <Input
                              id="family-name"
                              value={newFamilyName}
                              onChange={(e) => setNewFamilyName(e.target.value)}
                              placeholder="Ex: Badges, Certificats, Attestations..."
                            />
                          </div>
                          <div className="flex justify-end space-x-2">
                            <Button variant="outline" onClick={() => setNewFamilyDialog(false)}>
                              Annuler
                            </Button>
                            <Button onClick={handleCreateFamily}>
                              Créer
                            </Button>
                          </div>
                        </div>
                      </DialogContent>
                    </Dialog>

                    {/* Dialog pour modifier une famille */}
                    <Dialog open={editFamilyDialog} onOpenChange={setEditFamilyDialog}>
                      <DialogContent>
                        <DialogHeader>
                          <DialogTitle>Modifier la Famille</DialogTitle>
                        </DialogHeader>
                        <div className="space-y-4">
                          <div>
                            <Label htmlFor="edit-family-name">Nom de la famille</Label>
                            <Input
                              id="edit-family-name"
                              value={editFamilyName}
                              onChange={(e) => setEditFamilyName(e.target.value)}
                            />
                          </div>
                          <div className="flex justify-end space-x-2">
                            <Button variant="outline" onClick={() => setEditFamilyDialog(false)}>
                              Annuler
                            </Button>
                            <Button onClick={handleUpdateFamily}>
                              Mettre à jour
                            </Button>
                          </div>
                        </div>
                      </DialogContent>
                    </Dialog>
                  </>
                ) : (
                  <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
                    <DialogTrigger asChild>
                      <Button onClick={() => { resetForm(); setSelectedModele(null); }}>
                        <Plus className="h-4 w-4 mr-2" />
                        Nouveau Modèle
                      </Button>
                    </DialogTrigger>
                    <DialogContent className="max-w-[98vw] max-h-[98vh] w-full flex flex-col">
                      <DialogHeader className="flex-shrink-0">
                        <DialogTitle>
                          {selectedModele ? 'Modifier le Modèle' : 'Créer un Nouveau Modèle'}
                        </DialogTitle>
                      </DialogHeader>
                      
                      <div className="flex-1 overflow-y-auto p-1" style={{ maxHeight: 'calc(98vh - 120px)' }}>
                        <form onSubmit={handleSubmit} className="space-y-8">
                          {/* Section 1: Paramètres généraux */}
                          <div className="bg-gray-50 p-6 rounded-lg space-y-4">
                            <h3 className="text-lg font-semibold mb-4">Paramètres Généraux</h3>
                            <div className="grid grid-cols-5 gap-4">
                              <div>
                                <label className="text-sm font-medium">Nom du modèle</label>
                                <Input
                                  value={formData.nom_modele}
                                  onChange={(e) => setFormData(prev => ({ ...prev, nom_modele: e.target.value }))}
                                  required
                                />
                              </div>
                              <div>
                                <label className="text-sm font-medium">Famille</label>
                                <Input
                                  value={formData.famille}
                                  onChange={(e) => setFormData(prev => ({ ...prev, famille: e.target.value }))}
                                  placeholder="Ex: Badge, Certificat..."
                                />
                              </div>
                              <div>
                                <label className="text-sm font-medium">Type de document</label>
                                <Select value={formData.type_document} onValueChange={(value) => setFormData(prev => ({ ...prev, type_document: value as 'certificat' | 'badge' | 'attestation' | 'diplome' }))}>
                                  <SelectTrigger>
                                    <SelectValue />
                                  </SelectTrigger>
                                  <SelectContent>
                                    <SelectItem value="certificat">Certificat</SelectItem>
                                    <SelectItem value="badge">Badge</SelectItem>
                                    <SelectItem value="diplome">Diplôme</SelectItem>
                                    <SelectItem value="attestation">Attestation</SelectItem>
                                  </SelectContent>
                                </Select>
                              </div>
                              <div>
                                <label className="text-sm font-medium">Format de page</label>
                                <Select value={formData.format_page} onValueChange={(value) => setFormData(prev => ({ ...prev, format_page: value }))}>
                                  <SelectTrigger>
                                    <SelectValue />
                                  </SelectTrigger>
                                  <SelectContent>
                                    {formats.map((format) => (
                                      <SelectItem key={format.id} value={format.nom}>
                                        {format.nom} ({format.largeur_mm}×{format.hauteur_mm}mm)
                                      </SelectItem>
                                    ))}
                                  </SelectContent>
                                </Select>
                              </div>
                              <div>
                                <label className="text-sm font-medium">Orientation</label>
                                <Select value={formData.orientation} onValueChange={(value) => setFormData(prev => ({ ...prev, orientation: value }))}>
                                  <SelectTrigger>
                                    <SelectValue />
                                  </SelectTrigger>
                                  <SelectContent>
                                    <SelectItem value="portrait">📄 Portrait</SelectItem>
                                    <SelectItem value="paysage">📑 Paysage</SelectItem>
                                  </SelectContent>
                                </Select>
                              </div>
                            </div>
                          </div>

                          {/* Section 2: Upload d'images */}
                          <div className="bg-blue-50 p-6 rounded-lg space-y-4">
                            <h3 className="text-lg font-semibold mb-4">Images du Document</h3>
                            <div className="grid grid-cols-2 gap-8">
                              <div>
                                <label className="text-sm font-medium mb-2 block">Image Recto</label>
                                <div className="space-y-3">
                                  <div className="border-2 border-dashed border-blue-300 rounded-lg p-6 text-center hover:border-blue-400 transition-colors">
                                    <input
                                      type="file"
                                      accept="image/*"
                                      onChange={(e) => {
                                        const file = e.target.files?.[0];
                                        if (file) handleFileUpload(file, 'recto');
                                      }}
                                      className="hidden"
                                      id="recto-upload"
                                    />
                                    <label htmlFor="recto-upload" className="cursor-pointer">
                                      <FileImage className="h-12 w-12 mx-auto mb-3 text-blue-400" />
                                      <p className="text-sm text-blue-600 font-medium">Cliquer pour uploader le recto</p>
                                      <p className="text-xs text-gray-500 mt-1">PNG, JPG jusqu'à 10MB</p>
                                    </label>
                                  </div>
                                  {formData.image_recto_url && (
                                    <div className="relative">
                                      <img src={formData.image_recto_url} alt="Recto" className="w-full h-48 object-cover rounded border-2 border-blue-200" />
                                      <div className="absolute top-2 right-2 bg-green-500 text-white px-2 py-1 rounded text-xs">
                                        Chargé
                                      </div>
                                    </div>
                                  )}
                                </div>
                              </div>
                              <div>
                                <label className="text-sm font-medium mb-2 block">Image Verso</label>
                                <div className="space-y-3">
                                  <div className="border-2 border-dashed border-blue-300 rounded-lg p-6 text-center hover:border-blue-400 transition-colors">
                                    <input
                                      type="file"
                                      accept="image/*"
                                      onChange={(e) => {
                                        const file = e.target.files?.[0];
                                        if (file) handleFileUpload(file, 'verso');
                                      }}
                                      className="hidden"
                                      id="verso-upload"
                                    />
                                    <label htmlFor="verso-upload" className="cursor-pointer">
                                      <FileImage className="h-12 w-12 mx-auto mb-3 text-blue-400" />
                                      <p className="text-sm text-blue-600 font-medium">Cliquer pour uploader le verso</p>
                                      <p className="text-xs text-gray-500 mt-1">PNG, JPG jusqu'à 10MB</p>
                                    </label>
                                  </div>
                                  {formData.image_verso_url && (
                                    <div className="relative">
                                      <img src={formData.image_verso_url} alt="Verso" className="w-full h-48 object-cover rounded border-2 border-blue-200" />
                                      <div className="absolute top-2 right-2 bg-green-500 text-white px-2 py-1 rounded text-xs">
                                        Chargé
                                      </div>
                                    </div>
                                  )}
                                </div>
                              </div>
                            </div>
                          </div>

                          {/* Section 3: Édition des blocs intégrée */}
                          <UnifiedBlocEditor 
                            modeleId={selectedModele?.id || ''}
                            blocs={blocs}
                            onBlocsChange={setBlocs}
                            imageRectoUrl={formData.image_recto_url}
                            imageVersoUrl={formData.image_verso_url}
                            formatPage={formData.format_page}
                            isNewModel={!selectedModele}
                          />

                          <div className="flex justify-end space-x-3 pt-6 border-t">
                            <Button type="button" variant="outline" onClick={() => setIsDialogOpen(false)}>
                              Annuler
                            </Button>
                            <Button type="submit" className="bg-blue-600 hover:bg-blue-700">
                              <Save className="h-4 w-4 mr-2" />
                              {selectedModele ? 'Mettre à jour' : 'Créer le Modèle'}
                            </Button>
                          </div>
                        </form>
                      </div>
                    </DialogContent>
                  </Dialog>
                 )}
              </div>
            </div>

            {/* Vue Groupes */}
            {currentView === 'groups' && (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
                {groupes.map((groupe) => {
                  const familiesInGroup = getFamiliesByGroup(groupe.nom);
                  const groupModeles = familiesInGroup.flatMap(family => getModelesByFamily(family));
                  return (
                    <Card 
                      key={groupe.id} 
                      className="cursor-pointer hover:shadow-lg transition-shadow relative group"
                    >
                      <div className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition-opacity z-10">
                        <div className="flex space-x-1">
                          <Button
                            size="sm"
                            variant="outline"
                            className="h-8 w-8 p-0 bg-white shadow-md"
                            onClick={(e) => {
                              e.stopPropagation();
                              handleEditGroup(groupe);
                            }}
                          >
                            <Edit className="h-3 w-3" />
                          </Button>
                          <Button
                            size="sm"
                            variant="outline"
                            className="h-8 w-8 p-0 bg-white shadow-md"
                            onClick={(e) => {
                              e.stopPropagation();
                              handleDeleteGroup(groupe);
                            }}
                          >
                            <Trash2 className="h-3 w-3" />
                          </Button>
                        </div>
                      </div>
                      <CardHeader 
                        className="text-center"
                        onClick={() => {
                          setSelectedGroup(groupe);
                          setCurrentView('families');
                        }}
                      >
                        <FolderOpen className="h-12 w-12 mx-auto mb-4 text-blue-500" />
                        <CardTitle className="text-lg">{groupe.nom}</CardTitle>
                        <Badge variant="secondary">
                          {familiesInGroup.length} famille{familiesInGroup.length > 1 ? 's' : ''} • {groupModeles.length} document{groupModeles.length > 1 ? 's' : ''}
                        </Badge>
                      </CardHeader>
                    </Card>
                  );
                })}
                
                {groupes.length === 0 && (
                  <Card className="col-span-full">
                    <CardContent className="py-8 text-center">
                      <p className="text-muted-foreground">Aucun groupe de documents trouvé</p>
                    </CardContent>
                  </Card>
                )}
              </div>
            )}

            {/* Vue Familles */}
            {currentView === 'families' && selectedGroup && (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
                {getFamiliesByGroup(selectedGroup.nom).map((famille) => {
                  const familyModeles = getModelesByFamily(famille);
                  return (
                    <Card 
                      key={famille} 
                      className="cursor-pointer hover:shadow-lg transition-shadow relative group"
                    >
                      <div className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition-opacity z-10">
                        <div className="flex space-x-1">
                          <Button
                            size="sm"
                            variant="outline"
                            className="h-8 w-8 p-0 bg-white shadow-md"
                            onClick={(e) => {
                              e.stopPropagation();
                              handleEditFamily(famille);
                            }}
                          >
                            <Edit className="h-3 w-3" />
                          </Button>
                          <Button
                            size="sm"
                            variant="outline"
                            className="h-8 w-8 p-0 bg-white shadow-md"
                            onClick={(e) => {
                              e.stopPropagation();
                              handleDeleteFamily(famille);
                            }}
                          >
                            <Trash2 className="h-3 w-3" />
                          </Button>
                        </div>
                      </div>
                      <CardHeader 
                        className="text-center"
                        onClick={() => {
                          setSelectedFamily(famille);
                          setCurrentView('documents');
                        }}
                      >
                        <div className="flex items-center justify-center mb-2">
                          {famille.toLowerCase().includes('badge') ? '🏷️' : 
                           famille.toLowerCase().includes('certificat') ? '📜' :
                           famille.toLowerCase().includes('attestation') ? '📋' :
                           famille.toLowerCase().includes('diplome') ? '🎓' : '📂'}
                        </div>
                        <CardTitle className="text-lg">{famille}</CardTitle>
                        <Badge variant="secondary">
                          {familyModeles.length} document{familyModeles.length > 1 ? 's' : ''}
                        </Badge>
                      </CardHeader>
                    </Card>
                  );
                })}
                
                {getFamiliesByGroup(selectedGroup.nom).length === 0 && (
                  <Card className="col-span-full">
                    <CardContent className="py-8 text-center">
                      <p className="text-muted-foreground">Aucune famille dans ce groupe</p>
                    </CardContent>
                  </Card>
                )}
              </div>
            )}

            {/* Vue Documents (Liste) */}
            {currentView === 'documents' && (
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <FileText className="h-5 w-5" />
                    Documents - {selectedFamily}
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Titre</TableHead>
                        <TableHead>Type</TableHead>
                        <TableHead>Date de création</TableHead>
                        <TableHead>Actions</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {getModelesByFamily(selectedFamily).map((modele) => (
                        <TableRow key={modele.id}>
                          <TableCell>
                            <div className="flex items-center gap-2">
                              <FileText className="h-4 w-4 text-blue-500" />
                              <span className="font-medium">{modele.nom_modele}</span>
                              {modele.is_active && (
                                <Badge variant="default" className="text-xs">Actif</Badge>
                              )}
                            </div>
                          </TableCell>
                          <TableCell>
                            <Badge variant="outline">{modele.type_document}</Badge>
                          </TableCell>
                          <TableCell>
                            <span className="text-sm text-muted-foreground">
                              {formatDate(modele.created_at)}
                            </span>
                          </TableCell>
                          <TableCell>
                            <div className="flex space-x-2">
                              <Button size="sm" variant="outline" onClick={() => handleEdit(modele)}>
                                <Edit className="h-4 w-4" />
                              </Button>
                              <Button size="sm" variant="outline" onClick={() => handleDuplicate(modele)}>
                                <Copy className="h-4 w-4" />
                              </Button>
                              <Button size="sm" variant="outline" onClick={() => handleDelete(modele.id)}>
                                <Trash2 className="h-4 w-4" />
                              </Button>
                            </div>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                   
                  {getModelesByFamily(selectedFamily).length === 0 && (
                    <div className="py-8 text-center">
                      <p className="text-muted-foreground">Aucun document dans cette famille</p>
                    </div>
                  )}
                </CardContent>
              </Card>
            )}

          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default ModelesDocumentsManagement;