import { useState, useEffect, useCallback } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger } from "@/components/ui/alert-dialog";
import { useToast } from "@/hooks/use-toast";
import { MapPin, Building2, Plus, Edit, Trash2, Palette, Upload, Image, Settings } from "lucide-react";
import VilleManagement from "./VilleManagement";
import './SegmentManagement.css';

interface Segment {
  id: string;
  nom: string;
  couleur: string;
  logo_url?: string;
  created_at: string;
  updated_at?: string;
  villes?: Ville[];
}

interface Ville {
  id: string;
  nom_ville: string;
  code_ville: string;
  segment_id: string;
  created_at: string;
  updated_at?: string;
}

const SegmentManagement = () => {
  const [segments, setSegments] = useState<Segment[]>([]);
  const [loading, setLoading] = useState(true);
  const [isSegmentDialogOpen, setIsSegmentDialogOpen] = useState(false);
  const [editingSegment, setEditingSegment] = useState<Segment | null>(null);
  const [villeManagementOpen, setVilleManagementOpen] = useState(false);
  const [selectedSegmentForVilles, setSelectedSegmentForVilles] = useState<Segment | null>(null);
  const { toast } = useToast();

  // Form states
  const [segmentFormData, setSegmentFormData] = useState({
    nom: "",
    couleur: "#3B82F6",
    logo_url: ""
  });
  const [uploadingLogo, setUploadingLogo] = useState(false);

  const predefinedColors = [
    "#3B82F6", // Blue
    "#10B981", // Emerald
    "#F59E0B", // Amber
    "#EF4444", // Red
    "#8B5CF6", // Violet
    "#06B6D4", // Cyan
    "#84CC16", // Lime
    "#F97316", // Orange
    "#EC4899", // Pink
    "#6366F1", // Indigo
  ];

  const loadData = useCallback(async () => {
    try {
      setLoading(true);

      const response = await fetch('/api/segments', {
        method: 'GET',
      });

      if (!response.ok) {
        throw new Error('Failed to fetch segments');
      }

      const segments = await response.json();
      setSegments(segments || []);
    } catch (error) {
      console.error('Erreur lors du chargement des segments:', error);
      toast({
        title: "Erreur",
        description: "Impossible de charger les segments",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleSegmentSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    try {
      const method = editingSegment ? 'PUT' : 'POST';
      const url = editingSegment ? `/api/segments/${editingSegment.id}` : '/api/segments';

      const response = await fetch(url, {
        method,
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(segmentFormData),
      });

      if (!response.ok) {
        throw new Error('Failed to submit segment');
      }

      toast({
        title: "Succès",
        description: editingSegment ? "Segment modifié avec succès" : "Segment créé avec succès",
      });

      setSegmentFormData({ nom: '', couleur: '', logo_url: '' });
      setEditingSegment(null);
      loadData();
    } catch (error) {
      console.error('Erreur lors de la soumission du segment:', error);
      toast({
        title: "Erreur",
        description: "Impossible de soumettre le segment",
        variant: "destructive"
      });
    }
  };

  const handleDeleteSegment = async (segmentId: string) => {
    try {
      const checkResponse = await fetch(`/api/villes?segment_id=${segmentId}`, {
        method: 'GET',
      });

      if (!checkResponse.ok) {
        throw new Error('Failed to check associated villes');
      }

      const associatedVilles = await checkResponse.json();

      if (associatedVilles && associatedVilles.length > 0) {
        toast({
          title: "Erreur",
          description: `Impossible de supprimer ce segment. ${associatedVilles.length} ville(s) y sont associées.`,
          variant: "destructive"
        });
        return;
      }

      const deleteResponse = await fetch(`/api/segments/${segmentId}`, {
        method: 'DELETE',
      });

      if (!deleteResponse.ok) {
        throw new Error('Failed to delete segment');
      }

      toast({
        title: "Succès",
        description: "Segment supprimé avec succès",
      });

      loadData();
    } catch (error) {
      console.error('Erreur lors de la suppression du segment:', error);
      toast({
        title: "Erreur",
        description: "Impossible de supprimer le segment",
        variant: "destructive"
      });
    }
  };

  const resetSegmentForm = () => {
    setSegmentFormData({
      nom: "",
      couleur: "#3B82F6",
      logo_url: ""
    });
    setEditingSegment(null);
  };

  const openEditSegmentDialog = (segment: Segment) => {
    setEditingSegment(segment);
    setSegmentFormData({
      nom: segment.nom,
      couleur: segment.couleur,
      logo_url: segment.logo_url || ""
    });
    setIsSegmentDialogOpen(true);
  };

  // Correction de l'appel à la méthode .from dans handleLogoUpload
  const handleLogoUpload = async (file: File) => {
    try {
      setUploadingLogo(true);

      // Generate unique filename
      const fileExt = file.name.split('.').pop();
      const fileName = `${Math.random().toString(36).substring(2)}-${Date.now()}.${fileExt}`;

      // Replace Supabase storage upload with custom API
      const formData = new FormData();
      formData.append('file', file);
      formData.append('fileName', fileName);

      const uploadResponse = await fetch('/api/segment-logos/upload', {
        method: 'POST',
        body: formData,
      });
      if (!uploadResponse.ok) throw new Error('Erreur lors de l\'upload du logo');
      const uploadData = await uploadResponse.json();

      // Replace Supabase getPublicUrl with custom API
      const publicUrlResponse = await fetch(`/api/segment-logos/public-url?fileName=${encodeURIComponent(fileName)}`);
      if (!publicUrlResponse.ok) throw new Error('Erreur lors de la récupération de l\'URL publique');
      const publicUrlData = await publicUrlResponse.json();

      setSegmentFormData({
        ...segmentFormData,
        logo_url: publicUrlData.publicUrl
      });

      toast({
        title: "Succès",
        description: "Logo uploadé avec succès"
      });
    } catch (error) {
      console.error('Error uploading logo:', error);
      toast({
        title: "Erreur",
        description: "Impossible d'uploader le logo",
        variant: "destructive"
      });
    } finally {
      setUploadingLogo(false);
    }
  };

  const openVilleManagement = (segment: Segment) => {
    setSelectedSegmentForVilles(segment);
    setVilleManagementOpen(true);
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="text-center">
          <MapPin className="h-12 w-12 mx-auto mb-4 text-muted-foreground animate-pulse" />
          <p className="text-muted-foreground">Chargement des segments...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h3 className="text-lg font-semibold">Gestion des Segments (Marques)</h3>
        <p className="text-sm text-muted-foreground">
          Configurez la structure organisationnelle de l'entreprise
        </p>
      </div>

      {/* Segments Management */}
      <div className="space-y-4">
        <div className="flex justify-between items-center">
          <h4 className="text-base font-medium">Marques / Segments</h4>
          
          <Dialog open={isSegmentDialogOpen} onOpenChange={setIsSegmentDialogOpen}>
            <DialogTrigger asChild>
              <Button onClick={resetSegmentForm} className="gap-2">
                <Plus className="h-4 w-4" />
                Ajouter une marque
              </Button>
            </DialogTrigger>
            
            <DialogContent className="max-w-md">
              <form onSubmit={handleSegmentSubmit}>
                <DialogHeader>
                  <DialogTitle>
                    {editingSegment ? "Modifier la marque" : "Nouvelle marque"}
                  </DialogTitle>
                  <DialogDescription>
                    {editingSegment ? "Modifiez les informations de la marque" : "Créez une nouvelle marque/segment"}
                  </DialogDescription>
                </DialogHeader>

                <div className="grid gap-4 py-4">
                  <div>
                    <Label htmlFor="segment-nom">Nom de la marque *</Label>
                    <Input
                      id="segment-nom"
                      value={segmentFormData.nom}
                      onChange={(e) => setSegmentFormData({...segmentFormData, nom: e.target.value})}
                      required
                      aria-label="Nom du segment"
                      className="segment-name-input"
                      placeholder="Entrez le nom de la marque"
                    />
                  </div>

                  <div>
                    <Label htmlFor="segment-couleur">Couleur de la marque</Label>
                    <div className="grid grid-cols-5 gap-2 mt-2">
                      {predefinedColors.map((color) => (
                        <button
                          key={color}
                          type="button"
                          className={`color-button color-${color.replace('#', '')}`}
                          title={`Choisir la couleur ${color}`}
                          onClick={() => setSegmentFormData({...segmentFormData, couleur: color})}
                        />
                      ))}
                    </div>
                    <Input
                      id="segment-couleur"
                      type="color"
                      value={segmentFormData.couleur}
                      onChange={(e) => setSegmentFormData({...segmentFormData, couleur: e.target.value})}
                      className="mt-2 h-10"
                      title="Sélectionner une couleur"
                    />
                  </div>

                  <div>
                    <Label htmlFor="segment-logo">Logo de la marque</Label>
                    <div className="space-y-3 mt-2">
                      <div className="flex items-center gap-3">
                        <Input
                          id="segment-logo"
                          type="url"
                          placeholder="https://exemple.com/logo.png"
                          value={segmentFormData.logo_url}
                          onChange={(e) => setSegmentFormData({...segmentFormData, logo_url: e.target.value})}
                          className="flex-1"
                          title="URL du logo de la marque"
                        />
                        <div className="flex gap-2">
                          <label htmlFor="logo-file-input" className="sr-only">Téléverser un logo</label>
                          <input
                            type="file"
                            accept="image/*"
                            id="logo-file-input"
                            title="Téléverser un logo"
                            placeholder="Choisir un fichier image"
                            onChange={(e) => {
                              const file = e.target.files?.[0];
                              if (file) {
                                handleLogoUpload(file);
                              }
                            }}
                            className="hidden"
                          />
                          <Button
                            type="button"
                            variant="outline"
                            size="sm"
                            className="gap-2 whitespace-nowrap"
                            onClick={() => document.getElementById('logo-file-input')?.click()}
                            disabled={uploadingLogo}
                            title="Téléverser un logo"
                          >
                            <Upload className="h-4 w-4" />
                            {uploadingLogo ? "Upload..." : "Parcourir"}
                          </Button>
                        </div>
                      </div>
                      {segmentFormData.logo_url && (
                        <div className="flex items-center gap-2 p-2 border rounded-md bg-muted/20 min-w-0">
                          <Image className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                          <img 
                            src={segmentFormData.logo_url} 
                            alt="Aperçu du logo" 
                            className="h-8 w-8 object-contain flex-shrink-0"
                            onError={(e) => {
                              (e.target as HTMLImageElement).style.display = 'none';
                            }}
                          />
                          <span className="text-sm text-muted-foreground truncate min-w-0 flex-1" title={segmentFormData.logo_url}>
                            {segmentFormData.logo_url.length > 50 
                              ? `${segmentFormData.logo_url.substring(0, 47)}...` 
                              : segmentFormData.logo_url
                            }
                          </span>
                        </div>
                      )}
                    </div>
                  </div>
                </div>

                <DialogFooter>
                  <Button type="button" variant="outline" onClick={() => setIsSegmentDialogOpen(false)}>
                    Annuler
                  </Button>
                  <Button type="submit">
                    {editingSegment ? "Modifier" : "Créer"}
                  </Button>
                </DialogFooter>
              </form>
            </DialogContent>
          </Dialog>
        </div>

        <Card>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Logo</TableHead>
                  <TableHead>Marque</TableHead>
                  <TableHead>Villes associées</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {segments.map((segment) => (
                  <TableRow key={segment.id}>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        {segment.logo_url ? (
                          <img 
                            src={segment.logo_url} 
                            alt={`Logo ${segment.nom}`}
                            className="h-10 w-10 object-contain rounded"
                            onError={(e) => {
                              (e.target as HTMLImageElement).style.display = 'none';
                            }}
                          />
                        ) : (
                          <div className="h-10 w-10 flex items-center justify-center border border-dashed border-muted-foreground/30 rounded">
                            <Image className="h-4 w-4 text-muted-foreground/50" />
                          </div>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-3">
                        <div 
                          className={`w-4 h-4 rounded-full flex-shrink-0 color-circle color-${segment.couleur.replace('#', '')}`}
                          title={`Couleur de la marque ${segment.nom}`}
                        />
                        <div className="font-medium">{segment.nom}</div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="secondary">
                        {segment.villes?.length || 0} ville(s)
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex gap-2 justify-end">
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => openVilleManagement(segment)}
                          className="gap-1"
                          title="Gérer les villes"
                        >
                          <Settings className="h-4 w-4" />
                          Villes
                        </Button>
                        
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => openEditSegmentDialog(segment)}
                          title="Modifier la marque"
                        >
                          <Edit className="h-4 w-4" />
                        </Button>
                        
                        <AlertDialog>
                          <AlertDialogTrigger asChild>
                            <Button variant="outline" size="sm" title="Supprimer la marque">
                              <Trash2 className="h-4 w-4" />
                            </Button>
                          </AlertDialogTrigger>
                          <AlertDialogContent>
                            <AlertDialogHeader>
                              <AlertDialogTitle>Confirmer la suppression</AlertDialogTitle>
                              <AlertDialogDescription>
                                Êtes-vous sûr de vouloir supprimer la marque "{segment.nom}" ? 
                                Cette action est irréversible.
                              </AlertDialogDescription>
                            </AlertDialogHeader>
                            <AlertDialogFooter>
                              <AlertDialogCancel>Annuler</AlertDialogCancel>
                              <AlertDialogAction 
                                onClick={() => handleDeleteSegment(segment.id)}
                                className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                                title="Supprimer le segment"
                              >
                                Supprimer
                              </AlertDialogAction>
                            </AlertDialogFooter>
                          </AlertDialogContent>
                        </AlertDialog>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </div>

      {/* Ville Management Modal */}
      {selectedSegmentForVilles && (
        <VilleManagement
          segment={selectedSegmentForVilles}
          isOpen={villeManagementOpen}
          onClose={() => {
            setVilleManagementOpen(false);
            setSelectedSegmentForVilles(null);
            loadData(); // Refresh data when closing ville management
          }}
        />
      )}
    </div>
  );
};

export default SegmentManagement;