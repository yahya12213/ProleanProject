import { useState, useEffect } from "react";
import axios from 'axios';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger } from "@/components/ui/alert-dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks/use-toast";

interface Centre {
  id: string;
  nom: string;
  adresse?: string;
  capacite?: number;
  equipements?: string[];
  created_at: string;
  ville_id?: string;
  villes?: {
    nom_ville: string;
  };
}

interface Formation {
  id: string;
  titre: string;
  description?: string;
  duree_heures: number;
  prix: number;
  niveau: string;
  created_at: string;
}

interface Classe {
  id: string;
  formation_id: string;
  centre_id: string;
  date_debut: string;
  date_fin: string;
  nombre_places: number;
  nom_classe: string;
  statut: 'programmee' | 'en_cours' | 'terminee' | 'annulee';
  formateur?: string;
  created_at: string;
  formations?: {
    titre: string;
    prix: number;
    duree_heures: number;
  };
  centres?: {
    nom: string;
    villes?: {
      nom_ville: string;
    };
  };
}

const FormationManagement = () => {
  const [centres, setCentres] = useState<Centre[]>([]);
  const [formations, setFormations] = useState<Formation[]>([]);
  const [classes, setClasses] = useState<Classe[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState("centres");
  
  // Dialog states
  const [isCentreDialogOpen, setIsCentreDialogOpen] = useState(false);
  const [isFormationDialogOpen, setIsFormationDialogOpen] = useState(false);
  const [isClasseDialogOpen, setIsClasseDialogOpen] = useState(false);
  
  // Editing states
  const [editingCentre, setEditingCentre] = useState<Centre | null>(null);
  const [editingFormation, setEditingFormation] = useState<Formation | null>(null);
  const [editingClasse, setEditingClasse] = useState<Classe | null>(null);
  
  const { toast } = useToast();

  // Form states
  const [centreFormData, setCentreFormData] = useState({
    nom: "",
    adresse: "",
    capacite: "",
    equipements: ""
  });

  const [formationFormData, setFormationFormData] = useState({
    titre: "",
    description: "",
    duree_heures: "",
    prix: "",
    niveau: "debutant"
  });

  const [classeFormData, setClasseFormData] = useState({
    formation_id: "",
    centre_id: "",
    date_debut: "",
    date_fin: "",
    nombre_places: "",
    nom_classe: "",
    formateur: ""
  });

  const niveauxFormation = [
    { value: "debutant", label: "Débutant" },
    { value: "intermediaire", label: "Intermédiaire" },
    { value: "avance", label: "Avancé" }
  ];

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);

      const [centresResponse, formationsResponse, classesResponse] = await Promise.all([
        axios.get('/api/centres?is_active=true'),
        axios.get('/api/formations?is_active=true'),
        axios.get('/api/classes?is_active=true'),
      ]);

      setCentres(centresResponse.data || []);
      setFormations(formationsResponse.data || []);
      setClasses(classesResponse.data || []);
    } catch (error) {
      console.error('Error loading data:', error);
      toast({
        title: "Erreur",
        description: "Impossible de charger les données",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  // Centre handlers
  const handleCentreSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    try {
      const equipements = centreFormData.equipements
        ? centreFormData.equipements.split(',').map(e => e.trim()).filter(e => e)
        : [];

      const centreData = {
        nom: centreFormData.nom,
        adresse: centreFormData.adresse,
        capacite: centreFormData.capacite ? parseInt(centreFormData.capacite) : null,
        equipements,
      };

      if (editingCentre) {
        await axios.put(`/api/centres/${editingCentre.id}`, centreData);
        toast({ title: "Succès", description: "Centre modifié avec succès" });
      } else {
        await axios.post('/api/centres', centreData);
        toast({ title: "Succès", description: "Centre créé avec succès" });
      }

      setIsCentreDialogOpen(false);
      resetCentreForm();
      loadData();
    } catch (error) {
      console.error('Error saving centre:', error);
      toast({ title: "Erreur", description: "Impossible de sauvegarder le centre", variant: "destructive" });
    }
  };

  // Formation handlers
  const handleFormationSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    try {
      const formationData = {
        titre: formationFormData.titre,
        description: formationFormData.description || null,
        duree_heures: parseInt(formationFormData.duree_heures),
        prix: parseFloat(formationFormData.prix),
        niveau: formationFormData.niveau,
      };

      if (editingFormation) {
        await axios.put(`/api/formations/${editingFormation.id}`, formationData);
        toast({ title: "Succès", description: "Formation modifiée avec succès" });
      } else {
        await axios.post('/api/formations', formationData);
        toast({ title: "Succès", description: "Formation créée avec succès" });
      }

      setIsFormationDialogOpen(false);
      resetFormationForm();
      loadData();
    } catch (error) {
      console.error('Error saving formation:', error);
      toast({ title: "Erreur", description: "Impossible de sauvegarder la formation", variant: "destructive" });
    }
  };

  // Classe handlers
  const handleClasseSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    try {
      const classeData = {
        formation_id: classeFormData.formation_id,
        centre_id: classeFormData.centre_id,
        date_debut: classeFormData.date_debut,
        date_fin: classeFormData.date_fin,
        nombre_places: parseInt(classeFormData.nombre_places),
        nom_classe: classeFormData.nom_classe,
        formateur: classeFormData.formateur || null
      };

      if (editingClasse) {
        await axios.put(`/api/classes/${editingClasse.id}`, classeData);
        toast({ title: "Succès", description: "Classe modifiée avec succès" });
      } else {
        await axios.post('/api/classes', classeData);
        toast({ title: "Succès", description: "Classe créée avec succès" });
      }

      setIsClasseDialogOpen(false);
      resetClasseForm();
      loadData();
    } catch (error) {
      console.error('Error saving classe:', error);
      toast({ title: "Erreur", description: "Impossible de sauvegarder la classe", variant: "destructive" });
    }
  };

  // Reset form functions
  const resetCentreForm = () => {
    setCentreFormData({
      nom: "", adresse: "",
      capacite: "", equipements: ""
    });
    setEditingCentre(null);
  };

  const resetFormationForm = () => {
    setFormationFormData({
      titre: "", description: "", duree_heures: "", prix: "",
      niveau: "debutant"
    });
    setEditingFormation(null);
  };

  const resetClasseForm = () => {
    setClasseFormData({
      formation_id: "", centre_id: "", date_debut: "", date_fin: "",
      nombre_places: "", nom_classe: "", formateur: ""
    });
    setEditingClasse(null);
  };

  // Open edit dialogs
  const openEditCentreDialog = (centre: Centre) => {
    setEditingCentre(centre);
    setCentreFormData({
      nom: centre.nom,
      adresse: centre.adresse || "",
      capacite: centre.capacite?.toString() || "",
      equipements: centre.equipements?.join(', ') || ""
    });
    setIsCentreDialogOpen(true);
  };

  const openEditFormationDialog = (formation: Formation) => {
    setEditingFormation(formation);
    setFormationFormData({
      titre: formation.titre,
      description: formation.description || "",
      duree_heures: formation.duree_heures.toString(),
      prix: formation.prix.toString(),
      niveau: formation.niveau
    });
    setIsFormationDialogOpen(true);
  };

  const openEditClasseDialog = (classe: Classe) => {
    setEditingClasse(classe);
    setClasseFormData({
      formation_id: classe.formation_id,
      centre_id: classe.centre_id,
      date_debut: classe.date_debut,
      date_fin: classe.date_fin,
      nombre_places: classe.nombre_places.toString(),
      nom_classe: classe.nom_classe,
      formateur: classe.formateur || ""
    });
    setIsClasseDialogOpen(true);
  };

  // Delete functions
  const handleDeleteCentre = async (centreId: string) => {
    try {
      await axios.put(`/api/centres/${centreId}`, { is_active: false });
      toast({ title: "Succès", description: "Centre supprimé avec succès" });
      loadData();
    } catch (error) {
      console.error('Error deleting centre:', error);
      toast({ title: "Erreur", description: "Impossible de supprimer le centre", variant: "destructive" });
    }
  };

  const handleDeleteFormation = async (formationId: string) => {
    try {
      await axios.put(`/api/formations/${formationId}`, { is_active: false });
      toast({ title: "Succès", description: "Formation supprimée avec succès" });
      loadData();
    } catch (error) {
      console.error('Error deleting formation:', error);
      toast({ title: "Erreur", description: "Impossible de supprimer la formation", variant: "destructive" });
    }
  };

  const handleDeleteClasse = async (classeId: string) => {
    try {
      await axios.put(`/api/classes/${classeId}`, { is_active: false });
      toast({ title: "Succès", description: "Classe supprimée avec succès" });
      loadData();
    } catch (error) {
      console.error('Error deleting classe:', error);
      toast({ title: "Erreur", description: "Impossible de supprimer la classe", variant: "destructive" });
    }
  };

  // Replace Supabase error handling with Axios-based API calls
  const handleError = async () => {
    try {
      const response = await axios.get('/api/formations/errors');
      const errorData = response.data;
      console.log('Error data:', errorData);
    } catch (error) {
      console.error('Error fetching formation errors:', error);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="text-center">
          <BookOpen className="h-12 w-12 mx-auto mb-4 text-muted-foreground animate-pulse" />
          <p className="text-muted-foreground">Chargement des formations...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h3 className="text-lg font-semibold">Gestion des Formations</h3>
        <p className="text-sm text-muted-foreground">
          Gérez l'offre de formation de l'entreprise : centres, catalogue et sessions
        </p>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
        <TabsList>
          <TabsTrigger value="centres" className="gap-2">
            <MapPin className="h-4 w-4" />
            Centres
          </TabsTrigger>
          <TabsTrigger value="formations" className="gap-2">
            <BookOpen className="h-4 w-4" />
            Catalogue
          </TabsTrigger>
          <TabsTrigger value="classes" className="gap-2">
            <Calendar className="h-4 w-4" />
            Classes
          </TabsTrigger>
        </TabsList>

        {/* Centres Tab */}
        <TabsContent value="centres">
          <div className="space-y-4">
            <div className="flex justify-between items-center">
              <h4 className="text-base font-medium">Centres de formation</h4>
              
              <Dialog open={isCentreDialogOpen} onOpenChange={setIsCentreDialogOpen}>
                <DialogTrigger asChild>
                  <Button onClick={resetCentreForm} className="gap-2">
                    <Plus className="h-4 w-4" />
                    Ajouter un centre
                  </Button>
                </DialogTrigger>
                
                <DialogContent className="max-w-md">
                  <form onSubmit={handleCentreSubmit}>
                    <DialogHeader>
                      <DialogTitle>
                        {editingCentre ? "Modifier le centre" : "Nouveau centre"}
                      </DialogTitle>
                    </DialogHeader>

                    <div className="grid gap-4 py-4">
                      <div>
                        <Label htmlFor="centre-nom">Nom du centre *</Label>
                        <Input
                          id="centre-nom"
                          value={centreFormData.nom}
                          onChange={(e) => setCentreFormData({...centreFormData, nom: e.target.value})}
                          required
                        />
                      </div>

                      <div>
                        <Label htmlFor="centre-adresse">Adresse</Label>
                        <Input
                          id="centre-adresse"
                          value={centreFormData.adresse}
                          onChange={(e) => setCentreFormData({...centreFormData, adresse: e.target.value})}
                        />
                      </div>

                      <div>
                        <Label htmlFor="centre-capacite">Capacité maximale</Label>
                        <Input
                          id="centre-capacite"
                          type="number"
                          value={centreFormData.capacite}
                          onChange={(e) => setCentreFormData({...centreFormData, capacite: e.target.value})}
                        />
                      </div>

                      <div>
                        <Label htmlFor="centre-equipements">Équipements (séparés par des virgules)</Label>
                        <Textarea
                          id="centre-equipements"
                          value={centreFormData.equipements}
                          onChange={(e) => setCentreFormData({...centreFormData, equipements: e.target.value})}
                          placeholder="Vidéoprojecteur, Tableaux, Wifi..."
                        />
                      </div>
                    </div>

                    <DialogFooter>
                      <Button type="button" variant="outline" onClick={() => setIsCentreDialogOpen(false)}>
                        Annuler
                      </Button>
                      <Button type="submit">
                        {editingCentre ? "Modifier" : "Créer"}
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
                      <TableHead>Centre</TableHead>
                      <TableHead>Adresse</TableHead>
                      <TableHead>Capacité</TableHead>
                      <TableHead>Équipements</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {centres.map((centre) => (
                      <TableRow key={centre.id}>
                        <TableCell>
                          <div className="flex items-center gap-3">
                            <MapPin className="h-4 w-4 text-muted-foreground" />
                            <div>
                              <div className="font-medium">{centre.nom}</div>
                              <div className="text-sm text-muted-foreground">{centre.villes?.nom_ville}</div>
                            </div>
                          </div>
                        </TableCell>
                        <TableCell className="max-w-xs">
                          <div className="text-sm">
                            {centre.adresse || '-'}
                          </div>
                        </TableCell>
                        <TableCell>
                          {centre.capacite ? (
                            <Badge variant="secondary">{centre.capacite} pers.</Badge>
                          ) : (
                            <span className="text-muted-foreground">-</span>
                          )}
                        </TableCell>
                        <TableCell>
                          <div className="flex flex-wrap gap-1 max-w-xs">
                            {centre.equipements?.slice(0, 2).map((equip, index) => (
                              <Badge key={index} variant="outline" className="text-xs">
                                {equip}
                              </Badge>
                            ))}
                            {centre.equipements && centre.equipements.length > 2 && (
                              <Badge variant="outline" className="text-xs">
                                +{centre.equipements.length - 2}
                              </Badge>
                            )}
                          </div>
                        </TableCell>
                        <TableCell className="text-right">
                          <div className="flex gap-2 justify-end">
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => openEditCentreDialog(centre)}
                            >
                              <Edit className="h-4 w-4" />
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
                                    Êtes-vous sûr de vouloir supprimer le centre "{centre.nom}" ?
                                  </AlertDialogDescription>
                                </AlertDialogHeader>
                                <AlertDialogFooter>
                                  <AlertDialogCancel>Annuler</AlertDialogCancel>
                                  <AlertDialogAction 
                                    onClick={() => handleDeleteCentre(centre.id)}
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
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Formations Tab */}
        <TabsContent value="formations">
          <div className="space-y-4">
            <div className="flex justify-between items-center">
              <h4 className="text-base font-medium">Catalogue de formations</h4>
              
              <Dialog open={isFormationDialogOpen} onOpenChange={setIsFormationDialogOpen}>
                <DialogTrigger asChild>
                  <Button onClick={resetFormationForm} className="gap-2">
                    <Plus className="h-4 w-4" />
                    Ajouter une formation
                  </Button>
                </DialogTrigger>
                
                <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
                  <form onSubmit={handleFormationSubmit}>
                    <DialogHeader>
                      <DialogTitle>
                        {editingFormation ? "Modifier la formation" : "Nouvelle formation"}
                      </DialogTitle>
                    </DialogHeader>

                    <div className="grid gap-4 py-4">
                      <div>
                        <Label htmlFor="formation-titre">Titre de la formation *</Label>
                        <Input
                          id="formation-titre"
                          value={formationFormData.titre}
                          onChange={(e) => setFormationFormData({...formationFormData, titre: e.target.value})}
                          required
                        />
                      </div>

                      <div>
                        <Label htmlFor="formation-description">Description</Label>
                        <Textarea
                          id="formation-description"
                          value={formationFormData.description}
                          onChange={(e) => setFormationFormData({...formationFormData, description: e.target.value})}
                          rows={3}
                        />
                      </div>

                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <Label htmlFor="formation-duree">Durée (heures) *</Label>
                          <Input
                            id="formation-duree"
                            type="number"
                            value={formationFormData.duree_heures}
                            onChange={(e) => setFormationFormData({...formationFormData, duree_heures: e.target.value})}
                            required
                          />
                        </div>
                        <div>
                          <Label htmlFor="formation-prix">Prix (DH) *</Label>
                          <Input
                            id="formation-prix"
                            type="number"
                            step="0.01"
                            value={formationFormData.prix}
                            onChange={(e) => setFormationFormData({...formationFormData, prix: e.target.value})}
                            required
                          />
                        </div>
                      </div>

                      <div>
                        <Label htmlFor="formation-niveau">Niveau *</Label>
                        <Select value={formationFormData.niveau} onValueChange={(value) => setFormationFormData({...formationFormData, niveau: value})}>
                          <SelectTrigger>
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            {niveauxFormation.map((niveau) => (
                              <SelectItem key={niveau.value} value={niveau.value}>
                                {niveau.label}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      </div>
                    </div>

                    <DialogFooter>
                      <Button type="button" variant="outline" onClick={() => setIsFormationDialogOpen(false)}>
                        Annuler
                      </Button>
                      <Button type="submit">
                        {editingFormation ? "Modifier" : "Créer"}
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
                      <TableHead>Formation</TableHead>
                      <TableHead>Niveau</TableHead>
                      <TableHead>Durée</TableHead>
                      <TableHead>Prix</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {formations.map((formation) => (
                      <TableRow key={formation.id}>
                        <TableCell>
                          <div className="flex items-center gap-3">
                            <GraduationCap className="h-4 w-4 text-muted-foreground" />
                            <div>
                              <div className="font-medium">{formation.titre}</div>
                              {formation.description && (
                                <div className="text-sm text-muted-foreground max-w-xs truncate">
                                  {formation.description}
                                </div>
                              )}
                            </div>
                          </div>
                        </TableCell>
                        <TableCell>
                          <Badge variant={
                            formation.niveau === 'debutant' ? 'secondary' :
                            formation.niveau === 'intermediaire' ? 'default' : 'destructive'
                          }>
                            {niveauxFormation.find(n => n.value === formation.niveau)?.label}
                          </Badge>
                        </TableCell>
                        <TableCell>{formation.duree_heures}h</TableCell>
                        <TableCell>
                          <div className="flex items-center gap-1">
                            {formation.prix} DH
                          </div>
                        </TableCell>
                        <TableCell className="text-right">
                          <div className="flex gap-2 justify-end">
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => openEditFormationDialog(formation)}
                            >
                              <Edit className="h-4 w-4" />
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
                                    Êtes-vous sûr de vouloir supprimer la formation "{formation.titre}" ?
                                  </AlertDialogDescription>
                                </AlertDialogHeader>
                                <AlertDialogFooter>
                                  <AlertDialogCancel>Annuler</AlertDialogCancel>
                                  <AlertDialogAction 
                                    onClick={() => handleDeleteFormation(formation.id)}
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
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Classes Tab */}
        <TabsContent value="classes">
          <div className="space-y-4">
            <div className="flex justify-between items-center">
              <h4 className="text-base font-medium">Sessions de formation</h4>
              
              <Dialog open={isClasseDialogOpen} onOpenChange={setIsClasseDialogOpen}>
                <DialogTrigger asChild>
                  <Button onClick={resetClasseForm} className="gap-2">
                    <Plus className="h-4 w-4" />
                    Programmer une classe
                  </Button>
                </DialogTrigger>
                
                <DialogContent className="max-w-md">
                  <form onSubmit={handleClasseSubmit}>
                    <DialogHeader>
                      <DialogTitle>
                        {editingClasse ? "Modifier la classe" : "Nouvelle classe"}
                      </DialogTitle>
                    </DialogHeader>

                    <div className="grid gap-4 py-4">
                      <div>
                        <Label htmlFor="classe-nom">Nom de la classe *</Label>
                        <Input
                          id="classe-nom"
                          value={classeFormData.nom_classe}
                          onChange={(e) => setClasseFormData({...classeFormData, nom_classe: e.target.value})}
                          required
                        />
                      </div>

                      <div>
                        <Label htmlFor="classe-formation">Formation *</Label>
                        <Select value={classeFormData.formation_id} onValueChange={(value) => setClasseFormData({...classeFormData, formation_id: value})}>
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
                        <Label htmlFor="classe-centre">Centre *</Label>
                        <Select value={classeFormData.centre_id} onValueChange={(value) => setClasseFormData({...classeFormData, centre_id: value})}>
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

                      <div className="grid grid-cols-2 gap-2">
                        <div>
                          <Label htmlFor="classe-debut">Date début *</Label>
                          <Input
                            id="classe-debut"
                            type="date"
                            value={classeFormData.date_debut}
                            onChange={(e) => setClasseFormData({...classeFormData, date_debut: e.target.value})}
                            required
                          />
                        </div>
                        <div>
                          <Label htmlFor="classe-fin">Date fin *</Label>
                          <Input
                            id="classe-fin"
                            type="date"
                            value={classeFormData.date_fin}
                            onChange={(e) => setClasseFormData({...classeFormData, date_fin: e.target.value})}
                            required
                          />
                        </div>
                      </div>

                      <div>
                        <Label htmlFor="classe-places">Places maximum *</Label>
                        <Input
                          id="classe-places"
                          type="number"
                          value={classeFormData.nombre_places}
                          onChange={(e) => setClasseFormData({...classeFormData, nombre_places: e.target.value})}
                          required
                        />
                      </div>

                      <div>
                        <Label htmlFor="classe-formateur">Formateur</Label>
                        <Input
                          id="classe-formateur"
                          value={classeFormData.formateur}
                          onChange={(e) => setClasseFormData({...classeFormData, formateur: e.target.value})}
                        />
                      </div>
                    </div>

                    <DialogFooter>
                      <Button type="button" variant="outline" onClick={() => setIsClasseDialogOpen(false)}>
                        Annuler
                      </Button>
                      <Button type="submit">
                        {editingClasse ? "Modifier" : "Créer"}
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
                      <TableHead>Classe</TableHead>
                      <TableHead>Formation</TableHead>
                      <TableHead>Centre</TableHead>
                      <TableHead>Dates</TableHead>
                      <TableHead>Places</TableHead>
                      <TableHead>Formateur</TableHead>
                      <TableHead>Statut</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {classes.map((classe) => (
                      <TableRow key={classe.id}>
                        <TableCell>
                          <div className="font-medium">{classe.nom_classe}</div>
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-2">
                            <Calendar className="h-4 w-4 text-muted-foreground" />
                            <div className="font-medium">{classe.formations?.titre}</div>
                          </div>
                        </TableCell>
                        <TableCell>
                          {classe.centres?.nom}<br />
                          <span className="text-sm text-muted-foreground">{classe.centres?.villes?.nom_ville}</span>
                        </TableCell>
                        <TableCell>
                          <div className="text-sm">
                            {new Date(classe.date_debut).toLocaleDateString('fr-FR')}<br />
                            au {new Date(classe.date_fin).toLocaleDateString('fr-FR')}
                          </div>
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-2">
                            <Users className="h-4 w-4" />
                            <span>{classe.nombre_places}</span>
                          </div>
                        </TableCell>
                        <TableCell>
                          {classe.formateur || <span className="text-muted-foreground italic">Non assigné</span>}
                        </TableCell>
                        <TableCell>
                          <Badge variant={
                            classe.statut === 'programmee' ? 'secondary' :
                            classe.statut === 'en_cours' ? 'default' :
                            classe.statut === 'terminee' ? 'secondary' : 'destructive'
                          }>
                            {classe.statut === 'programmee' ? 'Programmée' :
                             classe.statut === 'en_cours' ? 'En cours' :
                             classe.statut === 'terminee' ? 'Terminée' : 'Annulée'}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-right">
                          <div className="flex gap-2 justify-end">
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => openEditClasseDialog(classe)}
                            >
                              <Edit className="h-4 w-4" />
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
                                    Êtes-vous sûr de vouloir supprimer cette classe ?
                                  </AlertDialogDescription>
                                </AlertDialogHeader>
                                <AlertDialogFooter>
                                  <AlertDialogCancel>Annuler</AlertDialogCancel>
                                  <AlertDialogAction 
                                    onClick={() => handleDeleteClasse(classe.id)}
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
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default FormationManagement;