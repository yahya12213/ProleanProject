import { useState, useEffect, useCallback } from "react";
import "./user-management.css";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger } from "@/components/ui/alert-dialog";
import { Checkbox } from "@/components/ui/checkbox";
import { Switch } from "@/components/ui/switch";
import { useToast } from "@/hooks/use-toast";
// Supabase supprimé, toute la logique doit passer par l'API Express locale
import { Users, Plus, Edit, Trash2, Search, Filter, Check, Eye, RefreshCw, UserX, UserCheck } from "lucide-react";

interface Profile {
  id: string;
  user_id?: string;
  nom: string;
  prenom: string;
  poste?: string;
  email: string;
  photo_url?: string;
  chef_hierarchique_id?: string;
  payroll_enabled?: boolean;
  account_status?: string;
  created_at: string;
  chef_hierarchique?: { nom: string; prenom: string };
  profile_segments?: Array<{ segments: { id: string; nom: string; couleur: string } }>;
  user_roles?: Array<{ roles: { nom: string } }>;
}

interface Role {
  id: string;
  nom: string;
  description?: string;
}

interface Segment {
  id: string;
  nom: string;
  couleur: string;
}

const UserManagement = () => {
  const [users, setUsers] = useState<Profile[]>([]);
  const [roles, setRoles] = useState<Role[]>([]);
  const [segments, setSegments] = useState<Segment[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedRole, setSelectedRole] = useState<string>("all");
  const [selectedSegment, setSelectedSegment] = useState<string>("all");
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [editingUser, setEditingUser] = useState<Profile | null>(null);
  const [selectedSegments, setSelectedSegments] = useState<string[]>([]);
  const [showSegmentSelector, setShowSegmentSelector] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const { toast } = useToast();

  // Form state
  const [formData, setFormData] = useState({
    nom: "",
    prenom: "",
    poste: "",
    email: "",
    password: "",
    role_id: "",
    chef_hierarchique_id: ""
  });

  const loadData = useCallback(async () => {
    try {
      setLoading(true);
      // Charger les utilisateurs avec leurs segments et rôles
      const profilesRes = await fetch('/api/profiles');
      const profiles = await profilesRes.json();
      if (!profilesRes.ok) {
        setUsers([]);
      } else {
        // Charger les rôles pour chaque utilisateur
        const profilesWithRoles = await Promise.all(
          (profiles || []).map(async (profile: Profile) => {
            const rolesRes = await fetch(`/api/roles?profile_id=${profile.id}`);
            const roles = await rolesRes.json();
            return { ...profile, roles };
          })
        );
        setUsers(profilesWithRoles);
      }
      loadRolesAndSegments();
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
  }, [toast]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const loadRolesAndSegments = async () => {
    try {
      const rolesRes = await fetch('/api/roles');
      const rolesData = await rolesRes.json();
      setRoles(rolesData || []);
      const segmentsRes = await fetch('/api/segments');
      const segmentsData = await segmentsRes.json();
      setSegments(segmentsData || []);
    } catch (error) {
      setRoles([]);
      setSegments([]);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.nom || !formData.prenom || !formData.email) {
      toast({
        title: "Erreur",
        description: "Veuillez remplir tous les champs obligatoires",
        variant: "destructive"
      });
      return;
    }
    try {
      if (editingUser) {
        const updateRes = await fetch(`/api/profiles/${editingUser.id}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            nom: formData.nom,
            prenom: formData.prenom,
            poste: formData.poste || null,
            chef_hierarchique_id: formData.chef_hierarchique_id || null
          })
        });
        if (!updateRes.ok) throw new Error('Erreur lors de la modification du profil');
        if (selectedSegments.length > 0) {
          await fetch(`/api/profile_segments/${editingUser.id}`, {
            method: 'DELETE'
          });
          await fetch('/api/profile_segments', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(selectedSegments.map(segmentId => ({ profile_id: editingUser.id, segment_id: segmentId })))
          });
        }
        toast({ title: "Succès", description: "Utilisateur modifié avec succès" });
      } else {
        const createRes = await fetch('/api/profiles', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            nom: formData.nom,
            prenom: formData.prenom,
            email: formData.email,
            poste: formData.poste || null,
            chef_hierarchique_id: formData.chef_hierarchique_id || null
          })
        });
        if (!createRes.ok) throw new Error('Erreur lors de la création du profil');
        toast({ title: "Succès", description: "Utilisateur ajouté avec succès" });
      }
  loadData();
    } catch (error) {
      console.error('Erreur lors de la soumission du formulaire:', error);
      toast({
        title: "Erreur",
        description: "Impossible de soumettre le formulaire",
        variant: "destructive"
      });
    }
  };

  const handlePayrollToggle = async (profileId: string, enabled: boolean) => {
    try {
      const res = await fetch(`/api/profiles/${profileId}/payroll`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ payroll_enabled: enabled })
      });
      if (!res.ok) throw new Error('Erreur lors de la mise à jour du statut de paie');
      toast({ title: "Succès", description: `Calcul de paie ${enabled ? 'activé' : 'désactivé'} avec succès` });
      loadData();
    } catch (error) {
      toast({ title: "Erreur", description: "Erreur lors de la mise à jour du statut de paie", variant: "destructive" });
    }
  };

  const handleAccountStatusToggle = async (profileId: string, currentStatus: string) => {
    try {
      setLoading(true);
      const newStatus = currentStatus === 'suspended' ? 'active' : 'suspended';
      const res = await fetch(`/api/profiles/${profileId}/status`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ account_status: newStatus })
      });
      if (!res.ok) throw new Error('Erreur lors de la modification du statut du compte');
      toast({ title: "Succès", description: `Utilisateur ${newStatus === 'suspended' ? 'suspendu' : 'autorisé à se connecter'} avec succès` });
      loadData();
    } catch (error) {
      toast({ title: "Erreur", description: "Erreur lors de la modification du statut du compte", variant: "destructive" });
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (userId: string, userAuthId?: string) => {
    try {
      const existsRes = await fetch(`/api/profiles/${userId}`);
      if (!existsRes.ok) throw new Error('Utilisateur introuvable');
      const userExists = await existsRes.json();
      if (!userExists) {
        toast({ title: "Utilisateur introuvable", description: "Cet utilisateur n'existe plus dans la base de données. Actualisation de la liste...", variant: "destructive" });
        loadData();
        return;
      }
      const deleteRes = await fetch(`/api/profiles/${userId}`, { method: 'DELETE' });
      if (!deleteRes.ok) throw new Error('Erreur lors de la suppression');
      toast({ title: "Succès", description: "Utilisateur supprimé avec succès" });
      loadData();
    } catch (error) {
      toast({ title: "Erreur", description: "Impossible de supprimer l'utilisateur", variant: "destructive" });
    }
  };

  const handleForceDelete = async (userId: string) => {
    try {
      const existsRes = await fetch(`/api/profiles/${userId}`);
      if (!existsRes.ok) throw new Error('Utilisateur introuvable');
      const userExists = await existsRes.json();
      if (!userExists) {
        toast({ title: "Utilisateur introuvable", description: "Cet utilisateur n'existe plus dans la base de données. Actualisation de la liste...", variant: "destructive" });
        loadData();
        return;
      }
      const deleteRes = await fetch(`/api/profiles/${userId}?force=true`, { method: 'DELETE' });
      if (!deleteRes.ok) throw new Error('Erreur lors de la suppression définitive');
      toast({ title: "Succès", description: "Utilisateur supprimé définitivement avec succès" });
      loadData();
    } catch (error) {
      toast({ title: "Erreur", description: "Impossible de supprimer définitivement l'utilisateur", variant: "destructive" });
    }
  };

  const resetForm = () => {
    setFormData({
      nom: "",
      prenom: "",
      poste: "",
      email: "",
      password: "",
      role_id: "",
      chef_hierarchique_id: ""
    });
    setSelectedSegments([]);
    setEditingUser(null);
    setShowSegmentSelector(false);
  };

  const handleSyncData = async () => {
    setSyncing(true);
    try {
      // TODO: Remplacer par appel à l'API Express locale pour nettoyage et synchronisation
      toast({
        title: "Synchronisation réussie",
        description: `Synchronisation terminée.`,
      });
      loadData();
    } catch (error: unknown) {
      console.error('Erreur:', error);
      toast({
        title: "Erreur",
        description: "Une erreur inattendue s'est produite",
        variant: "destructive"
      });
    } finally {
      setSyncing(false);
    }
  };

  const openEditDialog = (user: Profile) => {
    setEditingUser(user);
    setFormData({
      nom: user.nom,
      prenom: user.prenom,
      poste: user.poste || "",
      email: user.email,
      password: "", // Ne pas préremplir le mot de passe
      role_id: "", // Récupérer depuis user_roles si nécessaire
      chef_hierarchique_id: user.chef_hierarchique_id || ""
    });
    // Récupérer les segments actuels de l'utilisateur
    const currentSegments = user.profile_segments?.map(ps => ps.segments.id) || [];
    setSelectedSegments(currentSegments);
    setIsDialogOpen(true);
  };

  const handleSegmentToggle = (segmentId: string) => {
    setSelectedSegments(prev => 
      prev.includes(segmentId) 
        ? prev.filter(id => id !== segmentId)
        : [...prev, segmentId]
    );
  };

  const confirmSegmentSelection = () => {
    setShowSegmentSelector(false);
  };

  const filteredUsers = users.filter(user => {
    const matchesSearch = 
      user.nom.toLowerCase().includes(searchTerm.toLowerCase()) ||
      user.prenom.toLowerCase().includes(searchTerm.toLowerCase()) ||
      user.email.toLowerCase().includes(searchTerm.toLowerCase());
    
    const matchesRole = selectedRole === "all" || !selectedRole || 
      user.user_roles?.some(ur => ur.roles.nom === selectedRole);
    
    const matchesSegment = selectedSegment === "all" || !selectedSegment || 
      user.profile_segments?.some(ps => ps.segments.id === selectedSegment);

    return matchesSearch && matchesRole && matchesSegment;
  });

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="text-center">
          <Users className="h-12 w-12 mx-auto mb-4 text-muted-foreground animate-pulse" />
          <p className="text-muted-foreground">Chargement des utilisateurs...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="user-management-section">
      {/* Header with Create Button */}
      <div className="flex justify-between items-center">
        <div>
          <h3 className="text-lg font-semibold">Gestion des Utilisateurs</h3>
          <p className="text-sm text-muted-foreground">
            Gérez les comptes utilisateurs de la plateforme
          </p>
        </div>
        
        <div className="flex gap-2">
          <Button 
            variant="outline" 
            onClick={handleSyncData}
            disabled={syncing}
            className="gap-2"
          >
            <RefreshCw className={`h-4 w-4 ${syncing ? 'animate-spin' : ''}`} />
            {syncing ? 'Synchronisation...' : 'Synchroniser'}
          </Button>
          
          <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
            <DialogTrigger asChild>
              <Button onClick={resetForm} className="gap-2">
                <Plus className="h-4 w-4" />
                Ajouter un utilisateur
              </Button>
            </DialogTrigger>
          
          <DialogContent className="max-w-md max-h-[90vh] overflow-y-auto">
            <form onSubmit={handleSubmit}>
              <DialogHeader>
                <DialogTitle>
                  {editingUser ? "Modifier l'utilisateur" : "Nouvel utilisateur"}
                </DialogTitle>
                <DialogDescription>
                  {editingUser ? "Modifiez les informations de l'utilisateur" : "Créez un nouveau compte utilisateur"}
                </DialogDescription>
              </DialogHeader>

              <div className="grid gap-4 py-4">
                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <Label htmlFor="prenom">Prénom *</Label>
                    <Input
                      id="prenom"
                      value={formData.prenom}
                      onChange={(e) => setFormData({...formData, prenom: e.target.value})}
                      required
                    />
                  </div>
                  <div>
                    <Label htmlFor="nom">Nom *</Label>
                    <Input
                      id="nom"
                      value={formData.nom}
                      onChange={(e) => setFormData({...formData, nom: e.target.value})}
                      required
                    />
                  </div>
                </div>

                <div>
                  <Label htmlFor="email">Email professionnel (authentification) *</Label>
                  <Input
                    id="email"
                    type="email"
                    value={formData.email}
                    onChange={(e) => setFormData({...formData, email: e.target.value})}
                    required
                    disabled={!!editingUser}
                    placeholder="email@prolean.com"
                  />
                  <p className="text-xs text-muted-foreground mt-1">
                    Cet email sera utilisé pour l'authentification au système
                  </p>
                </div>

                {!editingUser && (
                  <div>
                    <Label htmlFor="password">Mot de passe *</Label>
                    <Input
                      id="password"
                      type="password"
                      value={formData.password}
                      onChange={(e) => setFormData({...formData, password: e.target.value})}
                      required
                      placeholder="Minimum 6 caractères"
                    />
                  </div>
                )}

                <div>
                  <Label htmlFor="poste">Poste</Label>
                  <Input
                    id="poste"
                    value={formData.poste}
                    onChange={(e) => setFormData({...formData, poste: e.target.value})}
                  />
                </div>

                <div>
                  <Label htmlFor="role">Rôle</Label>
                  <Select value={formData.role_id} onValueChange={(value) => setFormData({...formData, role_id: value})}>
                    <SelectTrigger>
                      <SelectValue placeholder="Sélectionner un rôle" />
                    </SelectTrigger>
                    <SelectContent>
                      {roles.map((role) => (
                        <SelectItem key={role.id} value={role.id}>
                          {role.nom} {role.description && `- ${role.description}`}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                <div>
                  <Label>Segments</Label>
                  {!showSegmentSelector ? (
                    <div className="space-y-2">
                      <Button 
                        type="button" 
                        variant="outline" 
                        onClick={() => setShowSegmentSelector(true)}
                        className="w-full justify-start"
                      >
                        {selectedSegments.length === 0 ? "Sélectionner des segments" : `${selectedSegments.length} segment(s) sélectionné(s)`}
                      </Button>
                      {selectedSegments.length > 0 && (
                        <div className="flex flex-wrap gap-1">
                          {selectedSegments.map(segmentId => {
                            const segment = segments.find(s => s.id === segmentId);
                            return segment ? (
                              <Badge 
                                key={segmentId} 
                                style={{ backgroundColor: segment.couleur }}
                                className="text-white"
                              >
                                {segment.nom}
                              </Badge>
                            ) : null;
                          })}
                        </div>
                      )}
                    </div>
                  ) : (
                    <Card className="p-4">
                      <div className="space-y-3">
                        <div className="flex justify-between items-center">
                          <Label className="text-sm font-medium">Choisir les segments</Label>
                          <Button 
                            type="button" 
                            size="sm" 
                            onClick={confirmSegmentSelection}
                            className="gap-1"
                          >
                            <Check className="h-3 w-3" />
                            Valider
                          </Button>
                        </div>
                        {segments.map((segment) => (
                          <div key={segment.id} className="flex items-center space-x-2">
                            <Checkbox
                              id={`segment-${segment.id}`}
                              checked={selectedSegments.includes(segment.id)}
                              onCheckedChange={() => handleSegmentToggle(segment.id)}
                            />
                            <Label 
                              htmlFor={`segment-${segment.id}`}
                              className="flex items-center gap-2 cursor-pointer"
                            >
                              <div 
                                className={`w-3 h-3 rounded-full segment-dot segment-dot-${segment.id}`}
                              />
                              {segment.nom}
                            </Label>
                          </div>
                        ))}
                      </div>
                    </Card>
                  )}
                </div>

                <div>
                  <Label htmlFor="chef">Chef hiérarchique (optionnel)</Label>
                  <Select value={formData.chef_hierarchique_id || "none"} onValueChange={(value) => setFormData({...formData, chef_hierarchique_id: value === "none" ? "" : value})}>
                    <SelectTrigger>
                      <SelectValue placeholder="Aucun chef hiérarchique" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="none">Aucun</SelectItem>
                      {users.filter(u => u.id !== editingUser?.id).map((user) => (
                        <SelectItem key={user.id} value={user.id}>
                          {user.prenom} {user.nom}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <DialogFooter>
                <Button type="button" variant="outline" onClick={() => setIsDialogOpen(false)}>
                  Annuler
                </Button>
                <Button type="submit">
                  {editingUser ? "Modifier" : "Créer"}
                </Button>
              </DialogFooter>
            </form>
          </DialogContent>
          </Dialog>
        </div>
      </div>

      {/* Filters */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Filter className="h-4 w-4" />
            Filtres et recherche
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 sm:gap-4">
            <div>
              <Label htmlFor="search" className="text-sm">Rechercher</Label>
              <div className="relative">
                <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
                <Input
                  id="search"
                  placeholder="Nom, prénom, email..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-8 text-sm"
                />
              </div>
            </div>
            
            <div>
              <Label htmlFor="filter-role">Filtrer par rôle</Label>
              <Select value={selectedRole} onValueChange={setSelectedRole}>
                <SelectTrigger>
                  <SelectValue placeholder="Tous les rôles" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">Tous les rôles</SelectItem>
                  {roles.map((role) => (
                    <SelectItem key={role.id} value={role.nom}>
                      {role.nom}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div>
              <Label htmlFor="filter-segment">Filtrer par segment</Label>
              <Select value={selectedSegment} onValueChange={setSelectedSegment}>
                <SelectTrigger>
                  <SelectValue placeholder="Tous les segments" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">Tous les segments</SelectItem>
                  {segments.map((segment) => (
                    <SelectItem key={segment.id} value={segment.id}>
                      {segment.nom}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Users Table */}
      <Card>
        <CardHeader>
          <CardTitle>Utilisateurs ({filteredUsers.length})</CardTitle>
          <CardDescription>
            Liste de tous les utilisateurs de la plateforme
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Utilisateur</TableHead>
                <TableHead>Email</TableHead>
                <TableHead>Rôle</TableHead>
                <TableHead>Segments</TableHead>
                <TableHead>Chef</TableHead>
                <TableHead className="text-center">Activation Paie</TableHead>
                <TableHead className="text-center">Statut Compte</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredUsers.map((user) => (
                <TableRow key={user.id}>
                  <TableCell className="flex items-center gap-3">
                    <Avatar className="h-8 w-8">
                      <AvatarImage src={user.photo_url} />
                      <AvatarFallback>
                        {user.prenom?.[0]}{user.nom?.[0]}
                      </AvatarFallback>
                    </Avatar>
                    <div>
                      <div className="font-medium">{user.prenom} {user.nom}</div>
                      {user.poste && (
                        <div className="text-sm text-muted-foreground">{user.poste}</div>
                      )}
                    </div>
                  </TableCell>
                  <TableCell>{user.email}</TableCell>
                  <TableCell>
                    {user.user_roles?.[0]?.roles.nom && (
                      <Badge variant="secondary">
                        {user.user_roles[0].roles.nom}
                      </Badge>
                    )}
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {user.profile_segments?.map((ps, index) => (
                        <Badge 
                          key={index} 
                          style={{ backgroundColor: ps.segments.couleur }}
                          className="text-white text-xs"
                        >
                          {ps.segments.nom}
                        </Badge>
                      ))}
                    </div>
                  </TableCell>
                  <TableCell>
                    {user.chef_hierarchique && (
                      <span className="text-sm">
                        {user.chef_hierarchique.prenom} {user.chef_hierarchique.nom}
                      </span>
                    )}
                  </TableCell>
                  <TableCell className="text-center">
                    <div className="flex items-center justify-center gap-2">
                      <Switch
                        checked={user.payroll_enabled ?? true}
                        onCheckedChange={(checked) => handlePayrollToggle(user.id, checked)}
                        disabled={loading}
                        className="data-[state=checked]:bg-green-600"
                      />
                      <span className="text-xs font-medium">
                        {user.payroll_enabled ?? true ? (
                          <span className="text-green-600">Activé</span>
                        ) : (
                          <span className="text-red-600">Désactivé</span>
                        )}
                      </span>
                    </div>
                  </TableCell>
                  <TableCell className="text-center">
                    <div className="flex items-center justify-center gap-2">
                      <Switch
                        checked={user.account_status !== 'suspended'}
                        onCheckedChange={(checked) => handleAccountStatusToggle(user.id, user.account_status || 'active')}
                        disabled={loading}
                        className="data-[state=checked]:bg-green-600"
                      />
                      <span className="text-xs font-medium">
                        {user.account_status === 'suspended' ? (
                          <span className="text-red-600">Suspendu</span>
                        ) : (
                          <span className="text-green-600">Actif</span>
                        )}
                      </span>
                    </div>
                  </TableCell>
                  <TableCell className="text-right">
                    <div className="flex justify-end gap-1">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => window.location.href = `/administration/employee/${user.id}`}
                        title="Voir le dossier complet"
                      >
                        <Eye className="h-4 w-4" />
                      </Button>
                       <Button
                         variant="ghost"
                         size="sm"
                         onClick={() => openEditDialog(user)}
                       >
                         <Edit className="h-4 w-4" />
                       </Button>
                      
                      <AlertDialog>
                        <AlertDialogTrigger asChild>
                          <Button variant="ghost" size="sm">
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </AlertDialogTrigger>
                        <AlertDialogContent>
                          <AlertDialogHeader>
                            <AlertDialogTitle>Supprimer l'utilisateur</AlertDialogTitle>
                            <AlertDialogDescription>
                              Êtes-vous sûr de vouloir supprimer {user.prenom} {user.nom} ? 
                              Cette action est irréversible.
                            </AlertDialogDescription>
                          </AlertDialogHeader>
                          <AlertDialogFooter>
                            <AlertDialogCancel>Annuler</AlertDialogCancel>
                            <AlertDialogAction 
                              onClick={() => handleDelete(user.id, user.user_id)}
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
              {filteredUsers.length === 0 && (
                <TableRow>
                  <TableCell colSpan={6} className="text-center py-8 text-muted-foreground">
                    Aucun utilisateur trouvé
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
};

export default UserManagement;