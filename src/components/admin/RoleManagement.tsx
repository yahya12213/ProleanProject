import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger } from "@/components/ui/alert-dialog";
import { Checkbox } from "@/components/ui/checkbox";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks/use-toast";
import { Shield, Plus, Edit, Trash2, Users, Key, Check, X, Search } from "lucide-react";
import { supabase } from "@/integrations/supabase/client";

interface Permission {
  id: string;
  nom: string;
  description: string;
  module: string;
}

interface Role {
  id: string;
  nom: string;
  description?: string;
  permissions: Permission[];
  type?: 'system' | 'custom';
}

const RoleManagement = () => {
  const [roles, setRoles] = useState<Role[]>([]);
  const [permissions, setPermissions] = useState<Permission[]>([]);
  const [loading, setLoading] = useState(true);
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [editingRole, setEditingRole] = useState<Role | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const { toast } = useToast();

  // Form state
  const [formData, setFormData] = useState({
    nom: "",
    description: "",
    selectedPermissions: [] as string[]
  });

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      await Promise.all([loadRoles(), loadPermissions()]);
    } catch (error) {
      toast({
        title: "Erreur",
        description: "Impossible de charger les données",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const loadRoles = async () => {
    const { data: rolesData, error: rolesError } = await supabase
      .from('roles')
      .select(`
        id,
        nom,
        description,
        type,
        role_permissions(
          permission_id,
          permissions(
            id,
            nom,
            description,
            module
          )
        )
      `);

    if (rolesError) {
      throw rolesError;
    }

    const rolesWithPermissions = rolesData?.map(role => ({
      id: role.id,
      nom: role.nom,
      description: role.description,
      type: role.type,
      permissions: role.role_permissions?.map((rp: any) => rp.permissions) || []
    })) || [];

    setRoles(rolesWithPermissions);
  };

  const loadPermissions = async () => {
    const { data: permissionsData, error: permissionsError } = await supabase
      .from('permissions')
      .select('*')
      .order('module', { ascending: true })
      .order('nom', { ascending: true });

    if (permissionsError) {
      throw permissionsError;
    }

    setPermissions(permissionsData || []);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!formData.nom.trim()) {
      toast({
        title: "Erreur",
        description: "Le nom du rôle est requis",
        variant: "destructive",
      });
      return;
    }

    try {
      if (editingRole) {
        // Modifier un rôle existant
        const { error: updateError } = await supabase
          .from('roles')
          .update({
            nom: formData.nom,
            description: formData.description
          })
          .eq('id', editingRole.id);

        if (updateError) throw updateError;

        // Supprimer les anciennes permissions
        const { error: deletePermError } = await supabase
          .from('role_permissions')
          .delete()
          .eq('role_id', editingRole.id);

        if (deletePermError) throw deletePermError;

        // Ajouter les nouvelles permissions
        if (formData.selectedPermissions.length > 0) {
          const rolePermissions = formData.selectedPermissions.map(permissionId => ({
            role_id: editingRole.id,
            permission_id: permissionId
          }));

          const { error: insertPermError } = await supabase
            .from('role_permissions')
            .insert(rolePermissions);

          if (insertPermError) throw insertPermError;
        }

        toast({
          title: "Succès",
          description: "Rôle modifié avec succès",
        });
      } else {
        // Créer un nouveau rôle
        const { data: newRole, error: insertError } = await supabase
          .from('roles')
          .insert({
            nom: formData.nom,
            description: formData.description,
            type: 'custom'
          })
          .select()
          .single();

        if (insertError) throw insertError;

        // Ajouter les permissions au nouveau rôle
        if (formData.selectedPermissions.length > 0) {
          const rolePermissions = formData.selectedPermissions.map(permissionId => ({
            role_id: newRole.id,
            permission_id: permissionId
          }));

          const { error: insertPermError } = await supabase
            .from('role_permissions')
            .insert(rolePermissions);

          if (insertPermError) throw insertPermError;
        }

        toast({
          title: "Succès",
          description: "Rôle créé avec succès",
        });
      }

      await loadRoles();
      resetForm();
      setIsDialogOpen(false);
    } catch (error) {
      toast({
        title: "Erreur",
        description: "Une erreur est survenue lors de l'opération",
        variant: "destructive",
      });
    }
  };

  const handleDelete = async (roleId: string) => {
    try {
      const { error } = await supabase
        .from('roles')
        .delete()
        .eq('id', roleId);

      if (error) throw error;

      toast({
        title: "Succès",
        description: "Rôle supprimé avec succès",
      });

      await loadRoles();
    } catch (error) {
      toast({
        title: "Erreur",
        description: "Impossible de supprimer le rôle",
        variant: "destructive",
      });
    }
  };

  const resetForm = () => {
    setFormData({
      nom: "",
      description: "",
      selectedPermissions: []
    });
    setEditingRole(null);
  };

  const openEditDialog = (role: Role) => {
    setEditingRole(role);
    setFormData({
      nom: role.nom,
      description: role.description || "",
      selectedPermissions: role.permissions.map(p => p.id)
    });
    setIsDialogOpen(true);
  };

  // Grouper les permissions par module
  const groupedPermissions = permissions.reduce((acc, permission) => {
    if (!acc[permission.module]) {
      acc[permission.module] = [];
    }
    acc[permission.module].push(permission);
    return acc;
  }, {} as Record<string, Permission[]>);

  // Filtrer les permissions selon le terme de recherche
  const filteredGroupedPermissions = Object.entries(groupedPermissions).reduce((acc, [module, perms]) => {
    const filteredPerms = perms.filter(p => 
      p.nom.toLowerCase().includes(searchTerm.toLowerCase()) ||
      p.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
      module.toLowerCase().includes(searchTerm.toLowerCase())
    );
    if (filteredPerms.length > 0) {
      acc[module] = filteredPerms;
    }
    return acc;
  }, {} as Record<string, Permission[]>);

  // Fonctions pour la sélection en masse
  const handleSelectAllInModule = (module: string, checked: boolean) => {
    const modulePermissions = groupedPermissions[module] || [];
    const modulePermissionIds = modulePermissions.map(p => p.id);
    
    if (checked) {
      setFormData(prev => ({
        ...prev,
        selectedPermissions: [...new Set([...prev.selectedPermissions, ...modulePermissionIds])]
      }));
    } else {
      setFormData(prev => ({
        ...prev,
        selectedPermissions: prev.selectedPermissions.filter(id => !modulePermissionIds.includes(id))
      }));
    }
  };

  const handleSelectAll = (checked: boolean) => {
    if (checked) {
      setFormData(prev => ({
        ...prev,
        selectedPermissions: permissions.map(p => p.id)
      }));
    } else {
      setFormData(prev => ({
        ...prev,
        selectedPermissions: []
      }));
    }
  };

  const isModuleFullySelected = (module: string): boolean => {
    const modulePermissions = groupedPermissions[module] || [];
    return modulePermissions.every(p => formData.selectedPermissions.includes(p.id));
  };

  const isModulePartiallySelected = (module: string): boolean => {
    const modulePermissions = groupedPermissions[module] || [];
    const selectedInModule = modulePermissions.filter(p => formData.selectedPermissions.includes(p.id));
    return selectedInModule.length > 0 && selectedInModule.length < modulePermissions.length;
  };

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[400px]">
        <Shield className="h-16 w-16 text-muted-foreground mb-4" />
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary mb-4"></div>
        <p className="text-muted-foreground">Chargement des rôles et permissions...</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-3xl font-bold tracking-tight">Gestion des Rôles et Permissions</h2>
          <p className="text-muted-foreground">
            Configurez les rôles utilisateur et leurs permissions d'accès
          </p>
        </div>
        
        <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
          <DialogTrigger asChild>
            <Button onClick={resetForm}>
              <Plus className="mr-2 h-4 w-4" />
              Nouveau Rôle
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle>
                {editingRole ? 'Modifier le rôle' : 'Créer un nouveau rôle'}
              </DialogTitle>
              <DialogDescription>
                {editingRole 
                  ? 'Modifiez les informations et permissions du rôle'
                  : 'Définissez un nouveau rôle et attribuez-lui des permissions'
                }
              </DialogDescription>
            </DialogHeader>
            
            <form onSubmit={handleSubmit} className="space-y-6">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="role-name">Nom du rôle *</Label>
                  <Input
                    id="role-name"
                    value={formData.nom}
                    onChange={(e) => setFormData(prev => ({ ...prev, nom: e.target.value }))}
                    placeholder="Ex: Manager Commercial"
                    required
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="role-description">Description</Label>
                  <Textarea
                    id="role-description"
                    value={formData.description}
                    onChange={(e) => setFormData(prev => ({ ...prev, description: e.target.value }))}
                    placeholder="Décrivez le rôle et ses responsabilités..."
                    rows={3}
                  />
                </div>
              </div>

              <div className="space-y-4">
                <div className="flex justify-between items-center">
                  <Label className="text-base font-semibold">Permissions</Label>
                  <div className="flex items-center gap-4">
                    <div className="relative">
                      <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
                      <Input
                        placeholder="Rechercher des permissions..."
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                        className="pl-8 w-64"
                      />
                    </div>
                    <div className="flex items-center gap-2">
                      <Checkbox
                        id="select-all"
                        checked={formData.selectedPermissions.length === permissions.length}
                        onCheckedChange={handleSelectAll}
                      />
                      <Label htmlFor="select-all" className="text-sm">
                        Tout sélectionner ({formData.selectedPermissions.length}/{permissions.length})
                      </Label>
                    </div>
                  </div>
                </div>

                <div className="border rounded-lg max-h-96 overflow-y-auto">
                  {Object.entries(filteredGroupedPermissions).map(([module, modulePermissions]) => (
                    <div key={module} className="border-b last:border-b-0">
                      <div className="bg-muted/50 p-3 border-b">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <Checkbox
                              id={`module-${module}`}
                              checked={isModuleFullySelected(module)}
                              onCheckedChange={(checked) => handleSelectAllInModule(module, checked as boolean)}
                            />
                            <Label htmlFor={`module-${module}`} className="font-medium">
                              {module}
                            </Label>
                          </div>
                          <Badge variant="outline">
                            {modulePermissions.filter(p => formData.selectedPermissions.includes(p.id)).length}/{modulePermissions.length}
                          </Badge>
                        </div>
                      </div>
                      <div className="p-3 space-y-2">
                        {modulePermissions.map((permission) => (
                          <div key={permission.id} className="flex items-start gap-2">
                            <Checkbox
                              id={permission.id}
                              checked={formData.selectedPermissions.includes(permission.id)}
                              onCheckedChange={(checked) => {
                                if (checked) {
                                  setFormData(prev => ({
                                    ...prev,
                                    selectedPermissions: [...prev.selectedPermissions, permission.id]
                                  }));
                                } else {
                                  setFormData(prev => ({
                                    ...prev,
                                    selectedPermissions: prev.selectedPermissions.filter(id => id !== permission.id)
                                  }));
                                }
                              }}
                            />
                            <div className="flex-1 min-w-0">
                              <Label htmlFor={permission.id} className="text-sm font-medium cursor-pointer">
                                {permission.nom}
                              </Label>
                              <p className="text-xs text-muted-foreground mt-1">
                                {permission.description}
                              </p>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <DialogFooter>
                <Button type="button" variant="outline" onClick={() => setIsDialogOpen(false)}>
                  Annuler
                </Button>
                <Button type="submit">
                  {editingRole ? 'Modifier' : 'Créer'}
                </Button>
              </DialogFooter>
            </form>
          </DialogContent>
        </Dialog>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Rôles Configurés</CardTitle>
          <CardDescription>
            Liste des rôles existants et leurs permissions associées
          </CardDescription>
        </CardHeader>
        <CardContent>
          {roles.length === 0 ? (
            <div className="text-center py-8">
              <Shield className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
              <p className="text-muted-foreground">Aucun rôle configuré</p>
              <p className="text-sm text-muted-foreground">Créez votre premier rôle pour commencer</p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Nom du Rôle</TableHead>
                  <TableHead>Description</TableHead>
                  <TableHead>Permissions</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {roles.map((role) => (
                  <TableRow key={role.id}>
                    <TableCell className="font-medium">
                      {role.nom}
                      {role.type === 'system' && (
                        <Badge variant="secondary" className="ml-2 text-xs">
                          Système
                        </Badge>
                      )}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {role.description || 'Aucune description'}
                    </TableCell>
                    <TableCell className="text-sm">
                      {role.permissions.length > 3 
                        ? `${role.permissions.slice(0, 3).map(p => p.nom).join(', ')}...` 
                        : role.permissions.map(p => p.nom).join(', ')
                      }
                      <div className="text-xs text-muted-foreground mt-1">
                        {role.permissions.length} permission(s)
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex gap-2 justify-end">
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => openEditDialog(role)}
                          disabled={role.type === 'system'}
                        >
                          <Edit className="h-4 w-4" />
                        </Button>
                        <AlertDialog>
                          <AlertDialogTrigger asChild>
                            <Button 
                              variant="outline" 
                              size="sm"
                              disabled={role.type === 'system'}
                            >
                              <Trash2 className="h-4 w-4" />
                            </Button>
                          </AlertDialogTrigger>
                          <AlertDialogContent>
                            <AlertDialogHeader>
                              <AlertDialogTitle>Supprimer le rôle</AlertDialogTitle>
                              <AlertDialogDescription>
                                Êtes-vous sûr de vouloir supprimer le rôle "{role.nom}" ? Cette action est irréversible.
                              </AlertDialogDescription>
                            </AlertDialogHeader>
                            <AlertDialogFooter>
                              <AlertDialogCancel>Annuler</AlertDialogCancel>
                              <AlertDialogAction
                                onClick={() => handleDelete(role.id)}
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
          )}
        </CardContent>
      </Card>
    </div>
  );
};

export default RoleManagement;