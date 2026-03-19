import React, { useState, useEffect } from 'react';
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useToast } from "@/hooks/use-toast";
import { Users, MapPin, Building2, ChevronRight, ArrowLeft, ArrowRight, Search, User, UserCheck, Settings2, ChevronLeft } from 'lucide-react';
import { cn } from "@/lib/utils";
// Supabase supprimé, toute la logique doit passer par l'API Express locale

interface Segment {
  id: string;
  nom: string;
  couleur: string;
  logo_url: string | null;
}

interface Profile {
  id: string;
  nom: string;
  prenom: string;
  email: string;
  photo_url: string | null;
  user_id: string;
}

interface Role {
  id: string;
  nom: string;
  description: string | null;
}

interface UserRole {
  user_id: string;
  role_id: string;
  roles: Role;
}

interface ProfileWithRole extends Profile {
  user_roles: UserRole[];
}

interface Ville {
  id: string;
  nom_ville: string;
  code_ville: string;
  segment_id: string;
  segments: Segment;
}

interface VilleAssignment {
  id: string;
  user_id: string;
  ville_id: string;
  assigned_by: string;
  assigned_at: string;
  is_active: boolean;
  profiles: Profile;
  villes: Ville;
}

type Step = 'segment' | 'user-filter' | 'user-select' | 'ville-assignment';

const VilleAssignment = () => {
  // State for steps and navigation
  const [currentStep, setCurrentStep] = useState<Step>('segment');
  const [selectedSegment, setSelectedSegment] = useState<Segment | null>(null);
  const [selectedUser, setSelectedUser] = useState<ProfileWithRole | null>(null);
  
  // Data state
  const [segments, setSegments] = useState<Segment[]>([]);
  const [profiles, setProfiles] = useState<ProfileWithRole[]>([]);
  const [roles, setRoles] = useState<Role[]>([]);
  const [villes, setVilles] = useState<Ville[]>([]);
  const [assignments, setAssignments] = useState<VilleAssignment[]>([]);
  
  // Filter state
  const [roleFilter, setRoleFilter] = useState<string>('all');
  const [searchFilter, setSearchFilter] = useState<string>('');
  
  // Loading state
  const [loading, setLoading] = useState(true);
  
  const { toast } = useToast();

  useEffect(() => {
    loadInitialData();
  }, []);

  useEffect(() => {
    if (selectedSegment) {
      loadSegmentVilles();
    }
  }, [selectedSegment]);

  const loadInitialData = async () => {
    try {
      setLoading(true);
      
      // Load segments
  // TODO: Remplacer par appel API Express ou mock
        .from('segments')
        .select('*')
        .order('nom');
      
      if (segmentsError) throw segmentsError;
      
      // Load profiles with roles - separate queries to avoid complex joins
  // TODO: Remplacer par appel API Express ou mock
        .from('profiles')
        .select('*')
        .order('nom', { ascending: true });
      
      if (profilesError) throw profilesError;
      
      // Load user roles
  // TODO: Remplacer par appel API Express ou mock
        .from('user_roles')
        .select(`
          user_id,
          role_id,
          roles(*)
        `);
      
      if (userRolesError) throw userRolesError;
      
      // Load roles
  // TODO: Remplacer par appel API Express ou mock
        .from('roles')
        .select('*')
        .order('nom');
      
      if (rolesError) throw rolesError;
      
      // Combine profiles with their roles
      const profilesWithRoles: ProfileWithRole[] = (profilesData || []).map(profile => ({
        ...profile,
        user_roles: (userRolesData || []).filter(ur => ur.user_id === profile.user_id)
      }));
      
      setSegments(segmentsData || []);
      setProfiles(profilesWithRoles);
      setRoles(rolesData || []);
      
    } catch (error) {
      console.error('Error loading initial data:', error);
      toast({
        title: "Erreur",
        description: "Impossible de charger les données initiales",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const loadSegmentVilles = async () => {
    if (!selectedSegment) return;
    
    try {
      // Load villes for selected segment
  // TODO: Remplacer par appel API Express ou mock
        .from('villes')
        .select(`
          *,
          segments(*)
        `)
        .eq('segment_id', selectedSegment.id)
        .order('nom_ville');
      
      if (villesError) throw villesError;
      
      // Load assignments for these villes - separate queries to avoid join issues
  // TODO: Remplacer par appel API Express ou mock
        .from('ville_assignments')
        .select('*')
        .eq('is_active', true)
        .in('ville_id', villesData?.map(v => v.id) || []);
      
      if (assignmentsError) throw assignmentsError;
      
      // Load profiles for assignments
      const userIds = assignmentsRaw?.map(a => a.user_id) || [];
  // TODO: Remplacer par appel API Express ou mock
        .from('profiles')
        .select('*')
        .in('user_id', userIds);
      
      if (profilesError) throw profilesError;
      
      // Combine assignments with profiles and villes
      const enrichedAssignments: VilleAssignment[] = (assignmentsRaw || []).map(assignment => ({
        ...assignment,
        profiles: (profilesData || []).find(p => p.user_id === assignment.user_id)!,
        villes: (villesData || []).find(v => v.id === assignment.ville_id)!
      })).filter(a => a.profiles && a.villes);
      
      setVilles(villesData || []);
      setAssignments(enrichedAssignments);
      
    } catch (error) {
      console.error('Error loading segment data:', error);
      toast({
        title: "Erreur",
        description: "Impossible de charger les données du segment",
        variant: "destructive"
      });
    }
  };

  const handleSegmentSelect = (segment: Segment) => {
    setSelectedSegment(segment);
    setCurrentStep('user-filter');
  };

  const handleUserSelect = (user: ProfileWithRole) => {
    setSelectedUser(user);
    setCurrentStep('ville-assignment');
  };

  const handleAssignVille = async (villeId: string, userId: string) => {
    try {
      // Check if user is already assigned to this ville
      const existingAssignment = assignments.find(a => 
        a.ville_id === villeId && 
        a.user_id === userId && 
        a.is_active
      );
      
      if (existingAssignment) {
        toast({
          title: "Affectation existante",
          description: "Cette personne est déjà affectée à cette ville",
          variant: "destructive"
        });
        return;
      }
      
      // Create new assignment (allowing multiple users per ville)
  // TODO: Remplacer par appel API Express ou mock
        .from('ville_assignments')
        .insert({
          user_id: userId,
          ville_id: villeId,
          assigned_by: userId, // In a real app, this would be the current user's ID
          is_active: true
        })
        .select('*')
        .single();
      
      if (error) throw error;
      
      // Get the profile and ville info for local state update
      const profile = profiles.find(p => p.user_id === userId);
      const ville = villes.find(v => v.id === villeId);
      
      if (profile && ville && newAssignment) {
        const enrichedAssignment: VilleAssignment = {
          ...newAssignment,
          profiles: profile,
          villes: ville
        };
        
        // Update local state - add to existing assignments without removing others
        setAssignments(prev => [...prev, enrichedAssignment]);
      }
      
      toast({
        title: "Succès",
        description: "Ville assignée avec succès",
      });
      
    } catch (error) {
      console.error('Error assigning ville:', error);
      toast({
        title: "Erreur",
        description: "Impossible d'assigner la ville",
        variant: "destructive"
      });
    }
  };

  const handleUnassignVille = async (villeId: string) => {
    try {
      const assignment = assignments.find(a => a.ville_id === villeId && a.is_active);
      if (!assignment) return;
      
  // TODO: Remplacer par appel API Express ou mock
        .from('ville_assignments')
        .update({ is_active: false })
        .eq('id', assignment.id);
      
      // Update local state
      setAssignments(prev => prev.filter(a => a.id !== assignment.id));
      
      toast({
        title: "Succès",
        description: "Assignation supprimée avec succès",
      });
      
    } catch (error) {
      console.error('Error unassigning ville:', error);
      toast({
        title: "Erreur",
        description: "Impossible de supprimer l'assignation",
        variant: "destructive"
      });
    }
  };

  const filteredProfiles = profiles.filter(profile => {
    const matchesRole = roleFilter === 'all' || 
      profile.user_roles.some(ur => ur.role_id === roleFilter);
    const matchesSearch = searchFilter === '' ||
      `${profile.prenom} ${profile.nom} ${profile.email}`.toLowerCase().includes(searchFilter.toLowerCase());
    
    return matchesRole && matchesSearch;
  });

  const getAssignedUser = (villeId: string) => {
    const assignment = assignments.find(a => a.ville_id === villeId && a.is_active);
    return assignment?.profiles || null;
  };

  const getUserAssignmentCount = (userId: string) => {
    return assignments.filter(a => a.user_id === userId && a.is_active).length;
  };

  const renderStepIndicator = () => {
    const steps = [
      { key: 'segment', label: 'Segment', icon: Building2 },
      { key: 'user-filter', label: 'Filtrage', icon: Search },
      { key: 'user-select', label: 'Utilisateur', icon: User },
      { key: 'ville-assignment', label: 'Affectation', icon: MapPin }
    ];

    const currentIndex = steps.findIndex(s => s.key === currentStep);

    return (
      <div className="flex items-center justify-between mb-6 p-4 bg-muted/50 rounded-lg">
        {steps.map((step, index) => {
          const Icon = step.icon;
          const isActive = step.key === currentStep;
          const isCompleted = index < currentIndex;
          
          return (
            <div key={step.key} className="flex items-center">
              <div className={cn(
                "flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium",
                isActive && "bg-primary text-primary-foreground",
                isCompleted && "bg-green-100 text-green-700",
                !isActive && !isCompleted && "text-muted-foreground"
              )}>
                <Icon className="h-4 w-4" />
                {step.label}
              </div>
              {index < steps.length - 1 && (
                <ChevronRight className="h-4 w-4 mx-2 text-muted-foreground" />
              )}
            </div>
          );
        })}
      </div>
    );
  };

  const renderSegmentSelection = () => (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-semibold mb-2">Sélectionnez un segment</h3>
        <p className="text-sm text-muted-foreground">
          Choisissez le segment pour lequel vous souhaitez gérer les affectations de villes.
        </p>
      </div>
      
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {segments.map((segment) => (
          <Card 
            key={segment.id} 
            className="cursor-pointer hover:shadow-md transition-shadow"
            onClick={() => handleSegmentSelect(segment)}
          >
            <CardContent className="p-6">
              <div className="flex items-center gap-3">
                <div 
                  className="w-12 h-12 rounded-lg flex items-center justify-center"
                  style={{ backgroundColor: segment.couleur + '20' }}
                >
                  {segment.logo_url ? (
                    <img 
                      src={segment.logo_url} 
                      alt={segment.nom}
                      className="w-8 h-8 object-contain"
                    />
                  ) : (
                    <Building2 
                      className="h-6 w-6" 
                      style={{ color: segment.couleur }}
                    />
                  )}
                </div>
                <div className="flex-1">
                  <h4 className="font-medium">{segment.nom}</h4>
                  <p className="text-sm text-muted-foreground">
                    {villes.filter(v => v.segment_id === segment.id).length} villes
                  </p>
                </div>
                <ChevronRight className="h-5 w-5 text-muted-foreground" />
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );

  const renderUserFilter = () => (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-semibold mb-2">Filtrer les utilisateurs</h3>
          <p className="text-sm text-muted-foreground">
            Segment sélectionné: <Badge variant="secondary">{selectedSegment?.nom}</Badge>
          </p>
        </div>
        <Button 
          variant="outline" 
          onClick={() => setCurrentStep('segment')}
          className="gap-2"
        >
          <ArrowLeft className="h-4 w-4" />
          Retour
        </Button>
      </div>

      <div className="flex gap-4">
        <div className="flex-1">
          <Select value={roleFilter} onValueChange={setRoleFilter}>
            <SelectTrigger>
              <SelectValue placeholder="Filtrer par rôle" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">Tous les rôles</SelectItem>
              {roles.map((role) => (
                <SelectItem key={role.id} value={role.id}>
                  {role.nom}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="flex-1">
          <Input
            placeholder="Rechercher par nom ou email..."
            value={searchFilter}
            onChange={(e) => setSearchFilter(e.target.value)}
            className="w-full"
          />
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {filteredProfiles.map((profile) => (
          <Card 
            key={profile.id}
            className="cursor-pointer hover:shadow-md transition-shadow"
            onClick={() => handleUserSelect(profile)}
          >
            <CardContent className="p-4">
              <div className="flex items-center gap-3">
                <Avatar className="h-10 w-10">
                  <AvatarImage src={profile.photo_url || ''} />
                  <AvatarFallback>
                    {profile.prenom?.[0]}{profile.nom?.[0]}
                  </AvatarFallback>
                </Avatar>
                <div className="flex-1 min-w-0">
                  <h4 className="font-medium truncate">
                    {profile.prenom} {profile.nom}
                  </h4>
                  <p className="text-sm text-muted-foreground truncate">
                    {profile.email}
                  </p>
                  <div className="flex items-center gap-2 mt-1">
                    {profile.user_roles.map((ur) => (
                      <Badge key={ur.role_id} variant="outline" className="text-xs">
                        {ur.roles.nom}
                      </Badge>
                    ))}
                  </div>
                  <p className="text-xs text-muted-foreground mt-1">
                    {getUserAssignmentCount(profile.user_id)} villes assignées
                  </p>
                </div>
                <ChevronRight className="h-5 w-5 text-muted-foreground" />
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {filteredProfiles.length === 0 && (
        <div className="text-center py-8 text-muted-foreground">
          Aucun utilisateur trouvé avec ces critères de recherche.
        </div>
      )}
    </div>
  );

  const renderVilleAssignment = () => (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-semibold mb-2">Gestion des affectations</h3>
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <span>Segment:</span>
            <Badge variant="secondary">{selectedSegment?.nom}</Badge>
            <span>•</span>
            <span>Utilisateur:</span>
            <Badge variant="secondary">{selectedUser?.prenom} {selectedUser?.nom}</Badge>
          </div>
        </div>
        <Button 
          variant="outline" 
          onClick={() => setCurrentStep('user-filter')}
          className="gap-2"
        >
          <ArrowLeft className="h-4 w-4" />
          Retour
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <MapPin className="h-5 w-5" />
            Villes du segment {selectedSegment?.nom}
            <Badge variant="secondary">{villes.length} villes</Badge>
          </CardTitle>
          <CardDescription>
            Cliquez sur "Assigner" pour affecter une ville à {selectedUser?.prenom} {selectedUser?.nom}, 
            ou sur "Réassigner" pour changer l'affectation d'une ville déjà assignée.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Ville</TableHead>
                <TableHead>Code</TableHead>
                <TableHead>Assignée à</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {villes.map((ville) => {
                const assignedUser = getAssignedUser(ville.id);
                const isAssignedToSelected = assignedUser?.user_id === selectedUser?.user_id;
                
                return (
                  <TableRow key={ville.id}>
                    <TableCell className="font-medium">{ville.nom_ville}</TableCell>
                    <TableCell>{ville.code_ville}</TableCell>
                    <TableCell>
                      {assignedUser ? (
                        <div className="flex items-center gap-2">
                          <Avatar className="h-6 w-6">
                            <AvatarImage src={assignedUser.photo_url || ''} />
                            <AvatarFallback className="text-xs">
                              {assignedUser.prenom?.[0]}{assignedUser.nom?.[0]}
                            </AvatarFallback>
                          </Avatar>
                          <span className="text-sm">
                            {assignedUser.prenom} {assignedUser.nom}
                          </span>
                          {isAssignedToSelected && (
                            <Badge variant="secondary" className="text-xs">Actuel</Badge>
                          )}
                        </div>
                      ) : (
                        <span className="text-sm text-muted-foreground italic">Non assignée</span>
                      )}
                    </TableCell>
                    <TableCell className="text-right">
                      {isAssignedToSelected ? (
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => handleUnassignVille(ville.id)}
                          className="gap-2"
                        >
                          Désassigner
                        </Button>
                      ) : (
                        <Button
                          variant={assignedUser ? "outline" : "default"}
                          size="sm"
                          onClick={() => handleAssignVille(ville.id, selectedUser!.user_id)}
                          className="gap-2"
                        >
                          {assignedUser ? "Réassigner" : "Assigner"}
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="text-center">
          <UserCheck className="h-12 w-12 mx-auto mb-4 text-muted-foreground animate-pulse" />
          <p className="text-muted-foreground">Chargement des données...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold mb-2">Affectation des Villes</h2>
        <p className="text-muted-foreground">
          Assignez un portefeuille de villes à chaque commercial selon leur segment d'activité.
        </p>
      </div>

      {renderStepIndicator()}

      {currentStep === 'segment' && renderSegmentSelection()}
      {currentStep === 'user-filter' && renderUserFilter()}
      {currentStep === 'ville-assignment' && renderVilleAssignment()}
    </div>
  );
};

export default VilleAssignment;