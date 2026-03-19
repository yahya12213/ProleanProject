import React, { useState, useEffect } from 'react';
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { useToast } from "@/hooks/use-toast";
import { MapPin, Search, Plus, Trash2 } from 'lucide-react';
// Supabase supprimé, toute la logique doit passer par l'API Express locale

interface Segment {
  id: string;
  nom: string;
  couleur: string;
  logo_url: string | null;
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
  villes: Ville;
}

interface Profile {
  id: string;
  nom: string;
  prenom: string;
}

interface VilleWithUsers extends Ville {
  assignedUsers: Profile[];
}

interface UserVilleAssignmentProps {
  userId: string;
}

export const UserVilleAssignment: React.FC<UserVilleAssignmentProps> = ({ userId }) => {
  const [segments, setSegments] = useState<Segment[]>([]);
  const [villes, setVilles] = useState<VilleWithUsers[]>([]);
  const [assignments, setAssignments] = useState<VilleAssignment[]>([]);
  const [userSegments, setUserSegments] = useState<string[]>([]);
  const [selectedSegment, setSelectedSegment] = useState<string>('all');
  const [searchFilter, setSearchFilter] = useState<string>('');
  const [loading, setLoading] = useState(true);
  const [profileId, setProfileId] = useState<string | null>(null);

  const { toast } = useToast();

  useEffect(() => {
    loadData();
  }, [userId]);

  const loadData = async () => {
    try {
      setLoading(true);

      // TODO: Remplacer par appels à l'API Express locale
      // Pour l'instant, utilisons des données par défaut
      
      // Segments par défaut
      const segmentsData: Segment[] = [
        {
          id: "segment1",
          nom: "Segment Professionnel",
          couleur: "#3B82F6",
          logo_url: null
        },
        {
          id: "segment2",
          nom: "Segment Formation",
          couleur: "#10B981",
          logo_url: null
        }
      ];
      setSegments(segmentsData);

      const userProfileId = "1";
      setProfileId(userProfileId);

      // Segments utilisateur par défaut
      const userSegmentIds = ["segment1", "segment2"];
      setUserSegments(userSegmentIds);

      // Villes par défaut
      const villesData: VilleWithUsers[] = [
        {
          id: "ville1",
          nom_ville: "Paris",
          code_ville: "75",
          segment_id: "segment1",
          segments: segmentsData[0],
          assignedUsers: []
        },
        {
          id: "ville2",
          nom_ville: "Lyon",
          code_ville: "69",
          segment_id: "segment2",
          segments: segmentsData[1],
          assignedUsers: []
        }
      ];
      
      setVilles(villesData);

      // Assignments par défaut
      const userAssignments: VilleAssignment[] = [];
      setAssignments(userAssignments);

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

  const handleAssignVille = async (villeId: string) => {
    try {
      // TODO: Remplacer par appel à l'API Express locale
      if (!profileId) {
        toast({
          title: "Erreur",
          description: "Utilisateur non authentifié",
          variant: "destructive",
        });
        return;
      }

      // Pour l'instant, simulons l'assignation
      const ville = villes.find(v => v.id === villeId);
      if (ville) {
        const newAssignment: VilleAssignment = {
          id: `assignment-${Date.now()}`,
          user_id: profileId,
          ville_id: villeId,
          assigned_by: "admin",
          assigned_at: new Date().toISOString(),
          is_active: true,
          villes: ville
        };
        
        setAssignments([...assignments, newAssignment]);
        
        toast({
          title: "Succès",
          description: "Ville assignée avec succès",
        });
      }
    } catch (error) {
      console.error('Error assigning ville:', error);
      toast({
        title: "Erreur",
        description: "Impossible d'assigner la ville",
        variant: "destructive",
      });
    }
  };

  const handleUnassignVille = async (assignmentId: string) => {
    try {
  // TODO: Remplacer par appel à l'API Express locale
        .from('ville_assignments')
        .update({ 
          is_active: false,
          updated_at: new Date().toISOString()
        })
        .eq('id', assignmentId);

      if (error) throw error;

      toast({
        title: "Succès",
        description: "Ville désassignée avec succès",
      });

      loadData();
    } catch (error) {
      console.error('Error unassigning ville:', error);
      toast({
        title: "Erreur",
        description: "Impossible de désassigner la ville",
        variant: "destructive",
      });
    }
  };

  const filteredVilles = villes.filter(ville => {
    const matchesSegment = selectedSegment === 'all' || ville.segment_id === selectedSegment;
    const matchesSearch = ville.nom_ville.toLowerCase().includes(searchFilter.toLowerCase()) ||
                         ville.code_ville.toLowerCase().includes(searchFilter.toLowerCase());
    return matchesSegment && matchesSearch;
  });

  const assignedVilleIds = assignments.map(a => a.ville_id);

  if (loading) {
    return <div className="flex items-center justify-center p-8">Chargement...</div>;
  }

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <MapPin className="h-5 w-5" />
            Affectations de Villes
          </CardTitle>
          <CardDescription>
            Gérer les villes assignées à cet utilisateur
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex gap-4 mb-6">
            <div className="flex-1">
              <div className="relative">
                <Search className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Rechercher une ville..."
                  value={searchFilter}
                  onChange={(e) => setSearchFilter(e.target.value)}
                  className="pl-10"
                />
              </div>
            </div>
            <Select value={selectedSegment} onValueChange={setSelectedSegment}>
              <SelectTrigger className="w-48">
                <SelectValue placeholder="Filtrer par segment" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">Segments autorisés</SelectItem>
                {segments
                  .filter(segment => userSegments.includes(segment.id))
                  .map((segment) => (
                    <SelectItem key={segment.id} value={segment.id}>
                      {segment.nom}
                    </SelectItem>
                  ))}
              </SelectContent>
            </Select>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Villes assignées */}
            <div>
              <h3 className="text-lg font-semibold mb-4">Villes assignées ({assignments.length})</h3>
              {assignments.length === 0 ? (
                <p className="text-muted-foreground">Aucune ville assignée</p>
              ) : (
                <div className="space-y-3">
                  {assignments.map((assignment) => {
                    const ville = villes.find(v => v.id === assignment.ville_id);
                    const assignedUsers = ville?.assignedUsers || [];
                    
                    return (
                      <div key={assignment.id} className="space-y-3 p-4 border rounded-lg bg-card">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-3">
                            <div>
                              <p className="font-medium">{assignment.villes.nom_ville}</p>
                              <p className="text-sm text-muted-foreground">
                                {assignment.villes.code_ville} • {assignment.villes.segments.nom}
                              </p>
                            </div>
                            <Badge style={{ backgroundColor: assignment.villes.segments.couleur }}>
                              {assignment.villes.segments.nom}
                            </Badge>
                          </div>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => handleUnassignVille(assignment.id)}
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </div>
                        
                        {/* Liste des utilisateurs assignés */}
                        <div className="space-y-2">
                          <p className="text-xs font-medium text-muted-foreground">
                            Utilisateurs assignés ({assignedUsers.length})
                          </p>
                          {assignedUsers.length > 0 ? (
                            <div className="flex flex-wrap gap-1">
                              {assignedUsers.map((user) => (
                                <Badge key={user.id} variant="secondary" className="text-xs">
                                  {user.prenom} {user.nom}
                                </Badge>
                              ))}
                            </div>
                          ) : (
                            <p className="text-xs text-muted-foreground italic">
                              Aucun utilisateur assigné
                            </p>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {/* Villes disponibles */}
            <div>
              <h3 className="text-lg font-semibold mb-4">Villes disponibles</h3>
              <div className="space-y-2 max-h-96 overflow-y-auto">
                  {filteredVilles
                    .filter(ville => !assignedVilleIds.includes(ville.id))
                    .map((ville) => (
                      <div key={ville.id} className="space-y-3 p-4 border rounded-lg bg-card">
                        <div className="flex items-start justify-between">
                          <div className="flex-1">
                            <div className="flex items-center gap-3 mb-2">
                              <div>
                                <p className="font-medium">{ville.nom_ville}</p>
                                <p className="text-sm text-muted-foreground">
                                  {ville.code_ville} • {ville.segments.nom}
                                </p>
                              </div>
                              <Badge style={{ backgroundColor: ville.segments.couleur }}>
                                {ville.segments.nom}
                              </Badge>
                            </div>
                            
                            {/* Liste des utilisateurs assignés - toujours visible */}
                            <div className="mt-3 space-y-2">
                              <p className="text-xs font-medium text-muted-foreground">
                                Utilisateurs assignés ({ville.assignedUsers.length})
                              </p>
                              {ville.assignedUsers.length > 0 ? (
                                <div className="flex flex-wrap gap-1">
                                  {ville.assignedUsers.map((user) => (
                                    <Badge key={user.id} variant="secondary" className="text-xs">
                                      {user.prenom} {user.nom}
                                    </Badge>
                                  ))}
                                </div>
                              ) : (
                                <p className="text-xs text-muted-foreground italic">
                                  Aucun utilisateur assigné
                                </p>
                              )}
                            </div>
                          </div>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => handleAssignVille(ville.id)}
                            className="ml-3"
                          >
                            <Plus className="h-4 w-4" />
                          </Button>
                        </div>
                      </div>
                    ))}
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};
