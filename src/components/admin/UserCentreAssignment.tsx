import React, { useState, useEffect } from 'react';
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { useToast } from "@/hooks/use-toast";
import { Building2, Search, Plus, Trash2, MapPin, Users, Mail, Phone } from 'lucide-react';
// Supabase supprimé, toute la logique doit passer par l'API Express locale

interface Ville {
  id: string;
  nom_ville: string;
  code_ville: string;
}

interface Profile {
  id: string;
  nom: string;
  prenom: string;
}

interface Centre {
  id: string;
  nom: string;
  adresse: string | null;
  telephone: string | null;
  email: string | null;
  capacite: number | null;
  equipements: string[] | null;
  ville_id: string | null;
  is_active: boolean;
  villes?: Ville;
  assignedUsers: Profile[];
}

interface CentreAssignment {
  id: string;
  user_id: string;
  centre_id: string;
  assigned_by: string;
  assigned_at: string;
  is_active: boolean;
  centres: Omit<Centre, 'assignedUsers'>;
}

interface UserCentreAssignmentProps {
  userId: string;
}

export const UserCentreAssignment: React.FC<UserCentreAssignmentProps> = ({ userId }) => {
  const [centres, setCentres] = useState<Centre[]>([]);
  const [assignments, setAssignments] = useState<CentreAssignment[]>([]);
  const [userVilles, setUserVilles] = useState<string[]>([]);
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
      const userProfileId = "1";
      setProfileId(userProfileId);

      // Données par défaut pour les villes
      const userVilleIds = ["ville1"];
      setUserVilles(userVilleIds);

      // Données par défaut pour les centres
      const centresData: Centre[] = [
        {
          id: "centre1",
          nom: "Centre Formation Paris",
          adresse: "123 Rue de la Formation, Paris",
          telephone: "01 23 45 67 89",
          email: "paris@formation.com",
          capacite: 50,
          equipements: ["Projecteur", "Wifi", "Climatisation"],
          ville_id: "ville1",
          is_active: true,
          assignedUsers: []
        },
        {
          id: "centre2",
          nom: "Centre Formation Lyon",
          adresse: "456 Avenue des Cours, Lyon",
          telephone: "04 56 78 90 12",
          email: "lyon@formation.com",
          capacite: 30,
          equipements: ["Tableaux", "Wifi"],
          ville_id: "ville1",
          is_active: true,
          assignedUsers: []
        }
      ];
      
      setCentres(centresData);

      // Données par défaut pour les assignments
      const userAssignments: CentreAssignment[] = [];
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

  const handleAssignCentre = async (centreId: string) => {
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
      const centre = centres.find(c => c.id === centreId);
      if (centre) {
        const newAssignment: CentreAssignment = {
          id: `assignment-${Date.now()}`,
          user_id: profileId,
          centre_id: centreId,
          assigned_by: "admin",
          assigned_at: new Date().toISOString(),
          is_active: true,
          centres: centre
        };
        
        setAssignments([...assignments, newAssignment]);
        
        toast({
          title: "Succès",
          description: "Centre assigné avec succès",
        });
      }
    } catch (error) {
      console.error('Error assigning centre:', error);
      toast({
        title: "Erreur",
        description: "Impossible d'assigner le centre",
        variant: "destructive",
      });
    }
  };

  const handleUnassignCentre = async (assignmentId: string) => {
    try {
      // TODO: Remplacer par appel à l'API Express locale
      // Pour l'instant, simulons la désassignation
      setAssignments(assignments.filter(a => a.id !== assignmentId));
      
      toast({
        title: "Succès",
        description: "Centre désassigné avec succès",
      });
    } catch (error) {
      console.error('Error unassigning centre:', error);
      toast({
        title: "Erreur",
        description: "Impossible de désassigner le centre",
        variant: "destructive",
      });
    }
  };

  const filteredCentres = centres.filter(centre => {
    const matchesSearch = centre.nom.toLowerCase().includes(searchFilter.toLowerCase()) ||
                         (centre.adresse && centre.adresse.toLowerCase().includes(searchFilter.toLowerCase()));
    return matchesSearch;
  });

  const assignedCentreIds = assignments.map(a => a.centre_id);

  if (loading) {
    return <div className="flex items-center justify-center p-8">Chargement...</div>;
  }

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Building2 className="h-5 w-5" />
            Affectations de Centres
          </CardTitle>
          <CardDescription>
            Gérer les centres assignés à cet utilisateur
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="mb-6">
            <div className="relative">
              <Search className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Rechercher un centre..."
                value={searchFilter}
                onChange={(e) => setSearchFilter(e.target.value)}
                className="pl-10"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Centres assignés */}
            <div>
              <h3 className="text-lg font-semibold mb-4">Centres assignés ({assignments.length})</h3>
              {assignments.length === 0 ? (
                <p className="text-muted-foreground">Aucun centre assigné</p>
              ) : (
                <div className="space-y-4">
                  {assignments.map((assignment) => (
                    <Card key={assignment.id} className="p-4">
                      <div className="flex items-start justify-between mb-3">
                        <div>
                          <h4 className="font-medium">{assignment.centres.nom}</h4>
                          <p className="text-sm text-muted-foreground flex items-center gap-1">
                            <MapPin className="h-3 w-3" />
                            Centre assigné
                          </p>
                        </div>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => handleUnassignCentre(assignment.id)}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                      <div className="space-y-2 text-sm">
                        {assignment.centres.adresse && (
                          <p className="text-muted-foreground">{assignment.centres.adresse}</p>
                        )}
                        <div className="flex items-center gap-4">
                          {assignment.centres.capacite && (
                            <span className="flex items-center gap-1">
                              <Users className="h-3 w-3" />
                              {assignment.centres.capacite} places
                            </span>
                          )}
                          {assignment.centres.telephone && (
                            <span className="flex items-center gap-1">
                              <Phone className="h-3 w-3" />
                              {assignment.centres.telephone}
                            </span>
                          )}
                        </div>
                        {assignment.centres.equipements && assignment.centres.equipements.length > 0 && (
                          <div className="flex flex-wrap gap-1">
                            {assignment.centres.equipements.map((equipement, index) => (
                              <Badge key={index} variant="secondary" className="text-xs">
                                {equipement}
                              </Badge>
                            ))}
                          </div>
                        )}
                      </div>
                    </Card>
                  ))}
                </div>
              )}
            </div>

            {/* Centres disponibles */}
            <div>
              <h3 className="text-lg font-semibold mb-4">Centres disponibles</h3>
              <div className="space-y-4 max-h-96 overflow-y-auto">
                {filteredCentres
                  .filter(centre => !assignedCentreIds.includes(centre.id))
                  .map((centre) => (
                    <Card key={centre.id} className="p-4">
                      <div className="flex items-start justify-between mb-3">
                        <div>
                          <h4 className="font-medium">{centre.nom}</h4>
                          <p className="text-sm text-muted-foreground flex items-center gap-1">
                            <MapPin className="h-3 w-3" />
                            Centre disponible
                          </p>
                        </div>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => handleAssignCentre(centre.id)}
                        >
                          <Plus className="h-4 w-4" />
                        </Button>
                      </div>
                      <div className="space-y-2 text-sm">
                        {centre.adresse && (
                          <p className="text-muted-foreground">{centre.adresse}</p>
                        )}
                        <div className="flex items-center gap-4">
                          {centre.capacite && (
                            <span className="flex items-center gap-1">
                              <Users className="h-3 w-3" />
                              {centre.capacite} places
                            </span>
                          )}
                          {centre.telephone && (
                            <span className="flex items-center gap-1">
                              <Phone className="h-3 w-3" />
                              {centre.telephone}
                            </span>
                          )}
                        </div>
                        {centre.equipements && centre.equipements.length > 0 && (
                          <div className="flex flex-wrap gap-1">
                            {centre.equipements.map((equipement, index) => (
                              <Badge key={index} variant="secondary" className="text-xs">
                                {equipement}
                              </Badge>
                            ))}
                          </div>
                        )}
                        {centre.assignedUsers.length > 0 && (
                          <div className="space-y-1">
                            <p className="text-xs text-muted-foreground">Utilisateurs assignés:</p>
                            <div className="flex flex-wrap gap-1">
                              {centre.assignedUsers.map((user) => (
                                <Badge key={user.id} variant="secondary" className="text-xs">
                                  {user.prenom} {user.nom}
                                </Badge>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    </Card>
                  ))}
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};
