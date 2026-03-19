import React, { useState, useEffect } from 'react';
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useToast } from "@/hooks/use-toast";
import { GraduationCap, Search, Plus, Trash2, Clock, Euro, TrendingUp } from 'lucide-react';
// Supabase supprimé, toute la logique doit passer par l'API Express locale

interface Centre {
  id: string;
  nom: string;
}

interface Profile {
  id: string;
  nom: string;
  prenom: string;
}

interface Formation {
  id: string;
  titre: string;
  description: string | null;
  duree_heures: number;
  niveau: string;
  prix: number | null;
  centre_id: string | null;
  is_active: boolean;
  centres?: Centre;
  assignedUsers: Profile[];
}

interface FormationAssignment {
  id: string;
  user_id: string;
  formation_id: string;
  assigned_by: string;
  assigned_at: string;
  is_active: boolean;
  formations: Omit<Formation, 'assignedUsers'>;
}

interface UserFormationAssignmentProps {
  userId: string;
}

const niveauColors = {
  'debutant': 'bg-green-500',
  'intermediaire': 'bg-yellow-500',
  'avance': 'bg-red-500',
  'expert': 'bg-purple-500'
};

const niveauLabels = {
  'debutant': 'Débutant',
  'intermediaire': 'Intermédiaire',
  'avance': 'Avancé',
  'expert': 'Expert'
};

export const UserFormationAssignment: React.FC<UserFormationAssignmentProps> = ({ userId }) => {
  const [formations, setFormations] = useState<Formation[]>([]);
  const [assignments, setAssignments] = useState<FormationAssignment[]>([]);
  const [userCentres, setUserCentres] = useState<string[]>([]);
  const [searchFilter, setSearchFilter] = useState<string>('');
  const [niveauFilter, setNiveauFilter] = useState<string>('all');
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

      // Données par défaut pour les centres
      const userCentreIds = ["centre1"];
      setUserCentres(userCentreIds);

      // Données par défaut pour les formations
      const formationsData: Formation[] = [
        {
          id: "formation1",
          titre: "Formation JavaScript",
          description: "Apprenez les bases de JavaScript",
          duree_heures: 40,
          niveau: "debutant",
          prix: 500,
          centre_id: "centre1",
          is_active: true,
          assignedUsers: []
        },
        {
          id: "formation2", 
          titre: "Formation React",
          description: "Développement avec React",
          duree_heures: 60,
          niveau: "intermediaire",
          prix: 800,
          centre_id: "centre1",
          is_active: true,
          assignedUsers: []
        }
      ];
      
      setFormations(formationsData);

      // Données par défaut pour les assignments
      const userAssignments: FormationAssignment[] = [];
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

  const handleAssignFormation = async (formationId: string) => {
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
      const formation = formations.find(f => f.id === formationId);
      if (formation) {
        const newAssignment: FormationAssignment = {
          id: `assignment-${Date.now()}`,
          user_id: profileId,
          formation_id: formationId,
          assigned_by: "admin",
          assigned_at: new Date().toISOString(),
          is_active: true,
          formations: formation
        };
        
        setAssignments([...assignments, newAssignment]);
        
        toast({
          title: "Succès",
          description: "Formation assignée avec succès",
        });
      }
    } catch (error) {
      console.error('Error assigning formation:', error);
      toast({
        title: "Erreur",
        description: "Impossible d'assigner la formation",
        variant: "destructive",
      });
    }
  };

  const handleUnassignFormation = async (assignmentId: string) => {
    try {
      // TODO: Remplacer par appel à l'API Express locale
      // Pour l'instant, simulons la désassignation
      setAssignments(assignments.filter(a => a.id !== assignmentId));
      
      toast({
        title: "Succès",
        description: "Formation désassignée avec succès",
      });
    } catch (error) {
      console.error('Error unassigning formation:', error);
      toast({
        title: "Erreur",
        description: "Impossible de désassigner la formation",
        variant: "destructive",
      });
    }
  };

  const filteredFormations = formations.filter(formation => {
    const matchesSearch = formation.titre.toLowerCase().includes(searchFilter.toLowerCase()) ||
                         (formation.description && formation.description.toLowerCase().includes(searchFilter.toLowerCase()));
    const matchesNiveau = niveauFilter === 'all' || formation.niveau === niveauFilter;
    return matchesSearch && matchesNiveau;
  });

  const assignedFormationIds = assignments.map(a => a.formation_id);

  if (loading) {
    return <div className="flex items-center justify-center p-8">Chargement...</div>;
  }

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <GraduationCap className="h-5 w-5" />
            Affectations de Formations
          </CardTitle>
          <CardDescription>
            Gérer les formations assignées à cet utilisateur
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex gap-4 mb-6">
            <div className="flex-1">
              <div className="relative">
                <Search className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Rechercher une formation..."
                  value={searchFilter}
                  onChange={(e) => setSearchFilter(e.target.value)}
                  className="pl-10"
                />
              </div>
            </div>
            <Select value={niveauFilter} onValueChange={setNiveauFilter}>
              <SelectTrigger className="w-48">
                <SelectValue placeholder="Filtrer par niveau" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">Tous les niveaux</SelectItem>
                <SelectItem value="debutant">Débutant</SelectItem>
                <SelectItem value="intermediaire">Intermédiaire</SelectItem>
                <SelectItem value="avance">Avancé</SelectItem>
                <SelectItem value="expert">Expert</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Formations assignées */}
            <div>
              <h3 className="text-lg font-semibold mb-4">Formations assignées ({assignments.length})</h3>
              {assignments.length === 0 ? (
                <p className="text-muted-foreground">Aucune formation assignée</p>
              ) : (
                <div className="space-y-4">
                  {assignments.map((assignment) => (
                    <Card key={assignment.id} className="p-4">
                      <div className="flex items-start justify-between mb-3">
                        <div className="flex-1">
                          <h4 className="font-medium">{assignment.formations.titre}</h4>
                          <p className="text-sm text-muted-foreground">
                            Formation assignée
                          </p>
                        </div>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => handleUnassignFormation(assignment.id)}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                      
                      <div className="space-y-2">
                        {assignment.formations.description && (
                          <p className="text-sm text-muted-foreground">
                            {assignment.formations.description}
                          </p>
                        )}
                        
                        <div className="flex items-center gap-4 text-sm">
                          <span className="flex items-center gap-1">
                            <Clock className="h-3 w-3" />
                            {assignment.formations.duree_heures}h
                          </span>
                          {assignment.formations.prix && (
                            <span className="flex items-center gap-1">
                              <Euro className="h-3 w-3" />
                              {assignment.formations.prix}€
                            </span>
                          )}
                        </div>
                        
                        <div className="flex items-center gap-2">
                          <Badge 
                            className={`${niveauColors[assignment.formations.niveau as keyof typeof niveauColors]} text-white`}
                          >
                            <TrendingUp className="h-3 w-3 mr-1" />
                            {niveauLabels[assignment.formations.niveau as keyof typeof niveauLabels]}
                          </Badge>
                        </div>
                      </div>
                    </Card>
                  ))}
                </div>
              )}
            </div>

            {/* Formations disponibles */}
            <div>
              <h3 className="text-lg font-semibold mb-4">Formations disponibles</h3>
              <div className="space-y-4 max-h-96 overflow-y-auto">
                {filteredFormations
                  .filter(formation => !assignedFormationIds.includes(formation.id))
                  .map((formation) => (
                    <Card key={formation.id} className="p-4">
                      <div className="flex items-start justify-between mb-3">
                        <div className="flex-1">
                          <h4 className="font-medium">{formation.titre}</h4>
                          <p className="text-sm text-muted-foreground">
                            Formation disponible
                          </p>
                        </div>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => handleAssignFormation(formation.id)}
                        >
                          <Plus className="h-4 w-4" />
                        </Button>
                      </div>
                      
                      <div className="space-y-2">
                        {formation.description && (
                          <p className="text-sm text-muted-foreground">
                            {formation.description}
                          </p>
                        )}
                        
                        <div className="flex items-center gap-4 text-sm">
                          <span className="flex items-center gap-1">
                            <Clock className="h-3 w-3" />
                            {formation.duree_heures}h
                          </span>
                          {formation.prix && (
                            <span className="flex items-center gap-1">
                              <Euro className="h-3 w-3" />
                              {formation.prix}€
                            </span>
                          )}
                        </div>
                        
                        <div className="flex items-center gap-2">
                          <Badge 
                            className={`${niveauColors[formation.niveau as keyof typeof niveauColors]} text-white`}
                          >
                            <TrendingUp className="h-3 w-3 mr-1" />
                            {niveauLabels[formation.niveau as keyof typeof niveauLabels]}
                          </Badge>
                        </div>
                        
                        {formation.assignedUsers.length > 0 && (
                          <div className="space-y-1">
                            <p className="text-xs text-muted-foreground">Utilisateurs assignés:</p>
                            <div className="flex flex-wrap gap-1">
                              {formation.assignedUsers.map((user) => (
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
