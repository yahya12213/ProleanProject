import React, { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { ArrowLeft, Users, Calendar } from 'lucide-react';
import { supabase } from '@/integrations/supabase/client';
import { useToast } from '@/hooks/use-toast';

interface CorpsFormation {
  id: string;
  nom: string;
  description?: string;
}

interface GroupeClasse {
  id: string;
  nom: string;
  description?: string;
  corps_formation_id: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
  _count?: {
    classes: number;
  };
}

interface Classe {
  id: string;
  nom_classe: string;
  date_debut: string;
  date_fin: string;
  nombre_places: number;
  statut: string;
}

interface GroupesClassesManagementProps {
  corpsFormation: CorpsFormation;
  onBack: () => void;
}

export function GroupesClassesManagement({ corpsFormation, onBack }: GroupesClassesManagementProps) {
  const { toast } = useToast();
  const [groupes, setGroupes] = useState<GroupeClasse[]>([]);
  const [classes, setClasses] = useState<Classe[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedGroupe, setSelectedGroupe] = useState<string | null>(null);

  useEffect(() => {
    loadData();
  }, [corpsFormation.id]);

  const loadData = async () => {
    try {
      // Charger le groupe de classes pour ce corps de formation
      const { data: groupeData, error: groupeError } = await supabase
        .from('groupes_classes')
        .select('*')
        .eq('corps_formation_id', corpsFormation.id)
        .eq('is_active', true);

      if (groupeError) throw groupeError;

      if (groupeData && groupeData.length > 0) {
        const groupe = groupeData[0];
        
        // Charger les classes de ce groupe
        const { data: classesData, error: classesError } = await supabase
          .from('classes')
          .select('*')
          .eq('groupe_classe_id', groupe.id)
          .eq('is_active', true)
          .order('date_debut', { ascending: false });

        if (classesError) throw classesError;

        setGroupes([{
          ...groupe,
          _count: { classes: classesData?.length || 0 }
        }]);
        setClasses(classesData || []);
      } else {
        setGroupes([]);
        setClasses([]);
      }
    } catch (error) {
      console.error('Erreur lors du chargement des données:', error);
      toast({
        title: "Erreur",
        description: "Impossible de charger les données",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const getStatutColor = (statut: string) => {
    switch (statut) {
      case 'programmee': return 'bg-blue-100 text-blue-800';
      case 'en_cours': return 'bg-yellow-100 text-yellow-800';
      case 'terminee': return 'bg-green-100 text-green-800';
      case 'annulee': return 'bg-red-100 text-red-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  const getStatutLabel = (statut: string) => {
    switch (statut) {
      case 'programmee': return 'Programmée';
      case 'en_cours': return 'En cours';
      case 'terminee': return 'Terminée';
      case 'annulee': return 'Annulée';
      default: return 'Inconnue';
    }
  };

  if (loading) {
    return <div className="flex justify-center items-center h-64">Chargement...</div>;
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-4">
        <Button variant="outline" onClick={onBack}>
          <ArrowLeft className="h-4 w-4 mr-2" />
          Retour
        </Button>
        <div>
          <h2 className="text-2xl font-bold">Groupe de Classes - {corpsFormation.nom}</h2>
          <p className="text-muted-foreground">
            Gestion du groupe de classes associé au corps de formation
          </p>
        </div>
      </div>

      {/* Informations du groupe */}
      {groupes.length > 0 ? (
        <div className="space-y-6">
          <div className="bg-muted/50 p-4 rounded-lg">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-lg font-semibold">{groupes[0].nom}</h3>
                <p className="text-sm text-muted-foreground">{groupes[0].description}</p>
                <div className="flex items-center gap-4 mt-2">
                  <div className="flex items-center gap-1">
                    <Users className="h-4 w-4" />
                    <span className="text-sm">{groupes[0]._count?.classes || 0} classe(s)</span>
                  </div>
                  <div className="flex items-center gap-1">
                    <Calendar className="h-4 w-4" />
                    <span className="text-sm">
                      Créé le {new Date(groupes[0].created_at).toLocaleDateString()}
                    </span>
                  </div>
                </div>
              </div>
              <Badge variant="outline" className="bg-green-50 text-green-700">
                Actif
              </Badge>
            </div>
          </div>

          {/* Liste des classes du groupe */}
          <div className="space-y-4">
            <h3 className="text-lg font-semibold">Classes du groupe</h3>
            
            {classes.length > 0 ? (
              <div className="border rounded-lg">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Nom de la classe</TableHead>
                      <TableHead>Date début</TableHead>
                      <TableHead>Date fin</TableHead>
                      <TableHead>Places</TableHead>
                      <TableHead>Statut</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {classes.map((classe) => (
                      <TableRow key={classe.id}>
                        <TableCell className="font-medium">{classe.nom_classe}</TableCell>
                        <TableCell>{new Date(classe.date_debut).toLocaleDateString()}</TableCell>
                        <TableCell>{new Date(classe.date_fin).toLocaleDateString()}</TableCell>
                        <TableCell>{classe.nombre_places}</TableCell>
                        <TableCell>
                          <Badge className={getStatutColor(classe.statut)}>
                            {getStatutLabel(classe.statut)}
                          </Badge>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            ) : (
              <div className="text-center py-8 text-muted-foreground">
                <Users className="h-12 w-12 mx-auto mb-4 opacity-50" />
                <p>Aucune classe n'est encore associée à ce groupe.</p>
                <p className="text-sm">
                  Les classes peuvent être ajoutées via la gestion des classes.
                </p>
              </div>
            )}
          </div>
        </div>
      ) : (
        <div className="text-center py-8 text-muted-foreground">
          <Users className="h-12 w-12 mx-auto mb-4 opacity-50" />
          <p>Aucun groupe de classes trouvé pour ce corps de formation.</p>
          <p className="text-sm">
            Le groupe sera créé automatiquement lors de la création du corps de formation.
          </p>
        </div>
      )}
    </div>
  );
}