import React, { useState, useEffect } from 'react';
import { Calendar as CalendarIcon, User, Filter, CheckCircle } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
// Supabase supprimé, toute la logique doit passer par l'API Express locale
import { useToast } from '@/hooks/use-toast';
import { format, parseISO, startOfMonth, endOfMonth, addMonths, subMonths } from 'date-fns';
import { fr } from 'date-fns/locale';

interface ValidatedLeave {
  id: string;
  demandeur_id: string;
  demandeur_nom: string;
  demandeur_prenom: string;
  titre: string;
  description: string;
  date_debut: string;
  date_fin: string;
  type_demande: string;
  statut: string;
  date_approbation: string;
  approuve_par_nom?: string;
  approuve_par_prenom?: string;
}

interface Profile {
  id: string;
  nom: string;
  prenom: string;
  email: string;
}

const ValidatedLeavesCalendar: React.FC = () => {
  const [validatedLeaves, setValidatedLeaves] = useState<ValidatedLeave[]>([]);
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedMonth, setSelectedMonth] = useState(new Date());
  const [selectedProfile, setSelectedProfile] = useState<string>('all');
  const [searchTerm, setSearchTerm] = useState('');
  const { toast } = useToast();

  useEffect(() => {
    loadProfiles();
  }, []);

  useEffect(() => {
    loadValidatedLeaves();
  }, [selectedMonth, selectedProfile]);

  const loadProfiles = async () => {
    try {
  // TODO: Remplacer par appel à l'API Express locale
        .from('profiles')
        .select('id, nom, prenom, email')
        .order('nom', { ascending: true });

      if (error) throw error;
      setProfiles(data || []);
    } catch (error) {
      console.error('Erreur lors du chargement des profils:', error);
      toast({
        title: "Erreur",
        description: "Impossible de charger la liste des employés",
        variant: "destructive",
      });
    }
  };

  const loadValidatedLeaves = async () => {
    try {
      setLoading(true);
      
      const startDate = format(startOfMonth(selectedMonth), 'yyyy-MM-dd');
      const endDate = format(endOfMonth(selectedMonth), 'yyyy-MM-dd');

  // TODO: Remplacer par appel à l'API Express locale
        .from('demandes_rh')
        .select(`
          id,
          demandeur_id,
          titre,
          description,
          date_debut,
          date_fin,
          type_demande,
          statut,
          date_approbation,
          approuve_par
        `)
        .eq('type_demande', 'conges')
        .eq('statut', 'approuve')
        .gte('date_debut', startDate)
        .lte('date_fin', endDate)
        .order('date_debut', { ascending: true });

      if (selectedProfile !== 'all') {
        query = query.eq('demandeur_id', selectedProfile);
      }

      const { data, error } = await query;

      if (error) throw error;

      const formattedLeaves: ValidatedLeave[] = (data || []).map(leave => ({
        id: leave.id,
        demandeur_id: leave.demandeur_id,
        demandeur_nom: 'Inconnu',
        demandeur_prenom: '',
        titre: leave.titre,
        description: leave.description || '',
        date_debut: leave.date_debut,
        date_fin: leave.date_fin,
        type_demande: leave.type_demande,
        statut: leave.statut,
        date_approbation: leave.date_approbation,
        approuve_par_nom: undefined,
        approuve_par_prenom: undefined
      }));

      setValidatedLeaves(formattedLeaves);
    } catch (error) {
      console.error('Erreur lors du chargement des congés validés:', error);
      toast({
        title: "Erreur",
        description: "Impossible de charger les congés validés",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const processAutomaticAttendance = async (profileId: string, leaveId: string) => {
    try {
      const leave = validatedLeaves.find(l => l.id === leaveId);
      if (!leave) return;

      const startDate = parseISO(leave.date_debut);
      const endDate = parseISO(leave.date_fin || leave.date_debut);
      
      // Créer les pointages automatiques pour chaque jour du congé
      const currentDate = new Date(startDate);
      while (currentDate <= endDate) {
  // TODO: Remplacer par appel à l'API Express locale
          p_profile_id: profileId,
          p_date: format(currentDate, 'yyyy-MM-dd')
        });

        if (error) {
          console.error('Erreur lors du traitement automatique:', error);
        }

        currentDate.setDate(currentDate.getDate() + 1);
      }

      toast({
        title: "Succès",
        description: "Pointages automatiques créés pour cette période de congé",
      });
    } catch (error) {
      console.error('Erreur lors du traitement automatique:', error);
      toast({
        title: "Erreur",
        description: "Impossible de créer les pointages automatiques",
        variant: "destructive",
      });
    }
  };

  const filteredLeaves = validatedLeaves.filter(leave => 
    searchTerm === '' || 
    leave.demandeur_nom.toLowerCase().includes(searchTerm.toLowerCase()) ||
    leave.demandeur_prenom.toLowerCase().includes(searchTerm.toLowerCase()) ||
    leave.titre.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const getDurationInDays = (startDate: string, endDate?: string) => {
    const start = parseISO(startDate);
    const end = parseISO(endDate || startDate);
    const diffTime = Math.abs(end.getTime() - start.getTime());
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24)) + 1;
    return diffDays;
  };

  const navigateMonth = (direction: 'prev' | 'next') => {
    setSelectedMonth(prev => 
      direction === 'prev' ? subMonths(prev, 1) : addMonths(prev, 1)
    );
  };

  if (loading) {
    return (
      <Card>
        <CardContent className="p-6">
          <div className="animate-pulse space-y-4">
            <div className="h-4 bg-muted rounded w-1/4"></div>
            <div className="h-32 bg-muted rounded"></div>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <CheckCircle className="h-5 w-5 text-green-600" />
          Congés Validés - Pointage Automatique
        </CardTitle>
      </CardHeader>
      <CardContent>
        {/* Filtres et navigation */}
        <div className="mb-6 space-y-4">
          <div className="flex flex-wrap items-center gap-4">
            {/* Navigation mensuelle */}
            <div className="flex items-center gap-2">
              <Button variant="outline" size="sm" onClick={() => navigateMonth('prev')}>
                ←
              </Button>
              <span className="font-medium min-w-[120px] text-center">
                {format(selectedMonth, 'MMMM yyyy', { locale: fr })}
              </span>
              <Button variant="outline" size="sm" onClick={() => navigateMonth('next')}>
                →
              </Button>
            </div>

            {/* Filtre par employé */}
            <div className="flex items-center gap-2">
              <Label htmlFor="profile-filter">Employé:</Label>
              <Select value={selectedProfile} onValueChange={setSelectedProfile}>
                <SelectTrigger className="w-[200px]">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">Tous les employés</SelectItem>
                  {profiles.map(profile => (
                    <SelectItem key={profile.id} value={profile.id}>
                      {profile.prenom} {profile.nom}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            {/* Recherche */}
            <div className="flex items-center gap-2">
              <Label htmlFor="search">Recherche:</Label>
              <Input
                id="search"
                placeholder="Nom, prénom ou titre..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-[200px]"
              />
            </div>
          </div>
        </div>

        {/* Statistiques */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
          <Card>
            <CardContent className="p-4">
              <div className="text-2xl font-bold text-primary">{filteredLeaves.length}</div>
              <p className="text-sm text-muted-foreground">Congés validés ce mois</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-4">
              <div className="text-2xl font-bold text-green-600">
                {filteredLeaves.reduce((sum, leave) => sum + getDurationInDays(leave.date_debut, leave.date_fin), 0)}
              </div>
              <p className="text-sm text-muted-foreground">Jours de congé total</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-4">
              <div className="text-2xl font-bold text-blue-600">
                {new Set(filteredLeaves.map(leave => leave.demandeur_id)).size}
              </div>
              <p className="text-sm text-muted-foreground">Employés concernés</p>
            </CardContent>
          </Card>
        </div>

        {/* Tableau des congés */}
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Employé</TableHead>
              <TableHead>Congé</TableHead>
              <TableHead>Période</TableHead>
              <TableHead>Durée</TableHead>
              <TableHead>Approuvé par</TableHead>
              <TableHead>Date d'approbation</TableHead>
              <TableHead>Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {filteredLeaves.length === 0 ? (
              <TableRow>
                <TableCell colSpan={7} className="text-center text-muted-foreground">
                  Aucun congé validé pour cette période
                </TableCell>
              </TableRow>
            ) : (
              filteredLeaves.map((leave) => (
                <TableRow key={leave.id}>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <User className="h-4 w-4 text-muted-foreground" />
                      <span className="font-medium">
                        {leave.demandeur_prenom} {leave.demandeur_nom}
                      </span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <div>
                      <div className="font-medium">{leave.titre}</div>
                      {leave.description && (
                        <div className="text-sm text-muted-foreground">{leave.description}</div>
                      )}
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="text-sm">
                      <div>{format(parseISO(leave.date_debut), 'dd/MM/yyyy', { locale: fr })}</div>
                      {leave.date_fin && leave.date_fin !== leave.date_debut && (
                        <div className="text-muted-foreground">
                          → {format(parseISO(leave.date_fin), 'dd/MM/yyyy', { locale: fr })}
                        </div>
                      )}
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline">
                      {getDurationInDays(leave.date_debut, leave.date_fin)} jour(s)
                    </Badge>
                  </TableCell>
                  <TableCell>
                    {leave.approuve_par_nom && (
                      <span className="text-sm">
                        {leave.approuve_par_prenom} {leave.approuve_par_nom}
                      </span>
                    )}
                  </TableCell>
                  <TableCell>
                    <span className="text-sm">
                      {format(parseISO(leave.date_approbation), 'dd/MM/yyyy', { locale: fr })}
                    </span>
                  </TableCell>
                  <TableCell>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => processAutomaticAttendance(leave.demandeur_id, leave.id)}
                      className="flex items-center gap-1"
                    >
                      <CalendarIcon className="h-4 w-4" />
                      Pointer automatiquement
                    </Button>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
};

export default ValidatedLeavesCalendar;