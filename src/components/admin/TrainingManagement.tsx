import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { BookOpen, MapPin, Users, Monitor, FileText } from 'lucide-react';
import { toast } from 'react-toastify';
import { useToast } from '@/hooks/use-toast';
import { supabase } from '../../lib/supabaseClient';

// Sub-components for different sections
import { CentresManagement } from './training/CentresManagement';
import { PlateformesManagement } from './training/PlateformesManagement';
import { CatalogueFormationsPhysique } from './training/CatalogueFormationsPhysique';
import { CatalogueFormationsEnLigne } from './training/CatalogueFormationsEnLigne';
import { ClassesManagement } from './training/ClassesManagement';
import { SessionsEnLigneManagement } from './training/SessionsEnLigneManagement';
import ModelesDocumentsManagement from './training/ModelesDocumentsManagement';
import GenerationDocuments from './training/GenerationDocuments';
import CorpsFormationManagement from './training/CorpsFormationManagement';

interface Segment {
  id: string;
  nom: string;
  couleur: string;
}

export function TrainingManagement() {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState('physique');
  const [selectedSegment, setSelectedSegment] = useState<string | null>(null);
  const [segments, setSegments] = useState<Segment[]>([]);
  const [loading, setLoading] = useState(false);
  const { toast } = useToast();

  // Encapsulation de loadSegments dans un hook useCallback
  const loadSegments = useCallback(async () => {
    try {
      setLoading(true);
      const { data, error } = await supabase
        .from('segments')
        .select('*')
        .order('nom');

      if (error) throw error;
      setSegments(data || []);
    } catch (error) {
      console.error('Error loading segments:', error);
      toast({
        title: "Erreur",
        description: "Impossible de charger les segments",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  }, [toast]);

  // Mise à jour de useEffect pour utiliser loadSegments
  useEffect(() => {
    loadSegments();
  }, [loadSegments]);

  const handleSegmentChange = (segmentId: string) => {
    setSelectedSegment(segmentId);
    localStorage.setItem('selectedSegment', segmentId);
  };

  const selectedSegmentData = segments.find(s => s.id === selectedSegment);

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Gestion des Formations</h1>
          <p className="text-muted-foreground mt-2">
            Gérez vos formations physiques et en ligne, centres, plateformes et étudiants
          </p>
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
        <TabsList className="grid w-full grid-cols-2">
          <TabsTrigger value="physique" className="flex items-center gap-2">
            <MapPin className="h-4 w-4" />
            Formation Physique
          </TabsTrigger>
          <TabsTrigger value="en_ligne" className="flex items-center gap-2">
            <Monitor className="h-4 w-4" />
            Formation en Ligne
          </TabsTrigger>
        </TabsList>

        {/* Formation Physique Tab */}
        <TabsContent value="physique" className="space-y-6">
          {/* Segment Selector */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <MapPin className="h-5 w-5" />
                Sélection du Segment
              </CardTitle>
            </CardHeader>
            <CardContent>
              {loading ? (
                <div>Chargement des segments...</div>
              ) : (
                <div className="space-y-4">
                  <div className="flex items-center gap-4">
                    <Select value={selectedSegment} onValueChange={handleSegmentChange}>
                      <SelectTrigger className="w-64">
                        <SelectValue placeholder="Sélectionner un segment" />
                      </SelectTrigger>
                      <SelectContent>
                        {segments.map((segment) => (
                          <SelectItem key={segment.id} value={segment.id}>
                            <div className="flex items-center gap-2">
                              <div 
                                className="w-3 h-3 rounded-full" 
                                style={{ backgroundColor: segment.couleur }}
                              />
                              {segment.nom}
                            </div>
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    {selectedSegmentData && (
                      <Badge 
                        variant="outline" 
                        style={{ borderColor: selectedSegmentData.couleur, color: selectedSegmentData.couleur }}
                      >
                        Segment sélectionné: {selectedSegmentData.nom}
                      </Badge>
                    )}
                  </div>
                  {!selectedSegment && (
                    <div className="text-sm text-muted-foreground">
                      Veuillez sélectionner un segment pour accéder aux modules de formation physique.
                    </div>
                  )}
                </div>
              )}
            </CardContent>
          </Card>

          {selectedSegment ? (
            <Tabs defaultValue="centres" className="space-y-4">
            <TabsList className="grid w-full grid-cols-5">
              <TabsTrigger value="corps">Corps de Formation</TabsTrigger>
              <TabsTrigger value="centres">Centres</TabsTrigger>
              <TabsTrigger value="livrables">Livrables</TabsTrigger>
              <TabsTrigger value="classes">Classes</TabsTrigger>
              <TabsTrigger value="documents">Documents</TabsTrigger>
            </TabsList>

            <TabsContent value="corps">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <BookOpen className="h-5 w-5" />
                    Corps de Formation
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <CorpsFormationManagement />
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="centres">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <MapPin className="h-5 w-5" />
                    Gestion des Centres
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <CentresManagement selectedSegmentId={selectedSegment} />
                </CardContent>
              </Card>
            </TabsContent>


            <TabsContent value="livrables">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <BookOpen className="h-5 w-5" />
                    Gestion des Livrables
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <ModelesDocumentsManagement />
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="classes">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Users className="h-5 w-5" />
                    Gestion des Classes
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="flex justify-between items-center">
                      <p className="text-muted-foreground">
                        Gérez les sessions de formation pour le segment sélectionné
                      </p>
                      <Button 
                        onClick={() => {
                          navigate(`/administration/formations/classes?segment=${selectedSegment}`);
                        }}
                        variant="outline"
                      >
                        Voir la page complète
                      </Button>
                    </div>
                    <ClassesManagement selectedSegmentId={selectedSegment} />
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="documents">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <FileText className="h-5 w-5" />
                    Génération de Documents
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <GenerationDocuments />
                </CardContent>
              </Card>
            </TabsContent>
            </Tabs>
          ) : (
            <Card>
              <CardContent className="p-8 text-center">
                <div className="text-muted-foreground">
                  Sélectionnez un segment pour accéder aux modules de gestion de formation physique.
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* Formation en Ligne Tab */}
        <TabsContent value="en_ligne" className="space-y-6">
          <Tabs defaultValue="plateformes" className="space-y-4">
            <TabsList className="grid w-full grid-cols-3">
              <TabsTrigger value="plateformes">Plateformes</TabsTrigger>
              <TabsTrigger value="catalogue">Catalogue de Formations</TabsTrigger>
              <TabsTrigger value="sessions">Sessions en ligne</TabsTrigger>
            </TabsList>

            <TabsContent value="plateformes">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Monitor className="h-5 w-5" />
                    Gestion des Plateformes
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <PlateformesManagement />
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="catalogue">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <BookOpen className="h-5 w-5" />
                    Catalogue des Formations en Ligne
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <CatalogueFormationsEnLigne />
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="sessions">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Monitor className="h-5 w-5" />
                    Gestion des Sessions en Ligne
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <SessionsEnLigneManagement />
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </TabsContent>
      </Tabs>
    </div>
  );
}