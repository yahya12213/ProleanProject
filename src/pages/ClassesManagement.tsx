import React, { useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { ArrowLeft, Users } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { ClassesManagement as ClassesManagementComponent } from '@/components/admin/training/ClassesManagement';
import MainNavigation from '@/components/MainNavigation';

interface Segment {
  id: string;
  nom: string;
  couleur: string;
}

const ClassesManagement = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [segments, setSegments] = useState<Segment[]>([]);
  const [selectedSegment, setSelectedSegment] = useState<string>('');
  const [loading, setLoading] = useState(true);
  const { toast } = useToast();

  useEffect(() => {
    const loadSegments = async () => {
      try {
        setLoading(true);
        const response = await fetch('/api/segments');
        const data = await response.json();

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
    };

    loadSegments();

    // Get segment from URL params or localStorage
    const segmentFromUrl = searchParams.get('segment');
    const savedSegment = localStorage.getItem('selectedSegment');
    
    if (segmentFromUrl) {
      setSelectedSegment(segmentFromUrl);
      localStorage.setItem('selectedSegment', segmentFromUrl);
    } else if (savedSegment) {
      setSelectedSegment(savedSegment);
    }
  }, [searchParams, toast, setLoading]);

  const selectedSegmentData = segments.find(s => s.id === selectedSegment);

  const handleRetour = () => {
    navigate('/administration', { 
      state: { activeTab: 'formations' }
    });
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-neutral flex items-center justify-center">
        <div className="text-center">
          <h1 className="text-2xl font-bold">Chargement...</h1>
        </div>
      </div>
    );
  }

  if (!selectedSegment || !selectedSegmentData) {
    return (
      <div className="min-h-screen bg-neutral">
        <header className="border-b bg-white shadow-soft">
          <div className="container mx-auto px-6 py-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-6">
                <Button
                  variant="ghost"
                  onClick={handleRetour}
                  className="flex items-center gap-2"
                >
                  <ArrowLeft className="h-4 w-4" />
                  Retour
                </Button>
                <h1 className="text-2xl font-heading font-bold text-gradient flex items-center gap-2">
                  <Users className="h-6 w-6" />
                  Gestion des Classes
                </h1>
              </div>
              <MainNavigation />
            </div>
          </div>
        </header>
        
        <div className="container mx-auto px-6 py-8">
          <Card>
            <CardContent className="p-8 text-center">
              <div className="text-muted-foreground">
                Aucun segment sélectionné. Veuillez retourner à la page d'administration pour sélectionner un segment.
              </div>
              <Button 
                className="mt-4" 
                onClick={handleRetour}
              >
                Retourner à l'administration
              </Button>
            </CardContent>
          </Card>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-neutral">
      <header className="border-b bg-white shadow-soft">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-6">
              <Button
                variant="ghost"
                onClick={handleRetour}
                className="flex items-center gap-2"
              >
                <ArrowLeft className="h-4 w-4" />
                Retour
              </Button>
              <h1 className="text-2xl font-heading font-bold text-gradient flex items-center gap-2">
                <Users className="h-6 w-6" />
                Gestion des Classes
              </h1>
              {selectedSegmentData && (
                <Badge 
                  variant="outline" 
                  style={{ borderColor: selectedSegmentData.couleur, color: selectedSegmentData.couleur }}
                >
                  {selectedSegmentData.nom}
                </Badge>
              )}
            </div>
            <MainNavigation />
          </div>
        </div>
      </header>

      <div className="container mx-auto px-6 py-8">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Users className="h-5 w-5" />
              Classes du segment {selectedSegmentData.nom}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ClassesManagementComponent selectedSegmentId={selectedSegment} />
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default ClassesManagement;