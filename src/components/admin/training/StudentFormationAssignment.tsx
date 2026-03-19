import React, { useState, useEffect } from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";
import { supabase } from "@/integrations/supabase/client";
import { BookOpen, GraduationCap } from "lucide-react";

interface CorpsFormation {
  id: string;
  nom: string;
  description?: string;
  is_active: boolean;
}

interface Formation {
  id: string;
  titre: string;
  description?: string;
  corps_formation_id?: string;
  niveau: string;
  duree_heures: number;
  prix?: number;
}

interface Etudiant {
  id: string;
  nom: string;
  prenom: string;
  email?: string;
  telephone?: string;
}

interface StudentFormationAssignmentProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSuccess: () => void;
}

export const StudentFormationAssignment: React.FC<StudentFormationAssignmentProps> = ({
  open,
  onOpenChange,
  onSuccess
}) => {
  const { toast } = useToast();
  const [loading, setLoading] = useState(false);
  const [corpsFormations, setCorpsFormations] = useState<CorpsFormation[]>([]);
  const [formations, setFormations] = useState<Formation[]>([]);
  const [etudiants, setEtudiants] = useState<Etudiant[]>([]);
  const [filteredFormations, setFilteredFormations] = useState<Formation[]>([]);
  
  const [selectedCorps, setSelectedCorps] = useState<string>('');
  const [selectedFormation, setSelectedFormation] = useState<string>('');
  const [selectedEtudiant, setSelectedEtudiant] = useState<string>('');

  useEffect(() => {
    if (open) {
      loadData();
    }
  }, [open]);

  useEffect(() => {
    if (selectedCorps) {
      const filtered = formations.filter(f => f.corps_formation_id === selectedCorps);
      setFilteredFormations(filtered);
      setSelectedFormation('');
    } else {
      setFilteredFormations([]);
      setSelectedFormation('');
    }
  }, [selectedCorps, formations]);

  const loadData = async () => {
    try {
      const [corpsResult, formationsResult, etudiantsResult] = await Promise.all([
        supabase
          .from('corps_formation')
          .select('*')
          .eq('is_active', true)
          .order('nom'),
        supabase
          .from('formations')
          .select('*')
          .eq('is_active', true)
          .order('titre'),
        supabase
          .from('etudiants')
          .select('*')
          .order('nom', { ascending: true })
      ]);

      if (corpsResult.error) throw corpsResult.error;
      if (formationsResult.error) throw formationsResult.error;
      if (etudiantsResult.error) throw etudiantsResult.error;

      setCorpsFormations(corpsResult.data || []);
      setFormations(formationsResult.data || []);
      setEtudiants(etudiantsResult.data || []);
    } catch (error) {
      console.error('Erreur lors du chargement des données:', error);
      toast({
        title: "Erreur",
        description: "Impossible de charger les données",
        variant: "destructive",
      });
    }
  };

  const handleSubmit = async () => {
    if (!selectedEtudiant || !selectedFormation) {
      toast({
        title: "Erreur",
        description: "Veuillez sélectionner un étudiant et une formation",
        variant: "destructive",
      });
      return;
    }

    setLoading(true);
    try {
    // Créer une inscription
    const { error } = await supabase
      .from('inscriptions')
      .insert([{ 
        etudiant_id: selectedEtudiant,
        formation_id: selectedFormation,
        statut_inscription: 'en_attente'
      }]);

      if (error) throw error;

      toast({
        title: "Succès",
        description: "Formation assignée avec succès à l'étudiant",
      });

      resetForm();
      onSuccess();
      onOpenChange(false);
    } catch (error) {
      console.error('Erreur lors de l\'assignation:', error);
      toast({
        title: "Erreur",
        description: "Impossible d'assigner la formation",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const resetForm = () => {
    setSelectedCorps('');
    setSelectedFormation('');
    setSelectedEtudiant('');
  };

  const selectedCorpsData = corpsFormations.find(c => c.id === selectedCorps);
  const selectedFormationData = filteredFormations.find(f => f.id === selectedFormation);
  const selectedEtudiantData = etudiants.find(e => e.id === selectedEtudiant);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <GraduationCap className="h-5 w-5" />
            Assigner une Formation à un Étudiant
          </DialogTitle>
        </DialogHeader>

        <div className="space-y-6">
          {/* Sélection du corps de formation */}
          <div className="space-y-2">
            <Label htmlFor="corps-formation">Corps de Formation</Label>
            <Select value={selectedCorps} onValueChange={setSelectedCorps}>
              <SelectTrigger>
                <SelectValue placeholder="Sélectionner un corps de formation" />
              </SelectTrigger>
              <SelectContent>
                {corpsFormations.map((corps) => (
                  <SelectItem key={corps.id} value={corps.id}>
                    <div className="flex items-center gap-2">
                      <BookOpen className="h-4 w-4" />
                      <span>{corps.nom}</span>
                    </div>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {selectedCorpsData && (
              <p className="text-sm text-muted-foreground">
                {selectedCorpsData.description}
              </p>
            )}
          </div>

          {/* Sélection de la formation */}
          <div className="space-y-2">
            <Label htmlFor="formation">Formation</Label>
            <Select 
              value={selectedFormation} 
              onValueChange={setSelectedFormation}
              disabled={!selectedCorps}
            >
              <SelectTrigger>
                <SelectValue placeholder={
                  selectedCorps 
                    ? "Sélectionner une formation" 
                    : "Sélectionnez d'abord un corps de formation"
                } />
              </SelectTrigger>
              <SelectContent>
                {filteredFormations.map((formation) => (
                  <SelectItem key={formation.id} value={formation.id}>
                    <div className="flex flex-col">
                      <div className="flex items-center gap-2">
                        <span className="font-medium">{formation.titre}</span>
                        <Badge variant="outline">{formation.niveau}</Badge>
                      </div>
                      <span className="text-xs text-muted-foreground">
                        {formation.duree_heures}h
                        {formation.prix && ` - ${formation.prix} MAD`}
                      </span>
                    </div>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {selectedFormationData && (
              <p className="text-sm text-muted-foreground">
                {selectedFormationData.description}
              </p>
            )}
          </div>

          {/* Sélection de l'étudiant */}
          <div className="space-y-2">
            <Label htmlFor="etudiant">Étudiant</Label>
            <Select value={selectedEtudiant} onValueChange={setSelectedEtudiant}>
              <SelectTrigger>
                <SelectValue placeholder="Sélectionner un étudiant" />
              </SelectTrigger>
              <SelectContent>
                {etudiants.map((etudiant) => (
                  <SelectItem key={etudiant.id} value={etudiant.id}>
                    <div className="flex flex-col">
                      <span className="font-medium">
                        {etudiant.prenom} {etudiant.nom}
                      </span>
                      {etudiant.email && (
                        <span className="text-xs text-muted-foreground">
                          {etudiant.email}
                        </span>
                      )}
                    </div>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {/* Résumé de la sélection */}
          {selectedCorpsData && selectedFormationData && selectedEtudiantData && (
            <div className="bg-muted/50 p-4 rounded-lg space-y-2">
              <h4 className="font-medium">Résumé de l'assignation :</h4>
              <div className="text-sm space-y-1">
                <p><span className="font-medium">Corps :</span> {selectedCorpsData.nom}</p>
                <p><span className="font-medium">Formation :</span> {selectedFormationData.titre}</p>
                <p><span className="font-medium">Étudiant :</span> {selectedEtudiantData.prenom} {selectedEtudiantData.nom}</p>
              </div>
            </div>
          )}

          {/* Actions */}
          <div className="flex justify-end space-x-2">
            <Button variant="outline" onClick={() => onOpenChange(false)}>
              Annuler
            </Button>
            <Button 
              onClick={handleSubmit} 
              disabled={loading || !selectedEtudiant || !selectedFormation}
            >
              {loading ? "Assignation..." : "Assigner"}
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
};