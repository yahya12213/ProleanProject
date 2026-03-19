import { useState, useEffect, useCallback } from 'react';
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ArrowLeft, FileText, Plus, Trash2, FolderOpen, FileCheck } from 'lucide-react';
import axios from 'axios';
import { toast } from "sonner";
import { DocumentSelectionModal } from './DocumentSelectionModal';
interface Formation {
  id: string;
  titre: string;
  reference?: string;
}
interface CorpsFormationFamille {
  id: string;
  famille_nom: string;
  famille_description?: string;
  famille_icone?: string;
  corps_formation_id: string;
}
interface ModeleDocument {
  id: string;
  nom_modele: string;
  type_document: string;
  corps_formation_famille_id?: string;
  is_active: boolean;
}
interface FormationModele {
  id: string;
  formation_id: string;
  modele_id: string;
  famille_context_id?: string;
  is_active: boolean;
  modeles_documents: ModeleDocument;
}
interface FormationDocumentsManagementProps {
  formationId: string;
  formationTitre: string;
  onBack: () => void;
}
export function FormationDocumentsManagement({
  formationId,
  formationTitre,
  onBack
}: FormationDocumentsManagementProps) {
  const [familles, setFamilles] = useState<CorpsFormationFamille[]>([]);
  const [modeles, setModeles] = useState<ModeleDocument[]>([]);
  const [assignedModeles, setAssignedModeles] = useState<FormationModele[]>([]);
  const [formation, setFormation] = useState<FormationData | null>(null);
  const [loading, setLoading] = useState(true);
  const loadData = useCallback(async () => {
    try {
      setLoading(true);

      // Charger la formation
      const formationResponse = await axios.get(`/api/formations/${formationId}`);
      const formationData = formationResponse.data;
      setFormation(formationData);

      if (!formationData.corps_formation_id) {
        toast.error("Cette formation n'est pas associée à un corps de formation");
        return;
      }

      // Charger les familles du corps de formation
      const famillesResponse = await axios.get(`/api/corps_formation_familles?corps_formation_id=${formationData.corps_formation_id}&is_active=true`);
      setFamilles(famillesResponse.data || []);

      // Charger tous les modèles de documents liés aux familles
      const modelesResponse = await axios.get(`/api/modeles_documents?is_active=true&corps_formation_famille_ids=${famillesResponse.data.map(f => f.id).join(',')}`);
      setModeles(modelesResponse.data || []);

      // Charger les modèles assignés
      const assignedResponse = await axios.get(`/api/formation_modeles?formation_id=${formationId}&is_active=true`);
      setAssignedModeles(assignedResponse.data || []);
    } catch (error) {
      console.error('Erreur lors du chargement des données:', error);
      toast.error('Erreur lors du chargement des données');
    } finally {
      setLoading(false);
    }
  }, [formationId]);
  useEffect(() => {
    loadData();
  }, [loadData]);
  const handleAssignModele = async (modeleId: string) => {
    try {
      const existingResponse = await axios.get(`/api/formation_modeles?formation_id=${formationId}&modele_id=${modeleId}`);
      const existing = existingResponse.data;

      if (existing) {
        if (!existing.is_active) {
          await axios.put(`/api/formation_modeles/${existing.id}`, { is_active: true });
        }
      } else {
        await axios.post('/api/formation_modeles', {
          formation_id: formationId,
          modele_id: modeleId,
          famille_context_id: null,
          is_active: true
        });
      }

      toast.success('Modèle assigné avec succès');
      loadData();
    } catch (error) {
      console.error('Erreur lors de l\'assignation du modèle:', error);
      toast.error('Erreur lors de l\'assignation du modèle');
    }
  };
  const handleUnassignModele = async (assignmentId: string) => {
    try {
      const {
        error
      } = await supabase.from('formation_modeles').update({
        is_active: false
      }).eq('id', assignmentId);
      if (error) throw error;
      toast.success('Modèle désassigné avec succès');
      loadData();
    } catch (error) {
      console.error('Erreur lors de la désassignation:', error);
      toast.error('Erreur lors de la désassignation du modèle');
    }
  };
  const isModeleAssigned = (modeleId: string) => {
    return assignedModeles.some(assigned => assigned.modele_id === modeleId);
  };
  if (loading) {
    return <div className="flex justify-center p-8">Chargement...</div>;
  }
  return <div className="space-y-6">
      {/* En-tête avec bouton retour */}
      <div className="flex items-center gap-4">
        <Button variant="outline" size="icon" onClick={onBack}>
          <ArrowLeft className="h-4 w-4" />
        </Button>
        <div>
          <h1 className="text-2xl font-bold">Gestion des Documents</h1>
          <p className="text-muted-foreground">Formation: {formationTitre}</p>
        </div>
      </div>

      <div className="space-y-6">
        {/* Section d'ajout de modèles par famille */}
        <Card>
          <CardHeader>
            <CardTitle>Ajouter des Documents type</CardTitle>
            <CardDescription>
              Gérez les documents par famille de livrables configurées dans le corps de formation
            </CardDescription>
          </CardHeader>
          <CardContent>
            {familles.length === 0 ? <p className="text-muted-foreground text-center py-8">
                Aucune famille de livrables configurée pour ce corps de formation
              </p> : <div className="space-y-4">
                {familles.map(famille => {
              // Compter seulement les documents assignés avec ce contexte de famille
              const documentsAssignesDelaFamille = assignedModeles.filter(assignment => assignment.famille_context_id === famille.id);
              const assignedCount = documentsAssignesDelaFamille.length;
              return <div key={famille.id} className="border rounded-lg p-4 space-y-3">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          <div className="text-xl">
                            {famille.famille_icone === 'Badge' ? '🏷️' : famille.famille_icone === 'Award' ? '🏆' : famille.famille_icone === 'Certificate' ? '📜' : famille.famille_icone === 'FileText' ? '📋' : famille.famille_icone === 'GraduationCap' ? '🎓' : '📂'}
                          </div>
                          <div>
                            <h3 className="font-semibold">{famille.famille_nom}</h3>
                            {famille.famille_description && <p className="text-sm text-muted-foreground">{famille.famille_description}</p>}
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          <Badge variant="outline" className="text-xs">
                            {assignedCount} document{assignedCount !== 1 ? 's' : ''} assigné{assignedCount !== 1 ? 's' : ''}
                          </Badge>
                          <DocumentSelectionModal famille={famille} formationId={formationId} onDocumentsLinked={loadData} />
                        </div>
                      </div>
                      
                      {/* Documents assignés de cette famille */}
                      {assignedCount > 0 && <div className="mt-3 space-y-2">
                          <Label className="text-sm font-medium">Documents assignés :</Label>
                          <div className="space-y-1">
                            {documentsAssignesDelaFamille.map(assignment => <div key={assignment.id} className="flex items-center justify-between p-2 bg-muted/30 rounded text-sm">
                                  <div className="flex items-center gap-2">
                                    <FileText className="h-3 w-3" />
                                    <span>{assignment.modeles_documents.nom_modele}</span>
                                    <Badge variant="secondary" className="text-xs">
                                      {assignment.modeles_documents.type_document}
                                    </Badge>
                                  </div>
                                  <Button variant="ghost" size="sm" onClick={() => handleUnassignModele(assignment.id)} className="h-6 w-6 p-0">
                                    <Trash2 className="h-3 w-3" />
                                  </Button>
                                </div>)}
                          </div>
                        </div>}
                    </div>;
            })}
              </div>}
          </CardContent>
        </Card>
      </div>
    </div>;
}