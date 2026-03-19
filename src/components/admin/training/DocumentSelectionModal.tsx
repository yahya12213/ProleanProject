import { useState, useEffect } from 'react';
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { FileText, Plus, Search, FolderOpen, Folder } from 'lucide-react';
import { supabase } from '@/integrations/supabase/client';
import { toast } from "sonner";

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
  groupe: string;
  famille: string;
  corps_formation_famille_id?: string;
  is_active: boolean;
}

interface DocumentSelectionModalProps {
  famille: CorpsFormationFamille;
  formationId: string;
  onDocumentsLinked: () => void;
}

export function DocumentSelectionModal({ famille, formationId, onDocumentsLinked }: DocumentSelectionModalProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [allDocuments, setAllDocuments] = useState<ModeleDocument[]>([]);
  const [availableGroups, setAvailableGroups] = useState<string[]>([]);
  const [selectedDocuments, setSelectedDocuments] = useState<string[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedGroupNav, setSelectedGroupNav] = useState<string>('all');
  const [selectedFamilleNav, setSelectedFamilleNav] = useState<string>('all');
  const [loading, setLoading] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (isOpen) {
      loadData();
    }
  }, [isOpen, formationId]);

  const loadData = async () => {
    try {
      setLoading(true);
      
      // Charger TOUS les documents actifs
      const { data: documents, error: documentsError } = await supabase
        .from('modeles_documents')
        .select('*')
        .eq('is_active', true)
        .order('groupe', { ascending: true })
        .order('famille', { ascending: true })
        .order('nom_modele', { ascending: true });

      if (documentsError) throw documentsError;

      // Charger TOUS les groupes de documents (même vides)
      const { data: groupesData, error: groupesError } = await supabase
        .from('groupes_documents')
        .select('nom')
        .eq('is_active', true)
        .order('nom');

      if (groupesError) throw groupesError;

      // Charger les documents déjà assignés à cette formation POUR CETTE FAMILLE SPÉCIFIQUE
      const { data: assignedDocuments, error: assignedError } = await supabase
        .from('formation_modeles')
        .select('modele_id')
        .eq('formation_id', formationId)
        .eq('famille_context_id', famille.id)
        .eq('is_active', true);

      if (assignedError) throw assignedError;

      const assignedIds = assignedDocuments?.map(a => a.modele_id) || [];
      
      // Filtrer pour ne garder que les documents non assignés à cette formation POUR CETTE FAMILLE
      // Un même document peut être assigné à plusieurs familles différentes
      const availableDocuments = (documents || []).filter(doc => 
        !assignedIds.includes(doc.id)
      );

      // Combiner les groupes avec et sans documents
      const groupesWithDocs = [...new Set(availableDocuments.map(doc => doc.groupe))];
      const groupesFromDB = (groupesData || []).map(g => g.nom);
      const allGroups = [...new Set([...groupesWithDocs, ...groupesFromDB])].sort();

      setAllDocuments(availableDocuments);
      setAvailableGroups(allGroups);
    } catch (error) {
      console.error('Erreur lors du chargement des données:', error);
      toast.error('Erreur lors du chargement des données');
    } finally {
      setLoading(false);
    }
  };

  const handleDocumentToggle = (documentId: string) => {
    setSelectedDocuments(prev => 
      prev.includes(documentId)
        ? prev.filter(id => id !== documentId)
        : [...prev, documentId]
    );
  };

  const handleLinkDocuments = async () => {
    if (selectedDocuments.length === 0) {
      toast.error('Veuillez sélectionner au moins un document');
      return;
    }

    try {
      setSubmitting(true);

      // Vérifier les liens existants pour cette formation ET cette famille spécifique
      const { data: allExistingLinks, error: checkError } = await supabase
        .from('formation_modeles')
        .select('id, modele_id, is_active')
        .eq('formation_id', formationId)
        .eq('famille_context_id', famille.id)
        .in('modele_id', selectedDocuments);

      if (checkError) throw checkError;

      const existingLinksMap = new Map();
      allExistingLinks?.forEach(link => {
        existingLinksMap.set(link.modele_id, link);
      });

      const toReactivate = [];
      const toCreate = [];

      selectedDocuments.forEach(modeleId => {
        const existingLink = existingLinksMap.get(modeleId);
        if (existingLink) {
          if (!existingLink.is_active) {
            toReactivate.push(existingLink.id);
          }
          // Si déjà actif, on ignore (pas d'erreur)
        } else {
          toCreate.push(modeleId);
        }
      });

      let linkedCount = 0;

      // Réactiver les liens existants inactifs
      if (toReactivate.length > 0) {
        const { error: reactivateError } = await supabase
          .from('formation_modeles')
          .update({ is_active: true, updated_at: new Date().toISOString() })
          .in('id', toReactivate);

        if (reactivateError) throw reactivateError;
        linkedCount += toReactivate.length;
      }

      // Créer de nouveaux liens
      if (toCreate.length > 0) {
        const formationModeles = toCreate.map(modeleId => ({
          formation_id: formationId,
          modele_id: modeleId,
          famille_context_id: famille.id,
          is_active: true
        }));

        const { error: insertError } = await supabase
          .from('formation_modeles')
          .insert(formationModeles);

        if (insertError) throw insertError;
        linkedCount += toCreate.length;
      }

      if (linkedCount === 0) {
        toast.info('Tous les documents sélectionnés sont déjà liés à cette famille');
      } else {
        toast.success(`${linkedCount} document(s) lié(s) avec succès à la famille "${famille.famille_nom}"`);
      }
      
      setIsOpen(false);
      setSelectedDocuments([]);
      setSearchTerm('');
      setSelectedFamilleNav('all');
      onDocumentsLinked();
    } catch (error) {
      console.error('Erreur lors de la liaison des documents:', error);
      toast.error('Erreur lors de la liaison des documents');
    } finally {
      setSubmitting(false);
    }
  };

  // Navigation par Groupes → Familles → Documents
  const filteredDocuments = allDocuments.filter(doc => {
    const matchesSearch = doc.nom_modele.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesGroup = selectedGroupNav === 'all' || doc.groupe === selectedGroupNav;
    const matchesFamille = selectedFamilleNav === 'all' || doc.famille.toLowerCase() === selectedFamilleNav.toLowerCase();
    return matchesSearch && matchesGroup && matchesFamille;
  });

  // Grouper les documents par Groupe puis par Famille
  const documentsByGroupAndFamily = availableGroups.reduce((acc, groupe) => {
    const docsInGroup = filteredDocuments.filter(doc => doc.groupe === groupe);
    
    // Grouper par famille au sein du groupe
    const famillesInGroup = [...new Set(docsInGroup.map(doc => doc.famille))].sort();
    const familleGroups = famillesInGroup.reduce((famAcc, famille) => {
      const docsInFamille = docsInGroup.filter(doc => doc.famille === famille);
      famAcc[famille] = docsInFamille;
      return famAcc;
    }, {} as Record<string, ModeleDocument[]>);

    acc[groupe] = {
      familles: familleGroups,
      totalDocuments: docsInGroup.length
    };
    return acc;
  }, {} as Record<string, { familles: Record<string, ModeleDocument[]>, totalDocuments: number }>);

  // Obtenir toutes les familles disponibles pour le filtre
  const availableFamilies = [...new Set(allDocuments.map(doc => doc.famille))].sort();

  return (
    <Dialog open={isOpen} onOpenChange={setIsOpen}>
      <DialogTrigger asChild>
        <Button variant="outline" size="sm">
          <Plus className="h-4 w-4 mr-1" />
          Ajouter
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-4xl max-h-[80vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Sélection de Documents - Navigation par Groupes</DialogTitle>
          <DialogDescription>
            Naviguez par Groupes de Documents → Familles → Documents. 
            Choisissez librement n'importe quel document de n'importe quel groupe pour la famille "{famille.famille_nom}".
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          {/* Contrôles de navigation */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Navigation par groupe */}
            <div>
              <Label>Groupe de Documents</Label>
              <Select value={selectedGroupNav} onValueChange={setSelectedGroupNav}>
                <SelectTrigger>
                  <SelectValue placeholder="Tous les groupes" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">
                    <div className="flex items-center gap-2">
                      <FolderOpen className="h-4 w-4" />
                      Tous les groupes
                    </div>
                  </SelectItem>
                  {availableGroups.map(groupe => {
                    const count = documentsByGroupAndFamily[groupe]?.totalDocuments || 0;
                    return (
                      <SelectItem key={groupe} value={groupe}>
                        <div className="flex items-center gap-2">
                          <Folder className="h-4 w-4" />
                          {groupe}
                          <Badge variant="secondary" className="text-xs">
                            {count} doc{count !== 1 ? 's' : ''}
                          </Badge>
                        </div>
                      </SelectItem>
                    );
                  })}
                </SelectContent>
              </Select>
            </div>

            {/* Navigation par famille */}
            <div>
              <Label>Famille de Documents</Label>
              <Select value={selectedFamilleNav} onValueChange={setSelectedFamilleNav}>
                <SelectTrigger>
                  <SelectValue placeholder="Toutes les familles" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">
                    <div className="flex items-center gap-2">
                      <FolderOpen className="h-4 w-4" />
                      Toutes les familles
                    </div>
                  </SelectItem>
                  {availableFamilies.map(famille => {
                    const count = filteredDocuments.filter(doc => doc.famille === famille).length;
                    return (
                      <SelectItem key={famille} value={famille}>
                        <div className="flex items-center gap-2">
                          <Folder className="h-4 w-4" />
                          {famille}
                          <Badge variant="secondary" className="text-xs">
                            {count} doc{count !== 1 ? 's' : ''}
                          </Badge>
                        </div>
                      </SelectItem>
                    );
                  })}
                </SelectContent>
              </Select>
            </div>

            {/* Recherche */}
            <div>
              <Label htmlFor="search">Rechercher</Label>
              <div className="relative">
                <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
                <Input
                  id="search"
                  placeholder="Nom du document..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-8"
                />
              </div>
            </div>
          </div>

          {/* Affichage par groupes et familles */}
          {loading ? (
            <div className="text-center py-8">Chargement des documents...</div>
          ) : (
            <div className="space-y-4 max-h-96 overflow-y-auto">
              {/* Afficher tous les groupes même s'ils sont vides */}
              {availableGroups.map((groupeName) => {
                const groupData = documentsByGroupAndFamily[groupeName];
                const totalDocuments = groupData?.totalDocuments || 0;
                const familles = groupData?.familles || {};
                
                // Afficher seulement si on est en mode "all" ou si c'est le groupe sélectionné
                if (selectedGroupNav !== 'all' && selectedGroupNav !== groupeName) {
                  return null;
                }

                return (
                  <div key={groupeName} className="border-2 rounded-lg p-4 bg-card">
                    <div className="flex items-center gap-2 mb-4">
                      <FolderOpen className="h-6 w-6 text-primary" />
                      <h2 className="text-lg font-bold">{groupeName}</h2>
                      <Badge variant="default" className="text-sm">
                        {totalDocuments} document{totalDocuments !== 1 ? 's' : ''}
                      </Badge>
                      {totalDocuments === 0 && (
                        <Badge variant="outline" className="text-sm">Vide</Badge>
                      )}
                    </div>
                    
                    {/* Afficher les familles dans ce groupe */}
                    {totalDocuments === 0 ? (
                      <p className="text-sm text-muted-foreground italic ml-4">
                        Aucun document disponible dans ce groupe
                      </p>
                    ) : (
                      <div className="space-y-3 ml-4">
                        {Object.entries(familles).map(([familleName, documents]) => {
                          // Filtrer selon la famille sélectionnée
                          if (selectedFamilleNav !== 'all' && selectedFamilleNav !== familleName) {
                            return null;
                          }

                        return (
                          <div key={familleName} className="border rounded-lg p-3 bg-muted/30">
                            <div className="flex items-center gap-2 mb-3">
                              <Folder className="h-5 w-5 text-secondary-foreground" />
                              <h3 className="font-semibold">{familleName}</h3>
                              <Badge variant="outline" className="text-xs">
                                {documents.length} document{documents.length !== 1 ? 's' : ''}
                              </Badge>
                            </div>
                            
                            {documents.length === 0 ? (
                              <p className="text-sm text-muted-foreground italic ml-6">
                                Aucun document dans cette famille
                              </p>
                            ) : (
                              <div className="space-y-2">
                                {documents.map((document) => (
                                  <div
                                    key={document.id}
                                    className="flex items-center space-x-3 p-3 border rounded hover:bg-background ml-2"
                                  >
                                    <Checkbox
                                      id={document.id}
                                      checked={selectedDocuments.includes(document.id)}
                                      onCheckedChange={() => handleDocumentToggle(document.id)}
                                    />
                                    <div className="flex-1">
                                      <div className="flex items-center gap-2">
                                        <FileText className="h-4 w-4" />
                                        <label 
                                          htmlFor={document.id}
                                          className="font-medium cursor-pointer"
                                        >
                                          {document.nom_modele}
                                        </label>
                                        <Badge variant="secondary" className="text-xs">
                                          {document.type_document}
                                        </Badge>
                                      </div>
                                    </div>
                                  </div>
                                ))}
                              </div>
                            )}
                          </div>
                        );
                      })}
                      </div>
                    )}
                  </div>
                );
              })}

              {/* Message si aucun groupe */}
              {availableGroups.length === 0 && (
                <div className="text-center py-8 text-muted-foreground">
                  Aucun groupe de documents configuré
                </div>
              )}
            </div>
          )}

          {/* Actions */}
          {selectedDocuments.length > 0 && (
            <div className="flex items-center justify-between pt-4 border-t">
              <Badge variant="outline">
                {selectedDocuments.length} document(s) sélectionné(s)
              </Badge>
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  onClick={() => {
                    setSelectedDocuments([]);
                    setSelectedGroupNav('all');
                    setSelectedFamilleNav('all');
                    setSearchTerm('');
                    setIsOpen(false);
                  }}
                >
                  Annuler
                </Button>
                <Button
                  onClick={handleLinkDocuments}
                  disabled={submitting}
                >
                  {submitting ? 'Liaison en cours...' : 'Lier les documents'}
                </Button>
              </div>
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}