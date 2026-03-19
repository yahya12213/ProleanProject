import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Badge } from '@/components/ui/badge';
import { useToast } from '@/hooks/use-toast';
import { supabase } from '@/integrations/supabase/client';
import { Download, FileText, Loader2, User, FileCheck, FolderOpen } from 'lucide-react';

interface Etudiant {
  id: string;
  nom: string;
  prenom: string;
  email?: string;
  photo_url?: string;
  cin?: string;
  date_naissance?: string;
  lieu_naissance?: string;
}

interface InscriptionInfo {
  id: string;
  statut_inscription: string;
  classe_id?: string;
  session_en_ligne_id?: string;
  classes?: {
    formation_id: string;
    nom_classe: string;
    date_debut: string;
    date_fin: string;
    formations?: {
      titre: string;
    };
  };
  sessions_en_ligne?: {
    formation_id: string;
    nom_session: string;
    date_debut: string;
    date_fin: string;
    formations?: {
      titre: string;
    };
  };
}

interface ModeleDocument {
  id: string;
  nom_modele: string;
  type_document: string;
  format_page: string;
  orientation: string;
  image_recto_url?: string;
  image_verso_url?: string;
  formation_id: string;
  famille?: string;
  formations?: {
    titre: string;
  };
}

interface GroupeDocument {
  id: string;
  nom: string;
  description?: string;
  is_active: boolean;
}

interface FamilleDocument {
  groupe: string;
  famille: string;
  count: number;
  modeles: ModeleDocument[];
}

interface DocumentGenere {
  id: string;
  fichier_url: string;
  generated_at: string;
  etudiant_id: string;
  modele_id: string;
  etudiants?: {
    nom: string;
    prenom: string;
  };
  modeles_documents?: {
    nom_modele: string;
    type_document: string;
  };
}

const GenerationDocuments = () => {
  const [etudiants, setEtudiants] = useState<Etudiant[]>([]);
  const [modeles, setModeles] = useState<ModeleDocument[]>([]);
  const [groupes, setGroupes] = useState<GroupeDocument[]>([]);
  const [familles, setFamilles] = useState<FamilleDocument[]>([]);
  const [documentsGeneres, setDocumentsGeneres] = useState<DocumentGenere[]>([]);
  const [selectedEtudiant, setSelectedEtudiant] = useState<string>('');
  const [selectedGroupe, setSelectedGroupe] = useState<string>('');
  const [selectedFamille, setSelectedFamille] = useState<string>('');
  const [selectedModeleIds, setSelectedModeleIds] = useState<string[]>([]);
  const [selectedEtudiantInfo, setSelectedEtudiantInfo] = useState<InscriptionInfo | null>(null);
  const [datePreview, setDatePreview] = useState<{ original: { debut: string, fin: string }, adjusted: { debut: string, fin: string } } | null>(null);
  const [isGenerating, setIsGenerating] = useState(false);
  const [loading, setLoading] = useState(true);
  const { toast } = useToast();

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      
      // Charger les étudiants
      const { data: etudiantsData, error: etudiantsError } = await supabase
        .from('etudiants')
        .select('*')
        .order('nom');

      if (etudiantsError) throw etudiantsError;
      setEtudiants(etudiantsData || []);

      // Charger les groupes
      const { data: groupesData, error: groupesError } = await supabase
        .from('groupes_documents')
        .select('*')
        .eq('is_active', true)
        .order('nom');

      if (groupesError) throw groupesError;
      setGroupes(groupesData || []);

      // Charger les modèles de documents avec les formations
      const { data: modelesData, error: modelesError } = await supabase
        .from('modeles_documents')
        .select(`
          *,
          formations!inner(titre)
        `)
        .eq('is_active', true)
        .order('nom_modele');

      if (modelesError) throw modelesError;
      setModeles(modelesData || []);

      // Organiser par groupes et familles
      const famillesMap = new Map<string, ModeleDocument[]>();
      modelesData?.forEach(modele => {
        const groupe = modele.groupe || 'Général';
        const famille = modele.famille || 'Général';
        const key = `${groupe}__${famille}`;
        if (!famillesMap.has(key)) {
          famillesMap.set(key, []);
        }
        famillesMap.get(key)!.push(modele);
      });

      const famillesArray = Array.from(famillesMap.entries()).map(([key, modeles]) => {
        const [groupe, famille] = key.split('__');
        return {
          groupe,
          famille,
          count: modeles.length,
          modeles
        };
      });

      setFamilles(famillesArray);

      // Charger l'historique des documents générés
      const { data: documentsData, error: documentsError } = await supabase
        .from('documents_generes')
        .select(`
          *,
          etudiants(nom, prenom),
          modeles_documents(nom_modele, type_document)
        `)
        .order('generated_at', { ascending: false })
        .limit(10);

      if (documentsError) throw documentsError;
      setDocumentsGeneres(documentsData || []);

    } catch (error: any) {
      toast({
        title: "Erreur de chargement",
        description: error.message,
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const loadEtudiantInfo = async (etudiantId: string) => {
    try {
      // Récupérer les informations d'inscription de l'étudiant
      const { data: inscriptions, error } = await supabase
        .from('inscriptions')
        .select(`
          id,
          statut_inscription,
          classe_id,
          session_en_ligne_id,
          classes!inner(
            formation_id,
            nom_classe,
            date_debut,
            date_fin,
            formations(titre)
          ),
          sessions_en_ligne(
            formation_id,
            nom_session,
            date_debut,
            date_fin,
            formations(titre)
          )
        `)
        .eq('etudiant_id', etudiantId)
        .limit(1);

      if (error) throw error;

      const inscription = inscriptions?.[0];
      if (inscription) {
        setSelectedEtudiantInfo(inscription);
        
        // Calculer l'aperçu des dates
        const formationData = inscription.classes || inscription.sessions_en_ligne;
        if (formationData) {
          const dateDebut = new Date(formationData.date_debut);
          const dateFin = new Date(formationData.date_fin);
          const aujourdhui = new Date();
          
          // Calculer les nouvelles dates selon la règle métier
          let nouvelleDateDebut = dateDebut;
          let nouvelleDateFin = dateFin;
          
          if (dateDebut > aujourdhui) {
            // Décaler la période vers le passé
            const duree = dateFin.getTime() - dateDebut.getTime();
            nouvelleDateFin = new Date(aujourdhui);
            nouvelleDateDebut = new Date(nouvelleDateFin.getTime() - duree);
          }
          
          setDatePreview({
            original: {
              debut: dateDebut.toLocaleDateString('fr-FR'),
              fin: dateFin.toLocaleDateString('fr-FR')
            },
            adjusted: {
              debut: nouvelleDateDebut.toLocaleDateString('fr-FR'),
              fin: nouvelleDateFin.toLocaleDateString('fr-FR')
            }
          });
        }
      } else {
        setSelectedEtudiantInfo(null);
        setDatePreview(null);
      }
    } catch (error: any) {
      console.error('Erreur lors du chargement des infos étudiant:', error);
      setSelectedEtudiantInfo(null);
      setDatePreview(null);
    }
  };

  const generateDocument = async () => {
    if (!selectedEtudiant) {
      toast({
        title: "Sélection incomplète",
        description: "Veuillez sélectionner un étudiant",
        variant: "destructive"
      });
      return;
    }

    if (!selectedGroupe || !selectedFamille) {
      toast({
        title: "Sélection incomplète",
        description: "Veuillez sélectionner un groupe et une famille de documents",
        variant: "destructive"
      });
      return;
    }

    // Vérifier le statut d'éligibilité
    if (!selectedEtudiantInfo || selectedEtudiantInfo.statut_inscription !== 'valide') {
      toast({
        title: "Étudiant non éligible",
        description: "L'étudiant doit avoir un statut 'valide' pour générer un document",
        variant: "destructive"
      });
      return;
    }

    try {
      setIsGenerating(true);

      // Génération par famille
      const selectedFamilyModels = familles.find(f => f.groupe === selectedGroupe && f.famille === selectedFamille)?.modeles || [];
      const hasExplicitSelection = selectedModeleIds.length > 0;
      const body: any = {
        etudiant_id: selectedEtudiant,
        famille: selectedFamille,
      };
      if (hasExplicitSelection) {
        body.modele_ids = selectedModeleIds;
      }
      const { data, error } = await supabase.functions.invoke('generate-family-documents', { body });

      if (error) throw error;

      if (data?.success) {
        const { results } = data;
        const successCount = results.successful.length;
        const totalCount = results.total;
        
        toast({
          title: "Documents générés",
          description: `${successCount}/${totalCount} documents générés avec succès pour la famille "${selectedFamille}"`
        });
        
        // Télécharger le PDF combiné s'il est disponible, sinon chaque document
        if (results?.combined?.filePath) {
          await downloadDocument(results.combined.filePath, results.combined.fileName);
        } else {
          for (const result of results.successful) {
            await downloadDocument(result.filePath, result.fileName);
          }
        }
        
        if (results.failed.length > 0) {
          console.warn('Échecs de génération:', results.failed);
        }
      } else {
        throw new Error(data?.error || "Erreur de génération de famille");
      }
      
      // Recharger l'historique
      loadData();
      
      // Reset selections
      setSelectedEtudiant('');
      setSelectedGroupe('');
      setSelectedFamille('');
      setSelectedEtudiantInfo(null);
      setDatePreview(null);

    } catch (error: any) {
      toast({
        title: "Erreur de génération",
        description: error.message,
        variant: "destructive"
      });
    } finally {
      setIsGenerating(false);
    }
  };

  const downloadDocument = async (fichierUrl: string, fileName?: string) => {
    try {
      const { data, error } = await supabase.storage
        .from('generated-documents')
        .download(fichierUrl);

      if (error) throw error;

      // Créer un lien de téléchargement
      const url = URL.createObjectURL(data);
      const link = document.createElement('a');
      link.href = url;
      link.download = fileName || 'document.pdf';
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);

    } catch (error: any) {
      toast({
        title: "Erreur de téléchargement",
        description: error.message,
        variant: "destructive"
      });
    }
  };

  const getEtudiantFullName = (etudiant: Etudiant | { nom: string; prenom: string }) => {
    return `${etudiant.prenom} ${etudiant.nom}`;
  };

  if (loading) {
    return <div className="flex justify-center p-8">Chargement...</div>;
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-bold">Génération de Documents PDF</h2>
      </div>

      {/* Interface de génération */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FileText className="h-5 w-5" />
            Générer un nouveau document
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="text-sm font-medium mb-2 block">Sélectionner un étudiant</label>
              <Select value={selectedEtudiant} onValueChange={(value) => {
                setSelectedEtudiant(value);
                if (value) {
                  loadEtudiantInfo(value);
                } else {
                  setSelectedEtudiantInfo(null);
                  setDatePreview(null);
                }
              }}>
                <SelectTrigger>
                  <SelectValue placeholder="Choisir un étudiant">
                    {selectedEtudiant && (
                      <div className="flex items-center gap-2">
                        <User className="h-4 w-4" />
                        {getEtudiantFullName(etudiants.find(e => e.id === selectedEtudiant)!)}
                      </div>
                    )}
                  </SelectValue>
                </SelectTrigger>
                <SelectContent>
                  {etudiants.map((etudiant) => (
                    <SelectItem key={etudiant.id} value={etudiant.id}>
                      <div className="flex items-center gap-2">
                        <User className="h-4 w-4" />
                        {getEtudiantFullName(etudiant)}
                        {etudiant.email && (
                          <span className="text-xs text-muted-foreground">
                            ({etudiant.email})
                          </span>
                        )}
                      </div>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div>
              <label className="text-sm font-medium mb-2 block">Sélectionner un groupe</label>
              <Select value={selectedGroupe} onValueChange={(value) => {
                setSelectedGroupe(value);
                setSelectedFamille(''); // Reset famille when groupe changes
                setSelectedModeleIds([]);
              }}>
                <SelectTrigger>
                  <SelectValue placeholder="Choisir un groupe">
                    {selectedGroupe && (
                      <div className="flex items-center gap-2">
                        <FolderOpen className="h-4 w-4" />
                        {selectedGroupe}
                      </div>
                    )}
                  </SelectValue>
                </SelectTrigger>
                <SelectContent>
                  {groupes.map((groupe) => (
                    <SelectItem key={groupe.id} value={groupe.nom}>
                      <div className="flex items-center gap-2">
                        <FolderOpen className="h-4 w-4" />
                        {groupe.nom}
                      </div>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div>
              <label className="text-sm font-medium mb-2 block">Sélectionner une famille</label>
              <Select 
                value={selectedFamille} 
                onValueChange={(value) => { setSelectedFamille(value); setSelectedModeleIds([]); }}
                disabled={!selectedGroupe}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Choisir une famille">
                    {selectedFamille && (
                      <div className="flex items-center gap-2">
                        <FileCheck className="h-4 w-4" />
                        {selectedFamille}
                      </div>
                    )}
                  </SelectValue>
                </SelectTrigger>
                <SelectContent>
                  {familles
                    .filter(famille => famille.groupe === selectedGroupe)
                    .map((famille) => (
                    <SelectItem key={`${famille.groupe}__${famille.famille}`} value={famille.famille}>
                      <div>
                        <div className="flex items-center gap-2">
                          <FileCheck className="h-4 w-4" />
                          {famille.famille}
                        </div>
                        <div className="text-xs text-muted-foreground">
                          {famille.count} document{famille.count > 1 ? 's' : ''} disponible{famille.count > 1 ? 's' : ''}
                        </div>
                      </div>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          {/* Affichage des informations de validation et d'aperçu des dates */}
          {selectedEtudiantInfo && (
            <div className="space-y-4 p-4 bg-muted/30 rounded-lg">
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium">Statut d'éligibilité:</span>
                <Badge 
                  variant={selectedEtudiantInfo.statut_inscription === 'valide' ? 'default' : 'destructive'}
                >
                  {selectedEtudiantInfo.statut_inscription}
                </Badge>
              </div>
              
              {datePreview && (
                <div className="space-y-2">
                  <div className="text-sm font-medium">Aperçu des dates dans le document:</div>
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div>
                      <div className="text-muted-foreground">Dates originales:</div>
                      <div>Du {datePreview.original.debut} au {datePreview.original.fin}</div>
                    </div>
                    <div>
                      <div className="text-muted-foreground">Dates ajustées:</div>
                      <div>Du {datePreview.adjusted.debut} au {datePreview.adjusted.fin}</div>
                      {datePreview.original.debut !== datePreview.adjusted.debut && (
                        <div className="text-xs text-orange-600 mt-1">
                          ⚠️ Dates automatiquement ajustées
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Sélection précise des modèles de la famille */}
          {selectedGroupe && selectedFamille && (
            <div className="p-4 border rounded-lg space-y-3">
              <div className="text-sm font-medium">Sélectionner les modèles à générer (facultatif)</div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                {familles.find(f => f.groupe === selectedGroupe && f.famille === selectedFamille)?.modeles.map((m) => (
                  <label key={m.id} className="flex items-center gap-2 text-sm">
                    <input
                      type="checkbox"
                      checked={selectedModeleIds.includes(m.id)}
                      onChange={(e) => {
                        setSelectedModeleIds((prev) => e.target.checked ? [...prev, m.id] : prev.filter(id => id !== m.id));
                      }}
                    />
                    {m.nom_modele} <span className="text-muted-foreground">({m.format_page} • {m.orientation})</span>
                  </label>
                ))}
              </div>
            </div>
          )}

          <div className="flex justify-center pt-4">
            <Button 
              onClick={generateDocument}
              disabled={!selectedEtudiant || !selectedGroupe || !selectedFamille || isGenerating}
              size="lg"
            >
              {isGenerating ? (
                <>
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  Génération en cours...
                </>
              ) : (
                <>
                  <FileText className="h-4 w-4 mr-2" />
                  Générer les Documents
                </>
              )}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Historique des documents générés */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Download className="h-5 w-5" />
            Documents récemment générés
          </CardTitle>
        </CardHeader>
        <CardContent>
          {documentsGeneres.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              Aucun document généré récemment
            </div>
          ) : (
            <div className="space-y-3">
              {documentsGeneres.map((doc) => (
                <div 
                  key={doc.id} 
                  className="flex items-center justify-between p-4 border rounded-lg hover:bg-gray-50"
                >
                  <div className="flex items-center gap-3">
                    <FileText className="h-5 w-5 text-blue-600" />
                    <div>
                      <div className="font-medium">
                        {doc.etudiants && getEtudiantFullName(doc.etudiants)}
                      </div>
                      <div className="text-sm text-muted-foreground">
                        {doc.modeles_documents?.nom_modele} • {doc.modeles_documents?.type_document}
                      </div>
                      <div className="text-xs text-muted-foreground">
                        Généré le {new Date(doc.generated_at).toLocaleDateString('fr-FR', {
                          day: '2-digit',
                          month: '2-digit',
                          year: 'numeric',
                          hour: '2-digit',
                          minute: '2-digit'
                        })}
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant="outline">PDF</Badge>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => downloadDocument(
                        doc.fichier_url,
                        `${doc.etudiants && getEtudiantFullName(doc.etudiants)}_${doc.modeles_documents?.type_document}.pdf`
                      )}
                    >
                      <Download className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
};

export default GenerationDocuments;