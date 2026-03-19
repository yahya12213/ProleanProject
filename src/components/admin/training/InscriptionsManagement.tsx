import React, { useState, useEffect, useCallback } from 'react';
import { useParams } from 'react-router-dom';
import { useNavigation } from '@/contexts/NavigationContext';
import { Breadcrumbs } from '@/components/Breadcrumbs';
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Checkbox } from "@/components/ui/checkbox";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { useToast } from "@/hooks/use-toast";
import { Plus, Edit, Trash2, Users, Calendar, MapPin, AlertCircle, CreditCard, ArrowLeft, Check, X, MoreVertical, FileText, Award } from 'lucide-react';
import { AjouterEtudiantModal } from './AjouterEtudiantModal';
import EditStudentModal from './EditStudentModal';
import type { Student, Inscription, Classe, FormationLivrable } from '@/types/models';
import type { FormationFamille } from '@/types/models';
import ClassStatistics from './ClassStatistics';
import { GestionPaiementsModal } from './GestionPaiementsModal';
import { PhotoModal } from './PhotoModal';
import { calculatePaymentInfo, formatAmount, getRemainingAmountColor } from '@/lib/payment-utils';


export default function InscriptionsManagement() {
  const { id: classeId } = useParams<{ id: string }>();
  const { goBack, setBreadcrumbs } = useNavigation();
  const { toast } = useToast();
  
  const [inscriptions, setInscriptions] = useState<Inscription[]>([]);
  const [classe, setClasse] = useState<Classe | null>(null);
  const [loading, setLoading] = useState(true);
  const [showAddModal, setShowAddModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [selectedStudentId, setSelectedStudentId] = useState<string | null>(null);
  const [showPaymentModal, setShowPaymentModal] = useState(false);
  const [showPhotoModal, setShowPhotoModal] = useState(false);
  const [selectedInscription, setSelectedInscription] = useState<Inscription | null>(null);
  const [selectedStudents, setSelectedStudents] = useState<Set<string>>(new Set());
  const [selectAll, setSelectAll] = useState(false);
  const [isGenerating, setIsGenerating] = useState(false);
  const [formationLivrables, setFormationLivrables] = useState<FormationLivrable[]>([]);
  const [formationFamilles, setFormationFamilles] = useState<Record<string, FormationFamille[]>>({});

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      // Charger les détails de la classe
      const classeDetails = await fetch(`/api/classes/${classeId}`);
      const classeData: Classe = await classeDetails.json();
      setClasse(classeData);

      // Charger les inscriptions
      const inscriptionsDetails = await fetch(`/api/inscriptions?classeId=${classeId}`);
      const inscriptionsData = await inscriptionsDetails.json();
      setInscriptions(inscriptionsData);

      // Générer des identifiants uniques pour les inscriptions sans identifiant
      if (inscriptionsData) {
        for (const inscription of inscriptionsData) {
          if (!inscription.student_id_unique) {
            const response = await fetch(`/api/inscriptions/${inscription.id}/generate-unique-id`, {
              method: 'POST',
            });
            const { studentId } = await response.json();
            inscription.student_id_unique = studentId;
          }
        }
      }

      // Charger les paiements pour chaque inscription
      const inscriptionsWithPaiements = await Promise.all(
        (inscriptionsData || []).map(async (inscription) => {
          const paiementsDetails = await fetch(`/api/paiements?inscriptionId=${inscription.id}`);
          const paiementsData = await paiementsDetails.json();
          return {
            ...inscription,
            paiements: paiementsData || []
          };
        })
      );

      setInscriptions(inscriptionsWithPaiements);
    } catch (error) {
      console.error('Erreur lors du chargement des données :', error);
      toast({
        title: 'Erreur',
        description: 'Une erreur est survenue lors du chargement des données.',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  }, [classeId, toast]);

  useEffect(() => {
    if (classeId) {
      loadData();
    }
  }, [classeId, loadData]);

  useEffect(() => {
    if (classe) {
      setBreadcrumbs([
        { label: 'Administration', path: '/administration' },
        { label: 'Gestion des Classes', path: '/administration/formations/classes' },
        { label: `Inscriptions - ${classe.formations?.titre || 'Classe'}`, path: `/administration/classe/${classeId}/inscriptions` }
      ]);
    }
  }, [classe, classeId, setBreadcrumbs]);

  // Remplacement de Supabase par une API Express locale
  useEffect(() => {
    const loadInscriptions = async () => {
      try {
        const response = await fetch('/api/inscriptions');
        const data = await response.json();

        setInscriptions(data || []);
      } catch (error) {
        console.error('Error loading inscriptions:', error);
        toast({
          title: "Erreur",
          description: "Impossible de charger les inscriptions",
          variant: "destructive"
        });
      }
    };

    loadInscriptions();
  }, [toast]);

  const handleDeleteInscription = async (inscriptionId: string) => {
    if (!confirm('Êtes-vous sûr de vouloir supprimer cette inscription ?')) return;

    try {
      const response = await fetch(`/api/inscriptions/${inscriptionId}`, {
        method: 'DELETE',
      });

      if (!response.ok) {
        throw new Error('Failed to delete inscription');
      }

      toast({
        title: "Succès",
        description: "Inscription supprimée avec succès",
      });

      // Reload inscriptions after deletion
      loadData();
    } catch (error) {
      console.error('Erreur lors de la suppression de l\'inscription:', error);
      toast({
        title: "Erreur",
        description: "Impossible de supprimer l'inscription",
        variant: "destructive",
      });
    }
  };

  const getStatutBadgeVariant = (statut: string) => {
    switch (statut?.toLowerCase()) {
      case 'active':
        return 'default';
      case 'inactive':
        return 'destructive';
      default:
        return 'outline';
    }
  };

  const getInscriptionStatutVariant = (statut: string) => {
    switch (statut?.toLowerCase()) {
      case 'confirmee':
        return 'default';
      case 'en_attente':
        return 'secondary';
      case 'annulee':
        return 'destructive';
      default:
        return 'outline';
    }
  };

  const handleEditStudent = (inscription: Inscription) => {
    console.log('🎯 handleEditStudent called with:', inscription);
    console.log('🎯 Student data:', inscription.etudiants);
    
    setSelectedStudentId(inscription.id);
    
    // Utiliser setTimeout pour s'assurer que l'état est mis à jour après setSelectedStudent
    setTimeout(() => {
      setShowEditModal(true);
      console.log('🎯 Modal state set - selectedStudent:', inscription, 'showEditModal:', true);
    }, 0);
  };

  const calculateRemainingAmount = (inscription: Inscription): number => {
    const paymentInfo = calculatePaymentInfo(inscription);
    return paymentInfo.remaining;
  };

  const getTotalPaid = (inscription: Inscription): number => {
    const paymentInfo = calculatePaymentInfo(inscription);
    return paymentInfo.totalPaid;
  };

  const handleManagePayments = (inscription: Inscription) => {
    setSelectedInscription(inscription);
    setShowPaymentModal(true);
  };

  const handleShowPhoto = (inscription: Inscription) => {
    setSelectedInscription(inscription);
    setShowPhotoModal(true);
  };

  const getInscriptionRemainingColor = (inscription: Inscription): string => {
    const paymentInfo = calculatePaymentInfo(inscription);
    return getRemainingAmountColor(paymentInfo.remaining, paymentInfo.formationPrice);
  };

  const handleSelectStudent = (inscriptionId: string, checked: boolean) => {
    const newSelected = new Set(selectedStudents);
    if (checked) {
      newSelected.add(inscriptionId);
    } else {
      newSelected.delete(inscriptionId);
    }
    setSelectedStudents(newSelected);
    setSelectAll(newSelected.size === inscriptions.length);
  };

  const handleSelectAll = (checked: boolean) => {
    if (checked) {
      setSelectedStudents(new Set(inscriptions.map(i => i.id)));
    } else {
      setSelectedStudents(new Set());
    }
    setSelectAll(checked);
  };

  const handleMassValidation = async (statut: 'valide' | 'non_valide') => {
    if (selectedStudents.size === 0) return;

    const action = statut === 'valide' ? 'valider' : 'invalider';
    if (!confirm(`Êtes-vous sûr de vouloir ${action} ${selectedStudents.size} étudiant(s) ?`)) return;

    try {
      const response = await fetch(`/api/inscriptions/bulk-update-validation`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ids: Array.from(selectedStudents),
          statut_compte: statut
        })
      });
      const result = await response.json();
      if (!response.ok || result.error) throw new Error(result.error || 'Erreur API');

      toast({
        title: "Succès",
        description: `${selectedStudents.size} étudiant(s) ${statut === 'valide' ? 'validé(s)' : 'invalidé(s)'} avec succès`
      });

      setSelectedStudents(new Set());
      setSelectAll(false);
      loadData();
    } catch (error) {
      console.error('Error updating validations:', error);
      toast({
        title: "Erreur",
        description: "Impossible de mettre à jour les validations",
        variant: "destructive"
      });
    }
  };

  const handleUpdateValidation = async (inscriptionId: string, statut: 'valide' | 'non_valide') => {
    try {
      const response = await fetch(`/api/inscriptions/${inscriptionId}/update-validation`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ statut_compte: statut })
      });
      const result = await response.json();
      if (!response.ok || result.error) throw new Error(result.error || 'Erreur API');

      toast({
        title: "Succès",
        description: `Statut de validation mis à jour`
      });

      loadData();
    } catch (error) {
      console.error('Error updating validation:', error);
      toast({
        title: "Erreur",
        description: "Impossible de mettre à jour le statut",
        variant: "destructive"
      });
    }
  };

  const getRowClassName = (statut_compte?: string): string => {
    if (statut_compte === 'valide') return 'bg-background';
    return 'bg-red-50 border-red-200';
  };

  const handleGenerateFormationDocument = async (livrable: FormationLivrable) => {
    // Correction du type pour `livrable`
    const validSelectedStudents = inscriptions.filter(inscription => 
      selectedStudents.has(inscription.id) && inscription.statut_compte === 'valide'
    );

    if (validSelectedStudents.length === 0) {
      toast({
        title: "Aucun candidat valide sélectionné",
        description: "Seuls les candidats avec un statut 'valide' peuvent avoir des documents générés",
        variant: "destructive"
      });
      return;
    }

    const totalSelected = selectedStudents.size;
    const invalidCount = totalSelected - validSelectedStudents.length;

    let confirmMessage = `Êtes-vous sûr de vouloir générer ${livrable.nom_modele} pour ${validSelectedStudents.length} étudiant(s) valide(s) ?`;
    if (invalidCount > 0) {
      confirmMessage += `\n\nNote: ${invalidCount} étudiant(s) non valide(s) seront ignorés.`;
    }

    if (!confirm(confirmMessage)) return;

    try {
      setIsGenerating(true);

      let successCount = 0;
      let errorCount = 0;

      for (const inscription of validSelectedStudents) {
        try {
          const response = await fetch(`/api/documents/generate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              etudiant_id: inscription.etudiant_id,
              modele_id: livrable.id
            })
          });
          const result = await response.json();
          if (!response.ok || result.error) throw new Error(result.error || 'Erreur API');

          if (result.success && result.filePath) {
            // Optionally fetch signed URL if needed
            // const signedUrlResponse = await fetch(`/api/documents/signed-url?filePath=${encodeURIComponent(result.filePath)}`);
            // const signedUrl = await signedUrlResponse.json();
            // console.log('Document généré avec succès:', signedUrl.url);
            successCount++;
          }
        } catch (error) {
          console.error('Erreur lors de la génération du document:', error);
          errorCount++;
        }
      }

      toast({
        title: "Génération terminée",
        description: `${successCount} document(s) généré(s) avec succès, ${errorCount} erreur(s)`
      });
    } catch (error) {
      console.error('Erreur lors de la génération des documents:', error);
      toast({
        title: "Erreur",
        description: "Impossible de générer les documents",
        variant: "destructive"
      });
    } finally {
      setIsGenerating(false);
    }
  };
  
  const handleGenerateFormationFamily = async (famille: string) => {
    // Filtrer pour ne prendre que les étudiants valides sélectionnés
    const validSelectedStudents = inscriptions.filter(inscription => 
      selectedStudents.has(inscription.id) && inscription.statut_compte === 'valide'
    );

    if (validSelectedStudents.length === 0) {
      toast({
        title: "Aucun candidat valide sélectionné",
        description: "Seuls les candidats avec un statut 'valide' peuvent avoir des documents générés",
        variant: "destructive"
      });
      return;
    }

    const totalSelected = selectedStudents.size;
    const invalidCount = totalSelected - validSelectedStudents.length;

    let confirmMessage = `Êtes-vous sûr de vouloir générer tous les documents de la famille "${famille}" pour ${validSelectedStudents.length} étudiant(s) valide(s) ?`;
    if (invalidCount > 0) {
      confirmMessage += `\n\nNote: ${invalidCount} étudiant(s) non valide(s) seront ignorés.`;
    }

    if (!confirm(confirmMessage)) return;

    try {
      setIsGenerating(true);

      // Préparer la liste des étudiants valides sélectionnés
      const etudiantIds = validSelectedStudents.map(i => i.etudiant_id);
      console.log(`Batch génération famille "${famille}" pour ${etudiantIds.length} étudiant(s)`);

      // Appeler la nouvelle fonction batch pour générer et COMBINER en un seul PDF
      const response = await fetch(`/api/documents/generate-family`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          etudiant_ids: etudiantIds,
          famille: famille
        })
      });
      const result = await response.json();
      if (!response.ok || result.error) throw new Error(result.error || 'Erreur lors de la génération batch');

      const results = result.results;
      const totalSuccessCount = results?.successful?.length || 0;
      const totalErrorCount = results?.failed?.length || 0;

      if (results?.combined?.filePath) {
        // Optionally fetch signed URL if needed
        // const signedUrlResponse = await fetch(`/api/documents/signed-url?filePath=${encodeURIComponent(results.combined.filePath)}`);
        // const signedUrl = await signedUrlResponse.json();
        // console.log('PDF combiné généré avec succès:', signedUrl.url);
      }

      toast({
        title: "Génération terminée",
        description: `${totalSuccessCount} document(s) généré(s) avec succès, ${totalErrorCount} erreur(s)`
      });
    } catch (error) {
      console.error('Erreur lors de la génération batch:', error);
      toast({
        title: "Erreur",
        description: "Impossible de générer les documents batch",
        variant: "destructive"
      });
    } finally {
      setIsGenerating(false);
    }
  };

  const handleGenerateAllDocumentsForStudent = async (etudiantId: string) => {
    // Récupérer une formation_id valide depuis la classe ou corps formation
    let formationId = classe?.formation_id;
    const corpsFormationId = classe?.corps_formation_id || null;
    
    if (!formationId && corpsFormationId) {
      // Essayer de trouver une formation par défaut pour ce corps de formation
      const response = await fetch(`/api/formations?corps_formation_id=${corpsFormationId}&is_active=true`);
      const formations = await response.json();
      if (formations && formations.length > 0) {
        formationId = formations[0].id;
      }
    }

    if (!formationId && !corpsFormationId) {
      toast({
        title: "Erreur",
        description: "Impossible de déterminer la formation ou le corps de formation.",
        variant: "destructive",
      });
      return;
    }

    try {
      setIsGenerating(true);
      
      // Get all families for this corps de formation
      let actualCorpsFormationId = corpsFormationId;
      
      if (formationId && !actualCorpsFormationId) {
  const response = await fetch(`/api/formations/${formationId}`);
  const formation = await response.json();
  actualCorpsFormationId = formation?.corps_formation_id;
      }

      if (!actualCorpsFormationId) {
        throw new Error('Corps de formation non trouvé');
      }

  const response = await fetch(`/api/corps-formation-familles?corps_formation_id=${actualCorpsFormationId}&is_active=true`);
  const familles = await response.json();
  if (!familles || familles.length === 0) {
        toast({
          title: "Aucune famille",
          description: "Aucune famille de documents trouvée pour ce corps de formation.",
          variant: "destructive",
        });
        return;
      }

      // Generate documents for each family
      const results = await Promise.all(
        familles.map(famille => 
          fetch('/api/generate-family-documents', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ etudiant_id: etudiantId, famille: famille.famille_nom })
          }).then(r => r.json())
        )
      );

      const successful = results.filter(r => !r.error).length;
      const failed = results.filter(r => r.error).length;

      toast({
        title: "Génération automatique terminée",
        description: `${successful} familles générées, ${failed} échecs`,
        variant: successful > 0 ? "default" : "destructive",
      });
    } catch (error) {
      console.error('Erreur lors de la génération automatique:', error);
      toast({
        title: "Erreur",
        description: "Une erreur est survenue lors de la génération automatique.",
        variant: "destructive",
      });
    } finally {
      setIsGenerating(false);
    }
  };

  const handleGenerateAllDocumentsForAllStudents = async () => {
    const validStudents = inscriptions.filter(i => i.statut_compte === 'valide');
    
    if (validStudents.length === 0) {
      toast({
        title: "Aucun étudiant valide",
        description: "Aucun étudiant avec le statut 'valide' trouvé.",
        variant: "destructive",
      });
      return;
    }

    try {
      setIsGenerating(true);

      // Liste des étudiants à traiter
      const etudiantIds = validStudents.map(i => i.etudiant_id);

      // Familles standard à générer
      const familles = ['badge', 'certif', 'att'];

      // Générer un PDF combiné par famille pour toute la classe
      const results = await Promise.all(
        familles.map((famille) =>
          fetch('/api/generate-family-documents-batch', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ etudiant_ids: etudiantIds, famille })
          }).then(r => r.json())
        )
      );

      const successful = results.filter(r => !r.error && r.data?.success).length;
      const failed = results.length - successful;

      // Télécharger chaque PDF combiné
      for (const r of results) {
        const combined = r.data?.results?.combined;
        if (combined?.filePath) {
          try {
            // Appel à l'API Express pour obtenir l'URL de téléchargement
            const urlResponse = await fetch(`/api/documents/signed-url?filePath=${encodeURIComponent(combined.filePath)}&expires=120`);
            const signedUrl = await urlResponse.json();
            if (signedUrl?.signedUrl) {
              const a = document.createElement('a');
              a.href = signedUrl.signedUrl;
              a.download = combined.fileName || 'combined.pdf';
              a.target = '_blank';
              document.body.appendChild(a);
              a.click();
              document.body.removeChild(a);
            }
          } catch (e) {
            console.warn('Téléchargement échoué pour', combined?.filePath, e);
          }
        }
      }

      toast({
        title: 'Génération en lot terminée',
        description: `${successful} famille(s) générée(s), ${failed} échec(s) pour ${validStudents.length} étudiants`,
        variant: successful > 0 ? 'default' : 'destructive',
      });
    } catch (error) {
      console.error('Erreur lors de la génération en lot:', error);
      toast({
        title: "Erreur",
        description: "Une erreur est survenue lors de la génération en lot.",
        variant: "destructive",
      });
    } finally {
      setIsGenerating(false);
    }
  };

  const handleGenerateDocument = async (type: 'badges' | 'certificats' | 'attestations' | 'cafat' | 'jcbatt') => {
    // Filtrer pour ne prendre que les étudiants valides sélectionnés
    const validSelectedStudents = inscriptions.filter(inscription => 
      selectedStudents.has(inscription.id) && inscription.statut_compte === 'valide'
    );

    if (validSelectedStudents.length === 0) {
      toast({
        title: "Aucun candidat valide sélectionné",
        description: "Seuls les candidats avec un statut 'valide' peuvent avoir des documents générés",
        variant: "destructive"
      });
      return;
    }

    const totalSelected = selectedStudents.size;
    const invalidCount = totalSelected - validSelectedStudents.length;

    const typeLabels = {
      badges: 'badges',
      certificats: 'certificats d\'accomplissements',
      attestations: 'attestations de formation',
      cafat: 'attestations CAFAT',
      jcbatt: 'attestations JCBATT'
    };

    let confirmMessage = `Êtes-vous sûr de vouloir générer les ${typeLabels[type]} pour ${validSelectedStudents.length} étudiant(s) valide(s) ?`;
    if (invalidCount > 0) {
      confirmMessage += `\n\nNote: ${invalidCount} étudiant(s) non valide(s) seront ignorés.`;
    }

    if (!confirm(confirmMessage)) return;

    try {
      setIsGenerating(true);
      
      // Mapper les types aux valeurs de base de données
      const typeMapping = {
        badges: 'badge',
        certificats: 'certificat', 
        attestations: 'attestation',
        cafat: 'attestation',
        jcbatt: 'attestation'
      };

      // Récupérer la formation de la classe pour trouver le bon modèle
      const classeRes = await fetch(`/api/classes/${classeId}`);
      const classeData = await classeRes.json();
      if (!classeData.formation_id) throw new Error('Formation non trouvée pour la classe');

      // D'abord chercher un modèle spécifique à la formation
      let modelesRes = await fetch(`/api/modeles-documents?type_document=${typeMapping[type]}&famille=${typeMapping[type]}&is_active=true&formation_id=${classeData.formation_id}`);
      let modeles = await modelesRes.json();

      // Si aucun modèle trouvé, chercher selon les familles disponibles
      if (!modeles || modeles.length === 0) {
        modelesRes = await fetch(`/api/modeles-documents?famille=${typeMapping[type]}&is_active=true`);
        modeles = await modelesRes.json();
      }

      if (!modeles || modeles.length === 0) {
        toast({
          title: "Modèle non trouvé",
          description: `Aucun modèle actif trouvé pour ${typeLabels[type]}`,
          variant: "destructive"
        });
        return;
      }

      const modele = modeles[0];
      let successCount = 0;
      let errorCount = 0;

      // Générer les documents pour chaque étudiant valide
      for (const inscription of validSelectedStudents) {
        try {
          // Générer le PDF via l'API Express
          const pdfRes = await fetch('/api/generate-pdf', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ etudiant_id: inscription.etudiant_id, modele_id: modele.id })
          });
          const data = await pdfRes.json();
          if (data?.success && data.filePath) {
            // Récupérer l'URL de téléchargement signée
            const urlRes = await fetch(`/api/documents/signed-url?filePath=${encodeURIComponent(data.filePath)}&expires=60`);
            const signedUrl = await urlRes.json();
            if (signedUrl?.signedUrl) {
              // Télécharger automatiquement le document
              const link = document.createElement('a');
              link.href = signedUrl.signedUrl;
              link.download = data.fileName || `${type}_${inscription.etudiants?.nom || 'document'}.pdf`;
              link.target = '_blank';
              document.body.appendChild(link);
              link.click();
              document.body.removeChild(link);
              successCount++;
            } else {
              errorCount++;
            }
          } else {
            errorCount++;
          }
        } catch (err) {
          errorCount++;
        }
      }

      let description = `${successCount} ${typeLabels[type]} généré(s) et téléchargé(s) avec succès`;
      if (errorCount > 0) {
        description += `. ${errorCount} échec(s).`;
      }
      if (invalidCount > 0) {
        description += ` ${invalidCount} candidat(s) non valide(s) ont été ignorés.`;
      }
      
      // Ajouter l'info sur le dossier de stockage
      const today = new Date().toISOString().split('T')[0];
      description += ` 📁 Stockés dans: generated-documents/${type}/${today}/`;
      
      toast({
        title: "Génération terminée",
        description,
        variant: successCount > 0 ? "default" : "destructive"
      });
      
    } catch (error) {
      console.error('Error generating documents:', error);
      toast({
        title: "Erreur",
        description: "Impossible de générer les documents",
        variant: "destructive"
      });
    } finally {
      setIsGenerating(false);
    }
  };

  if (loading) {
    return <div className="p-6">Chargement...</div>;
  }

  if (!classe) {
    return <div className="p-6">Classe non trouvée</div>;
  }

  const placesOccupees = inscriptions.length;
  const placesDisponibles = classe.nombre_places - placesOccupees;

  return (
    <div className="space-y-6">
      <Breadcrumbs />
      
      {/* Bouton Retour */}
      <div className="flex items-center gap-4">
        <Button
          variant="outline"
          onClick={() => {
            // Navigator vers le menu gestion des classes
            const segmentId = localStorage.getItem('selectedSegment');
            if (segmentId) {
              window.location.href = `/administration/formations/classes?segment=${segmentId}`;
            } else {
              window.location.href = '/administration/formations/classes';
            }
          }}
          className="flex items-center gap-2"
        >
          <ArrowLeft className="h-4 w-4" />
          Retour
        </Button>
        <h1 className="text-2xl font-bold">Gestion des Inscriptions - {classe?.nom_classe}</h1>
      </div>

      {/* En-tête avec statistiques */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Users className="h-5 w-5" />
            Gestion des Inscriptions - {classe.nom_classe}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <ClassStatistics classeId={classeId!} />
        </CardContent>
      </Card>

      {/* Informations de la classe */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-2 mb-2">
              <MapPin className="h-4 w-4 text-muted-foreground" />
              <h3 className="font-semibold">Centre de formation</h3>
            </div>
            <p className="font-medium">{classe.centres?.nom}</p>
            <p className="text-sm text-muted-foreground">{classe.centres?.villes?.nom_ville}</p>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-2 mb-2">
              <Calendar className="h-4 w-4 text-muted-foreground" />
              <h3 className="font-semibold">Période</h3>
            </div>
            <p className="text-sm">Du {new Date(classe.date_debut).toLocaleDateString()}</p>
            <p className="text-sm">Au {new Date(classe.date_fin).toLocaleDateString()}</p>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-2 mb-2">
              <Users className="h-4 w-4 text-muted-foreground" />
              <h3 className="font-semibold">Places disponibles</h3>
            </div>
            <p className="text-2xl font-bold">{placesOccupees}/{classe.nombre_places}</p>
            <p className="text-sm text-muted-foreground">
              {placesDisponibles} places libres
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Actions et liste */}
      <Card>
        <CardHeader>
          <div className="flex justify-between items-center">
            <CardTitle>Étudiants inscrits ({placesOccupees})</CardTitle>
            <div className="flex gap-2">
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="outline">
                    <FileText className="h-4 w-4 mr-2" />
                    Générer documents
                    <MoreVertical className="h-4 w-4 ml-2" />
                  </Button>
                </DropdownMenuTrigger>
                 <DropdownMenuContent align="end" className="w-72">
                   <>
                     <DropdownMenuItem 
                       onClick={handleGenerateAllDocumentsForAllStudents}
                       className="cursor-pointer font-semibold text-primary"
                     >
                       <div className="flex items-center gap-2 w-full">
                         <div className="text-lg">🎯</div>
                         <div className="flex-1">
                           <span>Générer TOUS les documents</span>
                           <div className="text-xs text-muted-foreground">
                             Pour tous les étudiants valides (automatique)
                           </div>
                         </div>
                       </div>
                     </DropdownMenuItem>
                      <hr className="my-1" />
                       {Object.keys(formationFamilles).length > 0 ? Object.keys(formationFamilles).map((famille) => (
                         <DropdownMenuItem 
                           key={famille}
                           onClick={() => handleGenerateFormationFamily(famille)}
                           className="cursor-pointer"
                           disabled={selectedStudents.size === 0}
                         >
                           <div className="flex items-center gap-2 w-full">
                             <div className="text-lg">
                               {famille === 'badge' ? '🏷️' : famille === 'certif' ? '📜' : '📋'}
                             </div>
                             <div className="flex-1">
                               <span className="font-semibold">{famille}</span>
                               <div className="text-xs text-muted-foreground">
                                 Sélectionnez des étudiants pour générer
                               </div>
                             </div>
                           </div>
                         </DropdownMenuItem>
                      )) : ['badge','certif','att'].map((famille) => (
                         <DropdownMenuItem 
                           key={famille}
                           onClick={() => handleGenerateFormationFamily(famille)}
                           className="cursor-pointer"
                           disabled={selectedStudents.size === 0}
                         >
                           <div className="flex items-center gap-2 w-full">
                             <div className="text-lg">
                               {famille === 'badge' ? '🏷️' : famille === 'certif' ? '📜' : '📋'}
                             </div>
                             <div className="flex-1">
                               <span className="font-semibold">{famille}</span>
                               <div className="text-xs text-muted-foreground">
                                 Sélectionnez des étudiants pour générer
                               </div>
                             </div>
                           </div>
                         </DropdownMenuItem>
                      ))}
                   </>
                 </DropdownMenuContent>
              </DropdownMenu>
              <Button 
                onClick={() => setShowAddModal(true)}
                disabled={placesDisponibles <= 0}
              >
                <Plus className="h-4 w-4 mr-2" />
                Ajouter un étudiant
              </Button>
            </div>
          </div>
          {placesDisponibles <= 0 && (
            <div className="flex items-center gap-2 p-3 bg-destructive/10 text-destructive rounded-lg">
              <AlertCircle className="h-4 w-4" />
              <span className="text-sm">Cette classe est complète. Aucune nouvelle inscription n'est possible.</span>
            </div>
          )}
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-[50px]">
                  <Checkbox
                    checked={selectAll}
                    onCheckedChange={(checked) => handleSelectAll(Boolean(checked))}
                    aria-label="Sélectionner tous les étudiants"
                  />
                </TableHead>
                <TableHead>Photo</TableHead>
                <TableHead>Nom</TableHead>
                <TableHead>Prénom</TableHead>
                <TableHead>CIN</TableHead>
                <TableHead>Téléphone</TableHead>
                <TableHead>Formation</TableHead>
                <TableHead>Prix / Reste</TableHead>
                <TableHead>Statut</TableHead>
                <TableHead>ID Unique</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {inscriptions.map((inscription) => {
                return (
                  <TableRow key={inscription.id} className={getRowClassName(inscription.statut_compte)}>
                    <TableCell className="w-[50px]">
                      <Checkbox
                        checked={selectedStudents.has(inscription.id)}
                        onCheckedChange={(checked) => handleSelectStudent(inscription.id, Boolean(checked))}
                        aria-label={`Sélectionner ${inscription.etudiants.nom}`}
                      />
                    </TableCell>
                    <TableCell>
                      <button onClick={() => handleShowPhoto(inscription)}>
                        {inscription.etudiants.photo_url ? (
                          <img 
                            src={inscription.etudiants.photo_url} 
                            alt="Photo étudiant" 
                            className="w-12 h-12 rounded-full object-cover cursor-pointer hover:opacity-80 transition-opacity"
                          />
                        ) : (
                          <div className="w-12 h-12 rounded-full bg-gray-200 flex items-center justify-center cursor-pointer hover:bg-gray-300 transition-colors">
                            <span className="text-sm font-medium text-gray-600">
                              {inscription.etudiants.prenom.charAt(0)}{inscription.etudiants.nom.charAt(0)}
                            </span>
                          </div>
                        )}
                      </button>
                    </TableCell>
                    <TableCell className="font-medium">{inscription.etudiants.nom}</TableCell>
                    <TableCell>{inscription.etudiants.prenom}</TableCell>
                    <TableCell>{inscription.etudiants.cin || '-'}</TableCell>
                    <TableCell>{inscription.etudiants.telephone || '-'}</TableCell>
                    <TableCell>
                      {(() => {
                        const formation = inscription.formations?.titre || classe?.formations?.titre || '-';
                        console.log(`🎓 Formation affichée pour ${inscription.etudiants.prenom} ${inscription.etudiants.nom}:`, {
                          formationAffichee: formation,
                          classeData: classe,
                          inscriptionId: inscription.id
                        });
                        return formation;
                      })()}
                    </TableCell>
                     <TableCell>
                        <button 
                          onClick={() => handleManagePayments(inscription)}
                          className="text-left hover:bg-gray-50 p-1 rounded transition-colors"
                        >
                          <div className="text-sm">
                            <span className="text-gray-600">Prix: </span>
                            <span className="font-medium">{formatAmount(inscription.formations?.prix || classe?.formations?.prix || 0)}</span>
                          </div>
                          <div className="text-sm border-t pt-1 mt-1">
                            <span className="text-gray-600">Reste: </span>
                            <span className={`font-medium ${getInscriptionRemainingColor(inscription)}`}>
                              {formatAmount(calculateRemainingAmount(inscription))}
                            </span>
                          </div>
                       </button>
                     </TableCell>
                      <TableCell>
                        <Select
                          value={inscription.statut_compte || 'non_valide'}
                          onValueChange={(value) => handleUpdateValidation(inscription.id, value as 'valide' | 'non_valide')}
                        >
                          <SelectTrigger className="w-32">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="valide">Valide</SelectItem>
                            <SelectItem value="non_valide">Non valide</SelectItem>
                          </SelectContent>
                        </Select>
                      </TableCell>
                     <TableCell>
                       <Badge variant="outline" className="font-mono text-xs">
                         {inscription.student_id_unique || 'Non généré'}
                       </Badge>
                     </TableCell>
                      <TableCell>
                        <div className="flex space-x-2">
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => handleManagePayments(inscription)}
                            className="text-blue-600 hover:text-blue-700"
                          >
                            <CreditCard className="h-4 w-4" />
                          </Button>
                          {inscription.statut_compte === 'valide' && (
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => handleGenerateAllDocumentsForStudent(inscription.etudiant_id)}
                              disabled={isGenerating}
                              className="text-green-600 hover:text-green-700"
                              title="Générer tous les documents pour cet étudiant"
                            >
                              <Award className="h-4 w-4" />
                            </Button>
                          )}
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => handleEditStudent(inscription)}
                          >
                            <Edit className="h-4 w-4" />
                          </Button>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => handleDeleteInscription(inscription.id)}
                            className="text-red-600 hover:text-red-700"
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </div>
                      </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>

          {inscriptions.length === 0 && (
            <div className="text-center py-8 text-muted-foreground">
              <Users className="h-12 w-12 mx-auto mb-4 opacity-50" />
              <h3 className="text-lg font-medium mb-2">Aucun étudiant inscrit</h3>
              <p className="text-sm">Cliquez sur "Ajouter un étudiant" pour commencer.</p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Modals */}
      <AjouterEtudiantModal
        open={showAddModal}
        onOpenChange={setShowAddModal}
  classe={classe}
        onSuccess={loadData}
      />

      {(() => {
        console.log('🔍 EditModal render check:', {
          showEditModal,
          selectedStudent: selectedStudentId,
          studentData: selectedStudentId ? inscriptions.find(inscription => inscription.id === selectedStudentId)?.etudiants : null
        });
        return showEditModal && selectedStudentId && (
          <EditStudentModal
            key={selectedStudentId}
            open={showEditModal}
            onOpenChange={setShowEditModal}
            student={inscriptions.find(inscription => inscription.id === selectedStudentId)?.etudiants as Student}
            inscription={inscriptions.find(inscription => inscription.id === selectedStudentId) as Inscription}
            onSuccess={() => {
              loadData();
              setShowEditModal(false);
              setSelectedStudentId(null);
            }}
          />
        );
      })()}

      {showPaymentModal && selectedInscription && (
        <GestionPaiementsModal
          open={showPaymentModal}
          onOpenChange={setShowPaymentModal}
          inscription={{
            id: selectedInscription.id,
            etudiant_id: selectedInscription.etudiant_id,
            formation_id: selectedInscription.formation_id,
            avance: selectedInscription.avance,
            etudiants: selectedInscription.etudiants,
            formations: selectedInscription.formations || classe?.formations
          }}
          onSuccess={loadData}
        />
      )}

      {showPhotoModal && selectedInscription && (
        <PhotoModal
          key={selectedInscription.id}
          open={showPhotoModal}
          onOpenChange={setShowPhotoModal}
          student={selectedInscription.etudiants}
        />
      )}
    </div>
  );
}