import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Command, CommandEmpty, CommandGroup, CommandInput, CommandItem } from "@/components/ui/command";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Calendar } from "@/components/ui/calendar";
import { format } from "date-fns";
import { cn } from "@/lib/utils";
import { Textarea } from "@/components/ui/textarea";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { Plus, Search, FileDown, Eye, Check, ChevronsUpDown, Phone, MessageSquare, Edit, Trash2, CalendarIcon } from "lucide-react";
// Supabase supprimé, toute la logique doit passer par l'API Express locale
import { useToast } from "@/hooks/use-toast";

import { autoDetectAndFormat, normalizePhoneNumber } from '@/lib/phone-utils';
import { useBulkActionsPermission } from '@/hooks/useBulkActionsPermission';

type ProspectData = {
  id: string;
  nom: string;
  prenom: string;
  telephone?: string;
  ville?: string;
  ville_id?: string;
  segment?: string;
  segment_id?: string;
  statut_contact?: string;
  statut_inscription?: string;
  created_at: string;
  updated_at: string;
  prospect_id_unique?: string;
  rdv_le?: string;
  duree_appel?: number;
  commentaire?: string;
  rendez_vous_le?: string;
  villes?: {
    nom_ville: string;
    code_ville: string;
  };
  segments?: {
    nom: string;
  };
};

type SegmentData = {
  id: string;
  nom: string;
};

const STATUTS_CONTACT = [
  'Non Contacté',
  'Contacté avec RDV',
  'Contacté sans réponse',
  'Boite vocale',
  'Non intéressé',
  'Déjà inscrit',
  'A recontacter'
];

const STATUTS_INSCRIPTION = ['Non inscrit', 'Inscrit', 'En cours'];

export function CrmProspects() {
  const [prospects, setProspects] = useState<ProspectData[]>([]);
  const [filteredProspects, setFilteredProspects] = useState<ProspectData[]>([]);
  const [searchTerm, setSearchTerm] = useState("");
  const [filterById, setFilterById] = useState("");
  const [filterByPhone, setFilterByPhone] = useState("");
  const [filterByVille, setFilterByVille] = useState<string>("all");
  const [filterStatutContact, setFilterStatutContact] = useState<string>("all");
  const [filterStatutInscription, setFilterStatutInscription] = useState<string>("all");
  const [filterSegment, setFilterSegment] = useState<string>("all");
  const [filterByRendezVous, setFilterByRendezVous] = useState<string>("all");
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage] = useState(25);
  const [isAddDialogOpen, setIsAddDialogOpen] = useState(false);
  const [segments, setSegments] = useState<SegmentData[]>([]);
  const [villesDisponibles, setVillesDisponibles] = useState<any[]>([]);
  const [toutesLesVilles, setToutesLesVilles] = useState<any[]>([]);
  const [selectedProspects, setSelectedProspects] = useState<string[]>([]);
  const [selectAll, setSelectAll] = useState(false);
  
  // États pour les actions en masse
  const [isBulkActionsVisible, setIsBulkActionsVisible] = useState(false);
  const [bulkAction, setBulkAction] = useState<string>("");
  const [bulkVille, setBulkVille] = useState<string>("");
  const [bulkSegment, setBulkSegment] = useState<string>("");
  const [bulkStatutContact, setBulkStatutContact] = useState<string>("");
  const [isBulkModalOpen, setIsBulkModalOpen] = useState(false);
  
  // Hook pour vérifier les permissions d'actions en masse
  const { canManageBulkActions, loading: permissionLoading } = useBulkActionsPermission();
  
  // États pour la modal d'appel
  const [isCallModalOpen, setIsCallModalOpen] = useState(false);
  const [currentProspect, setCurrentProspect] = useState<any>(null);
  const [callDuration, setCallDuration] = useState(0);
  const [callStartTime, setCallStartTime] = useState<Date | null>(null);
  const [contactStatus, setContactStatus] = useState('');
  const [appointmentDate, setAppointmentDate] = useState('');
  const [appointmentTime, setAppointmentTime] = useState('');
  const [comment, setComment] = useState('');
  
  // États pour la gestion de la ville dans la modal d'appel
  const [callModalVilleId, setCallModalVilleId] = useState('');
  const [callModalVilleSearch, setCallModalVilleSearch] = useState('');
  const [showCallModalVilleDropdown, setShowCallModalVilleDropdown] = useState(false);
  const [callModalVillesDisponibles, setCallModalVillesDisponibles] = useState<any[]>([]);

  const { toast } = useToast();

  const [newProspect, setNewProspect] = useState({
    nom_complet: "",
    telephone: "",
    ville: "",
    segment: "",
    segmentId: "",
    villeId: ""
  });
  const [phoneValidation, setPhoneValidation] = useState({ isValid: false, message: '' });
  const [villeSearchQuery, setVilleSearchQuery] = useState("");
  const [showVilleDropdown, setShowVilleDropdown] = useState(false);

  // Filtrer les villes en fonction de la recherche
  const filteredVilles = villesDisponibles.filter((ville) => {
    if (!villeSearchQuery.trim()) return true;
    const query = villeSearchQuery.toLowerCase();
    return (
      ville.nom_ville?.toLowerCase().includes(query) ||
      ville.code_ville?.toLowerCase().includes(query)
    );
  });

  // Obtenir la ville sélectionnée et son nom
  const getSelectedVille = () => {
    return villesDisponibles.find(v => v.id === newProspect.villeId);
  };
  
  const getSelectedVilleName = () => {
    const selected = getSelectedVille();
    return selected ? selected.nom_ville : "";
  };

  const loadSegments = async () => {
    try {
      // Remplacement Supabase: fetch segments depuis l'API Express
      const res = await fetch('/api/segments');
      if (!res.ok) throw new Error('Erreur lors du chargement des segments');
      const segments = await res.json();
      // ...traitement des segments ici (setSegments, etc.)
      
      if (data && Array.isArray(data)) {
        const segmentsArray = data.map((s: any) => ({
          id: s.id,
          nom: s.nom
        }));
        setSegments(segmentsArray);
      } else {
        setSegments([]);
      }
    } catch (error) {
      console.error('Erreur lors du chargement des segments:', error);
      // Segments par défaut en cas d'erreur
      setSegments([
        { id: '1', nom: 'ProLean' },
        { id: '2', nom: 'Diray' },
        { id: '3', nom: 'TechPro' }
      ]);
    }
  };

  const loadToutesLesVilles = async () => {
    try {
      // TODO: Remplacer par appel API Express ou mock
      const { data, error } = await supabase
        .from('villes')
        .select('id, nom_ville, code_ville, segment_id')
        .order('nom_ville');
      
      if (error) {
        console.error('Erreur lors du chargement des villes:', error);
        return;
      }
      
      if (data && Array.isArray(data)) {
        setToutesLesVilles(data);
      }
    } catch (error) {
      console.error('Erreur lors du chargement des villes:', error);
    }
  };

  const loadVillesParSegment = async (segmentId: string) => {
    if (!segmentId) {
      setVillesDisponibles([]);
      return;
    }

    try {
  // TODO: Remplacer par appel API Express ou mock
        .from('villes')
        .select('id, nom_ville, code_ville')
        .eq('segment_id', segmentId)
        .order('nom_ville');

      if (error) {
        console.error('Erreur lors du chargement des villes:', error);
        setVillesDisponibles([]);
        return;
      }

      if (data && Array.isArray(data)) {
        setVillesDisponibles(data);
      } else {
        setVillesDisponibles([]);
      }
    } catch (error) {
      console.error('Erreur villes:', error);
      setVillesDisponibles([]);
    }
  };

  const loadProspects = async () => {
    try {
      console.log('Chargement des prospects...');
      
      // Nouvelle approche: d'abord récupérer les prospects simples
  // TODO: Remplacer par appel API Express ou mock
        .from('prospects')
        .select('*')
        .order('updated_at', { ascending: false });

      if (prospectsError) {
        console.error('Erreur lors du chargement des prospects:', prospectsError);
        toast({
          title: "Erreur",
          description: "Impossible de charger les prospects",
          variant: "destructive",
        });
        setProspects([]);
        return;
      }

      console.log('Prospects de base chargés:', prospectsData?.length || 0);

      // Ensuite enrichir avec les données des villes et segments
      const enrichedProspects = await Promise.all(
        (prospectsData || []).map(async (prospect) => {
          let ville = null;
          let segment = null;

          // Récupérer la ville si ville_id existe
          if (prospect.ville_id) {
            try {
              // TODO: Remplacer par appel API Express ou mock
                .from('villes')
                .select('nom_ville, code_ville')
                .eq('id', prospect.ville_id)
                .single();
              ville = villeData;
            } catch (error) {
              console.warn('Erreur lors du chargement de la ville:', error);
            }
          }

          // Récupérer le segment si segment_id existe
          if (prospect.segment_id) {
            try {
              // TODO: Remplacer par appel API Express ou mock
                .from('segments')
                .select('nom')
                .eq('id', prospect.segment_id)
                .single();
              segment = segmentData;
            } catch (error) {
              console.warn('Erreur lors du chargement du segment:', error);
            }
          }

          return {
            ...prospect,
            villes: ville,
            segments: segment,
            segment: segment?.nom || '',
            statut_contact: prospect.statut_contact || 'Non Contacté',
            statut_inscription: prospect.statut_inscription || 'Non inscrit'
          };
        })
      );

      console.log('Prospects enrichis:', enrichedProspects.length);
      setProspects(enrichedProspects);
    } catch (error) {
      console.error('Erreur prospects:', error);
      toast({
        title: "Erreur",
        description: "Impossible de charger les prospects",
        variant: "destructive"
      });
      setProspects([]);
    }
  };

  // Fonction pour charger les villes par segment pour la modal d'appel
  const loadCallModalVillesParSegment = async (segmentId: string, currentVilleId?: string) => {
    if (!segmentId) {
      setCallModalVillesDisponibles([]);
      return;
    }

    try {
  // TODO: Remplacer par appel API Express ou mock
        .from('villes')
        .select('id, nom_ville, code_ville')
        .eq('segment_id', segmentId)
        .order('nom_ville');

      if (error) {
        console.error('Erreur lors du chargement des villes pour modal:', error);
        setCallModalVillesDisponibles([]);
        return;
      }

      if (data && Array.isArray(data)) {
        setCallModalVillesDisponibles(data);
        
        // Si une ville courante est spécifiée, préremplir le champ de recherche
        if (currentVilleId) {
          const currentVille = data.find(v => v.id === currentVilleId);
          if (currentVille) {
            setCallModalVilleSearch(currentVille.nom_ville);
          }
        }
      } else {
        setCallModalVillesDisponibles([]);
      }
    } catch (error) {
      console.error('Erreur villes modal:', error);
      setCallModalVillesDisponibles([]);
    }
  };

  // Actions pour les prospects
  const handleCall = async (prospect: any) => {
    console.log('Appel prospect:', prospect);
    
    // Copier le numéro dans le presse-papiers
    if (prospect.telephone) {
      try {
        await navigator.clipboard.writeText(prospect.telephone);
        toast({
          title: "Numéro copié",
          description: "Le numéro de téléphone a été copié dans le presse-papiers",
        });
      } catch (error) {
        console.warn('Impossible de copier le numéro:', error);
      }
    }
    
    // Ouvrir la modal et démarrer le compteur
    setCurrentProspect(prospect);
    setContactStatus(prospect.statut_contact || 'Non Contacté');
    setInitialStatus(prospect.statut_contact || 'Non Contacté'); // Sauvegarder le statut initial
    setCallModalVilleId(prospect.ville_id || '');
    setInitialVilleId(prospect.ville_id || ''); // Sauvegarder la ville initiale
    setCallModalVilleSearch('');
    setShowCallModalVilleDropdown(false); // Fermer le dropdown par défaut
    setComment('');
    setAppointmentDate('');
    setAppointmentTime('');
    setCallDuration(0);
    setIsCallModalOpen(true);
    
    // Charger les villes pour le segment du prospect
    if (prospect.segment_id) {
      await loadCallModalVillesParSegment(prospect.segment_id, prospect.ville_id);
    }
    
    // Démarrer le compteur après 5 secondes
    setTimeout(() => {
      setCallStartTime(new Date());
    }, 5000);
  };

  const handleMessage = (prospect: any) => {
    console.log('Message prospect:', prospect);
    toast({
      title: "Message",
      description: `Message envoyé à ${prospect.nom} ${prospect.prenom}`,
    });
  };

  const handleEdit = (prospect: any) => {
    console.log('Modifier prospect:', prospect);
    toast({
      title: "Modification",
      description: `Modification de ${prospect.nom} ${prospect.prenom}`,
    });
  };

  const handleDelete = async (prospect: any) => {
    if (confirm('Êtes-vous sûr de vouloir supprimer ce prospect ?')) {
      try {
        console.log('Tentative de suppression du prospect:', prospect.id);
        
  // TODO: Remplacer par appel API Express ou mock
          .from('prospects')
          .delete()
          .eq('id', prospect.id)
          .select();

        console.log('Résultat suppression:', { data, error, count });

        if (error) {
          console.error('Erreur lors de la suppression:', error);
          toast({
            title: "Erreur de suppression",
            description: `Erreur: ${error.message}`,
            variant: "destructive"
          });
          return;
        }

        // Vérifier si quelque chose a été supprimé
        if (!data || data.length === 0) {
          console.warn('Aucun prospect supprimé - permissions insuffisantes ou prospect inexistant');
          toast({
            title: "Erreur",
            description: "Impossible de supprimer le prospect. Vérifiez vos permissions.",
            variant: "destructive"
          });
          return;
        }

        console.log('Prospect supprimé avec succès:', data[0]);
        loadProspects();
        toast({
          title: "Suppression",
          description: "Prospect supprimé avec succès",
        });
      } catch (error) {
        console.error('Exception lors de la suppression:', error);
        toast({
          title: "Erreur système",
          description: "Erreur inattendue lors de la suppression",
          variant: "destructive"
        });
      }
    }
  };

  useEffect(() => {
    loadProspects();
    loadSegments();
    loadToutesLesVilles();
  }, []);

  useEffect(() => {
    if (newProspect.segmentId) {
      loadVillesParSegment(newProspect.segmentId);
    }
  }, [newProspect.segmentId, segments]);

  // Compteur d'appel
  useEffect(() => {
    let interval: NodeJS.Timeout;
    if (callStartTime && isCallModalOpen) {
      interval = setInterval(() => {
        const now = new Date();
        const duration = Math.floor((now.getTime() - callStartTime.getTime()) / 1000);
        setCallDuration(duration);
      }, 1000);
    }
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [callStartTime, isCallModalOpen]);

  // Fermer le dropdown quand on clique en dehors
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (showVilleDropdown) {
        const target = event.target as Element;
        if (!target.closest('.ville-dropdown-container')) {
          setShowVilleDropdown(false);
        }
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [showVilleDropdown]);

  // État pour tracker les changements
  const [initialStatus, setInitialStatus] = useState('');
  const [initialVilleId, setInitialVilleId] = useState('');

  // Fonction pour fermer la modal d'appel et sauvegarder
  const handleCloseCallModal = async () => {
    if (currentProspect) {
      try {
        const updateData: any = {};
        let hasStatusChanged = false;
        let hasVilleChanged = false;

        // Vérifier si le statut a changé
        if (contactStatus !== initialStatus) {
          updateData.statut_contact = contactStatus;
          hasStatusChanged = true;
          
          // Capturer la durée d'appel seulement si le statut a changé
          if (callDuration > 0) {
            updateData.duree_appel = callDuration;
          }
        }

        // Vérifier si la ville a changé
        if (callModalVilleId && callModalVilleId !== initialVilleId) {
          updateData.ville_id = callModalVilleId;
          hasVilleChanged = true;
          
          // Si la ville a changé, remettre le statut à "Non Contacté"
          updateData.statut_contact = 'Non Contacté';
        }

        // Ajouter les notes si elles existent
        if (comment) {
          updateData.notes = comment;
        }

        // Ajouter le rendez-vous si date et heure sont fournies
        if (appointmentDate && appointmentTime) {
          updateData.rdv_le = appointmentDate;
          updateData.rdv_a = appointmentTime;
        } else if (appointmentDate) {
          updateData.rdv_le = appointmentDate;
        }

        // Effectuer la mise à jour seulement s'il y a des changements
        if (Object.keys(updateData).length > 0) {
          // TODO: Remplacer par appel API Express ou mock
            .from('prospects')
            .update(updateData)
            .eq('id', currentProspect.id);

          if (error) {
            console.error('Erreur lors de la mise à jour:', error);
            toast({
              title: "Erreur de sauvegarde",
              description: `Erreur: ${error.message}`,
              variant: "destructive"
            });
            return;
          }

          let message = "Modifications enregistrées";
          if (hasStatusChanged && callDuration > 0) {
            message += ` - Durée: ${Math.floor(callDuration / 60)}:${(callDuration % 60).toString().padStart(2, '0')}`;
          }
          if (hasVilleChanged) {
            message += " - Statut remis à 'Non Contacté' (ville modifiée)";
          }

          toast({
            title: "Appel enregistré",
            description: message,
          });

          // Recharger les prospects pour mettre à jour l'affichage
          await loadProspects();
        }
      } catch (error) {
        console.error('Erreur lors de la sauvegarde:', error);
        toast({
          title: "Erreur",
          description: "Impossible de sauvegarder les données d'appel",
          variant: "destructive"
        });
      }
    }

    // Réinitialiser les états
    setIsCallModalOpen(false);
    setCurrentProspect(null);
    setCallDuration(0);
    setCallStartTime(null);
    setContactStatus('');
    setCallModalVilleId('');
    setCallModalVilleSearch('');
    setComment('');
    setAppointmentDate('');
    setAppointmentTime('');
  };

  // Fonction pour annuler l'appel
  const handleCancelCall = () => {
    setIsCallModalOpen(false);
    setCurrentProspect(null);
    setCallDuration(0);
    setCallStartTime(null);
    setContactStatus('');
    setCallModalVilleId('');
    setCallModalVilleSearch('');
    setComment('');
    setAppointmentDate('');
    setAppointmentTime('');
  };

  // Formatage du temps d'appel
  const formatCallTime = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
  };

  // Fonction pour gérer le changement de ville dans la modal d'appel
  const handleCallModalVilleChange = (villeId: string) => {
    setCallModalVilleId(villeId);
    // Si la ville change, remettre le statut à "Non contacté"
    if (villeId !== currentProspect?.ville_id) {
      setContactStatus('Non Contacté');
    }
    setShowCallModalVilleDropdown(false);
  };

  // Fonction pour la sauvegarde automatique
  const handleAutoSave = async (newStatus: string) => {
    if (!currentProspect || callDuration === 0) return;
    
    try {
  // TODO: Remplacer par appel API Express ou mock
        .from('prospects')
        .update({
          statut_contact: newStatus,
          duree_appel: callDuration,
          notes: comment || null
        })
        .eq('id', currentProspect.id);

      if (error) {
        console.error('Erreur sauvegarde automatique:', error);
        return;
      }

      // Mettre à jour la liste des prospects
      loadProspects();
      
      toast({
        title: "Sauvegarde automatique",
        description: "Les données ont été sauvegardées automatiquement",
      });
    } catch (error) {
      console.error('Exception sauvegarde automatique:', error);
    }
  };

  // Filtrer les villes pour la modal d'appel
  const callModalFilteredVilles = callModalVillesDisponibles.filter((ville) => {
    if (!callModalVilleSearch.trim()) return true;
    const query = callModalVilleSearch.toLowerCase();
    return (
      ville.nom_ville?.toLowerCase().includes(query) ||
      ville.code_ville?.toLowerCase().includes(query)
    );
  });

  // Obtenir le nom de la ville sélectionnée dans la modal
  const getCallModalSelectedVilleName = () => {
    const selected = callModalVillesDisponibles.find(v => v.id === callModalVilleId);
    return selected ? selected.nom_ville : currentProspect?.villes?.nom_ville || currentProspect?.ville || '';
  };

  // Fonction pour réinitialiser tous les filtres
  const resetFilters = () => {
    setSearchTerm("");
    setFilterById("");
    setFilterByPhone("");
    setFilterByVille("all");
    setFilterStatutContact("all");
    setFilterStatutInscription("all");
    setFilterSegment("all");
    setFilterByRendezVous("all");
  };

  // Filtrer les villes selon le segment sélectionné
  const getVillesDisponiblesPourFiltre = () => {
    if (filterSegment === "all") {
      return toutesLesVilles;
    }
    
    // Trouver l'ID du segment sélectionné
    const segmentSelectionne = segments.find(s => s.nom === filterSegment);
    if (!segmentSelectionne) {
      return [];
    }
    
    // Retourner seulement les villes de ce segment
    return toutesLesVilles.filter(ville => ville.segment_id === segmentSelectionne.id);
  };

  // Réinitialiser le filtre ville quand le segment change
  const handleSegmentFilterChange = (value: string) => {
    setFilterSegment(value);
    // Réinitialiser le filtre ville car les villes disponibles changent
    setFilterByVille("all");
  };

  // Fonctions pour les actions en masse
  const handleSelectAll = (checked: boolean) => {
    setSelectAll(checked);
    if (checked) {
      setSelectedProspects(filteredProspects.map(p => p.id));
    } else {
      setSelectedProspects([]);
    }
  };

  const handleSelectProspect = (prospectId: string, checked: boolean) => {
    if (checked) {
      setSelectedProspects(prev => [...prev, prospectId]);
    } else {
      setSelectedProspects(prev => prev.filter(id => id !== prospectId));
      setSelectAll(false);
    }
  };

  const resetBulkStates = () => {
    setBulkAction("");
    setBulkVille("");
    setBulkSegment("");
    setBulkStatutContact("");
    setIsBulkModalOpen(false);
  };

  const handleBulkAction = (action: string) => {
    if (selectedProspects.length === 0) {
      toast({
        title: "Aucune sélection",
        description: "Veuillez sélectionner au moins un prospect",
        variant: "destructive"
      });
      return;
    }

    setBulkAction(action);
    setIsBulkModalOpen(true);
  };

  const executeBulkAction = async () => {
    if (selectedProspects.length === 0) return;

    try {
      let updateData: any = {};

      switch (bulkAction) {
        case 'delete':
          // TODO: Remplacer par appel API Express ou mock
            .from('prospects')
            .delete()
            .in('id', selectedProspects);

          if (deleteError) {
            console.error('Erreur suppression:', deleteError);
            throw deleteError;
          }

          toast({
            title: "Suppression réussie",
            description: `${selectedProspects.length} prospect(s) supprimé(s)`
          });
          break;

        case 'change_ville':
          if (!bulkVille) {
            toast({
              title: "Erreur",
              description: "Veuillez sélectionner une ville",
              variant: "destructive"
            });
            return;
          }
          updateData = { 
            ville_id: bulkVille,
            rdv_le: null,
            duree_appel: null,
            updated_at: new Date().toISOString()
          };
          break;

        case 'change_segment':
          if (!bulkSegment) {
            toast({
              title: "Erreur", 
              description: "Veuillez sélectionner un segment",
              variant: "destructive"
            });
            return;
          }
          
          updateData = { 
            segment_id: bulkSegment,
            rdv_le: null,
            duree_appel: null,
            updated_at: new Date().toISOString()
          };
          break;

        case 'change_statut':
          if (!bulkStatutContact) {
            toast({
              title: "Erreur",
              description: "Veuillez sélectionner un statut de contact",
              variant: "destructive"
            });
            return;
          }
          updateData = { 
            statut_contact: bulkStatutContact,
            rdv_le: null,
            duree_appel: null,
            updated_at: new Date().toISOString()
          };
          break;

        default:
          console.error('Action bulk inconnue:', bulkAction);
          return;
      }

      if (bulkAction !== 'delete') {
        console.log('Données de mise à jour:', updateData);
        console.log('IDs sélectionnés:', selectedProspects);
        
  // TODO: Remplacer par appel API Express ou mock
          .from('prospects')
          .update(updateData)
          .in('id', selectedProspects)
          .select();

        if (updateError) {
          console.error('Erreur mise à jour:', updateError);
          throw updateError;
        }

        console.log('Mise à jour réussie:', data);

        toast({
          title: "Mise à jour réussie",
          description: `${selectedProspects.length} prospect(s) mis à jour`
        });
      }

      // Recharger les données et réinitialiser les sélections
      await loadProspects();
      setSelectedProspects([]);
      setSelectAll(false);
      resetBulkStates();

    } catch (error) {
      console.error('Erreur lors de l\'action en masse:', error);
      toast({
        title: "Erreur",
        description: `Erreur lors de l'exécution de l'action en masse: ${error.message || error}`,
        variant: "destructive"
      });
    }
  };

  // Afficher/masquer les actions en masse
  useEffect(() => {
    setIsBulkActionsVisible(canManageBulkActions && !permissionLoading);
  }, [canManageBulkActions, permissionLoading]);

  useEffect(() => {
    let filtered = prospects.filter(prospect => {
      // Recherche générale (si pas de filtres spécifiques actifs)
      const hasSpecificFilters = filterById || filterByPhone;
      const matchesSearch = !hasSpecificFilters && (searchTerm === "" || 
        prospect.nom?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        prospect.prenom?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        prospect.telephone?.includes(searchTerm));

      // Filtres spécifiques
      const matchesId = filterById === "" || 
        prospect.prospect_id_unique?.toString().includes(filterById) ||
        prospect.id?.toString().includes(filterById);
        
      const matchesPhone = filterByPhone === "" || 
        prospect.telephone?.includes(filterByPhone);
        
      const matchesVille = filterByVille === "all" || 
        prospect.ville_id === filterByVille;

      const matchesStatutContact = filterStatutContact === "all" || 
        prospect.statut_contact === filterStatutContact;
        
      const matchesStatutInscription = filterStatutInscription === "all" || 
        prospect.statut_inscription === filterStatutInscription;
        
      const matchesSegment = filterSegment === "all" || 
        prospect.segment === filterSegment;

      const matchesRendezVous = filterByRendezVous === "all" || 
        (filterByRendezVous === "avec" && prospect.rendez_vous_le) ||
        (filterByRendezVous === "sans" && !prospect.rendez_vous_le);

      // Si on a des filtres spécifiques, on ignore la recherche générale
      if (hasSpecificFilters) {
        return matchesId && matchesPhone && matchesVille && matchesStatutContact && 
               matchesStatutInscription && matchesSegment && matchesRendezVous;
      }

      // Sinon, on utilise la recherche générale + autres filtres
      return matchesSearch && matchesVille && matchesStatutContact && 
             matchesStatutInscription && matchesSegment && matchesRendezVous;
    });

    setFilteredProspects(filtered);
    setCurrentPage(1);
  }, [prospects, searchTerm, filterById, filterByPhone, filterByVille, filterStatutContact, filterStatutInscription, filterSegment, filterByRendezVous]);

  // Fonction pour gérer le changement du numéro de téléphone
  const handlePhoneChange = (value: string) => {
    const result = autoDetectAndFormat(value);
    
    setNewProspect(prev => ({
      ...prev,
      telephone: result.formatted
    }));
    
    if (value && !result.isValid) {
      setPhoneValidation({
        isValid: false,
        message: 'Format de numéro invalide ou incomplet'
      });
    } else if (result.isValid) {
      setPhoneValidation({
        isValid: true,
        message: `Numéro ${result.country === 'MA' ? 'marocain' : 'international'} valide`
      });
    } else {
      setPhoneValidation({ isValid: false, message: '' });
    }
  };

  const addProspect = async () => {
    // Validation du numéro de téléphone
    const phoneResult = autoDetectAndFormat(newProspect.telephone);
    if (!phoneResult.isValid) {
      toast({
        title: "Erreur",
        description: "Veuillez saisir un numéro de téléphone valide et complet",
        variant: "destructive",
      });
      return;
    }

    // Validation des données requises
    if (!newProspect.segmentId || !newProspect.villeId) {
      toast({
        title: "Erreur",
        description: "Veuillez sélectionner un segment et une ville",
        variant: "destructive",
      });
      return;
    }

    try {
      const nomCompletParts = newProspect.nom_complet.trim().split(' ');
      const prenom = nomCompletParts[0] || '';
      const nom = nomCompletParts.slice(1).join(' ') || nomCompletParts[0] || '';
      const normalizedPhone = normalizePhoneNumber(newProspect.telephone);

  // TODO: Remplacer par appel API Express ou mock
        .from('prospects')
        .insert([{
          nom: nom,
          prenom: prenom,
          email: '', // Champ requis
          telephone: normalizedPhone,
          ville_id: newProspect.villeId,
          segment_id: newProspect.segmentId,
          statut_contact: 'non contacté',
          statut_inscription: 'Non inscrit'
        }])
        .select()
        .single();

      if (response.data) {
        toast({
          title: "Succès",
          description: "Prospect ajouté avec succès"
        });

        // Recharger la liste des prospects
        await loadProspects();
        
        // Réinitialiser le formulaire
        setNewProspect({
          nom_complet: "",
          telephone: "",
          ville: "",
          segment: "",
          segmentId: "",
          villeId: ""
        });
        setPhoneValidation({ isValid: false, message: '' });
        setVilleSearchQuery("");
        setIsAddDialogOpen(false);
      }
    } catch (error) {
      console.error('Erreur ajout:', error);
      toast({
        title: "Erreur",
        description: "Impossible d'ajouter le prospect",
        variant: "destructive"
      });
    }
  };

  const getStatutContactColor = (statut: string) => {
    switch (statut) {
      case 'non contacté': return 'bg-gray-100 text-gray-800';
      case 'Contacté avec RDV': return 'bg-green-100 text-green-800';
      case 'Contacté sans réponse': return 'bg-orange-100 text-orange-800';
      case 'Boite vocale': return 'bg-blue-100 text-blue-800';
      case 'Non intéressé': return 'bg-red-100 text-red-800';
      case 'Déjà inscrit': return 'bg-purple-100 text-purple-800';
      case 'A recontacter': return 'bg-yellow-100 text-yellow-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  const getStatutInscriptionColor = (statut: string) => {
    switch (statut) {
      case 'Non inscrit': return 'bg-gray-100 text-gray-800';
      case 'Inscrit': return 'bg-green-100 text-green-800';
      case 'En cours': return 'bg-orange-100 text-orange-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  const paginatedProspects = filteredProspects.slice(
    (currentPage - 1) * itemsPerPage,
    currentPage * itemsPerPage
  );

  const totalPages = Math.ceil(filteredProspects.length / itemsPerPage);


  // Fonction pour formater l'ID personnalisé
  const formatCustomId = (prospect: any) => {
    if (!prospect.villes || !prospect.prospect_id_unique) return prospect.prospect_id_unique;
    
    const villeNom = prospect.villes.nom_ville;
    const lastSixDigits = prospect.prospect_id_unique.slice(-6);
    return `${villeNom} ${lastSixDigits}`;
  };

  return (
    <div className="space-y-6 p-6">
      {/* Header avec statistiques */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="p-4">
            <div className="text-2xl font-bold">{prospects.length}</div>
            <div className="text-sm text-muted-foreground">Total Prospects</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="text-2xl font-bold text-green-600">
              {prospects.filter(p => p.statut_contact === 'Contacté avec RDV').length}
            </div>
            <div className="text-sm text-muted-foreground">Avec RDV</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="text-2xl font-bold text-purple-600">
              {prospects.filter(p => p.statut_inscription === 'Inscrit').length}
            </div>
            <div className="text-sm text-muted-foreground">Inscrits</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="text-2xl font-bold text-orange-600">
              {prospects.filter(p => p.statut_contact === 'A recontacter').length}
            </div>
            <div className="text-sm text-muted-foreground">À recontacter</div>
          </CardContent>
        </Card>
      </div>

      {/* Filtres et actions */}
      <Card>
        <CardHeader className="pb-4">
          <div className="flex flex-col lg:flex-row gap-4 justify-between items-start lg:items-center">
            <CardTitle>Gestion des Prospects</CardTitle>
            <div className="flex gap-2">
              {selectedProspects.length > 0 && (
                <Button variant="outline" className="btn-secondary-enhanced">
                  Actions ({selectedProspects.length})
                </Button>
              )}
              <Dialog open={isAddDialogOpen} onOpenChange={setIsAddDialogOpen}>
                 <DialogTrigger asChild>
                   <Button className="btn-primary-enhanced px-6 py-3">
                     <Plus className="h-4 w-4 mr-2" />
                     Ajouter Prospect
                   </Button>
                 </DialogTrigger>
                <DialogContent className="max-w-md">
                  <DialogHeader>
                    <DialogTitle>Ajouter un nouveau prospect</DialogTitle>
                  </DialogHeader>
                  <div className="space-y-4">
                    <div>
                      <Label htmlFor="nom_complet">Nom Prénom</Label>
                      <Input
                        id="nom_complet"
                        value={newProspect.nom_complet}
                        onChange={(e) => setNewProspect({ ...newProspect, nom_complet: e.target.value })}
                        placeholder="Nom et prénom complet"
                        className="border-blue-200 focus:border-blue-500"
                      />
                    </div>
                    
                     <div>
                       <Label htmlFor="segment">Segment *</Label>
                       <Select 
                         value={newProspect.segmentId} 
                         onValueChange={(value) => {
                           const selectedSegment = segments.find(s => s.id === value);
                            setNewProspect({ 
                              ...newProspect, 
                              segmentId: value,
                              segment: selectedSegment?.nom || "",
                              ville: "",
                              villeId: ""
                            });
                         }}
                       >
                         <SelectTrigger>
                           <SelectValue placeholder="Sélectionner un segment" />
                         </SelectTrigger>
                          <SelectContent>
                            {(segments || []).map((segment) => (
                              <SelectItem key={segment.id} value={segment.id}>{segment.nom}</SelectItem>
                            ))}
                          </SelectContent>
                       </Select>
                     </div>

                    <div>
                      <Label htmlFor="ville">Ville *</Label>
                      <div className="relative ville-dropdown-container">
                        <div className="flex">
                          <Input
                            placeholder="Rechercher par nom ou code ville..."
                            value={getSelectedVilleName() || villeSearchQuery}
                            onChange={(e) => {
                              setVilleSearchQuery(e.target.value);
                              setShowVilleDropdown(true);
                               if (!e.target.value) {
                                 setNewProspect({ ...newProspect, ville: "", villeId: "" });
                               }
                            }}
                            onFocus={() => setShowVilleDropdown(true)}
                            className="pr-10"
                            disabled={!newProspect.segmentId}
                          />
                          <Button 
                            type="button"
                            variant="ghost" 
                            size="sm" 
                            className="absolute right-0 top-0 h-full px-3"
                            onClick={() => setShowVilleDropdown(!showVilleDropdown)}
                            disabled={!newProspect.segmentId}
                          >
                            <Search className="h-4 w-4" />
                          </Button>
                        </div>
                        
                        {showVilleDropdown && filteredVilles.length > 0 && (
                          <div className="absolute z-50 w-full mt-1 bg-background border border-border rounded-md shadow-lg max-h-60 overflow-auto">
                            {filteredVilles.map((ville) => (
                              <div
                                key={ville.id}
                                className="px-3 py-2 hover:bg-muted cursor-pointer text-sm"
                                onClick={() => {
                                  setNewProspect({ 
                                    ...newProspect, 
                                    ville: ville.nom_ville,
                                    villeId: ville.id
                                  });
                                  setVilleSearchQuery("");
                                  setShowVilleDropdown(false);
                                }}
                              >
                                {ville.nom_ville} ({ville.code_ville})
                              </div>
                            ))}
                          </div>
                        )}
                        
                        {showVilleDropdown && filteredVilles.length === 0 && villeSearchQuery && (
                          <div className="absolute z-50 w-full mt-1 bg-background border border-border rounded-md shadow-lg">
                            <div className="px-3 py-2 text-sm text-muted-foreground">
                              Aucune ville trouvée
                            </div>
                          </div>
                        )}
                      </div>
                    </div>

                    <div>
                      <Label htmlFor="telephone">Téléphone *</Label>
                      <Input
                        id="telephone"
                        placeholder="Collez directement depuis WhatsApp (ex: 06 60 77 84 47)"
                        value={newProspect.telephone}
                        onChange={(e) => handlePhoneChange(e.target.value)}
                        className={`${
                          newProspect.telephone && phoneValidation.isValid 
                            ? 'border-green-500 focus-visible:ring-green-500' 
                            : newProspect.telephone && !phoneValidation.isValid && phoneValidation.message
                            ? 'border-red-500 focus-visible:ring-red-500'
                            : ''
                        }`}
                      />
                      {phoneValidation.message && (
                        <p className={`text-sm mt-1 ${
                          phoneValidation.isValid ? 'text-green-600' : 'text-red-600'
                        }`}>
                          {phoneValidation.message}
                        </p>
                      )}
                    </div>
                  </div>
                  
                  <div className="flex justify-end gap-2 mt-6">
                    <Button variant="outline" onClick={() => setIsAddDialogOpen(false)}>
                      Annuler
                    </Button>
                     <Button 
                       onClick={addProspect} 
                       disabled={!newProspect.segmentId || !newProspect.villeId || !newProspect.telephone}
                       className="bg-green-500 hover:bg-green-600 text-white"
                     >
                      Ajouter
                    </Button>
                  </div>
                </DialogContent>
              </Dialog>
              
              <Button variant="outline">
                <FileDown className="h-4 w-4 mr-2" />
                Exporter
              </Button>
            </div>
          </div>
        </CardHeader>
        
        <CardContent>
          {/* Première ligne de filtres */}
          <div className="flex flex-col lg:flex-row gap-4 mb-4">
            <div className="flex-1">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 h-4 w-4" />
                <Input
                  placeholder="Recherche générale (nom, prénom)..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-10"
                />
              </div>
            </div>
            <div className="flex gap-2">
              <Input
                placeholder="Rechercher par ID..."
                value={filterById}
                onChange={(e) => setFilterById(e.target.value)}
                className="w-40"
              />
              <Input
                placeholder="Rechercher par téléphone..."
                value={filterByPhone}
                onChange={(e) => setFilterByPhone(e.target.value)}
                className="w-48"
              />
            </div>
          </div>
          
          {/* Deuxième ligne de filtres */}
          <div className="flex flex-col lg:flex-row gap-4 mb-6">
            <div className="flex gap-2 flex-wrap">
              <Select value={filterSegment} onValueChange={handleSegmentFilterChange}>
                <SelectTrigger className="w-48">
                  <SelectValue placeholder="1. Sélectionnez le segment" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">Tous les segments</SelectItem>
                  {(segments || []).map((segment) => (
                    <SelectItem key={segment.id} value={segment.nom}>{segment.nom}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
              
              <Select 
                value={filterByVille} 
                onValueChange={setFilterByVille}
                disabled={filterSegment === "all"}
              >
                <SelectTrigger className="w-48">
                  <SelectValue placeholder={filterSegment === "all" ? "2. Choisissez d'abord un segment" : "2. Sélectionnez la ville"} />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">Toutes les villes</SelectItem>
                  {getVillesDisponiblesPourFiltre().map(ville => (
                    <SelectItem key={ville.id} value={ville.id}>{ville.nom_ville}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
              
              <Select value={filterStatutContact} onValueChange={setFilterStatutContact}>
                <SelectTrigger className="w-48">
                  <SelectValue placeholder="Statut Contact" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">Tous les statuts</SelectItem>
                  {STATUTS_CONTACT.map((statut) => (
                    <SelectItem key={statut} value={statut}>{statut}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
              
              <Select value={filterByRendezVous} onValueChange={setFilterByRendezVous}>
                <SelectTrigger className="w-48">
                  <SelectValue placeholder="Rendez-vous" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">Tous</SelectItem>
                  <SelectItem value="avec">Avec RDV</SelectItem>
                  <SelectItem value="sans">Sans RDV</SelectItem>
                </SelectContent>
              </Select>
            </div>
            
            <div className="flex gap-2 items-center">
              <Button variant="outline" onClick={resetFilters} size="sm">
                Réinitialiser
              </Button>
              <div className="text-sm text-muted-foreground">
                {filteredProspects.length} résultat{filteredProspects.length > 1 ? 's' : ''}
              </div>
            </div>
          </div>

          {/* Section Actions en Masse - Visible seulement pour les utilisateurs autorisés */}
          {isBulkActionsVisible && (
            <div className="mb-6 p-4 border border-orange-200 bg-orange-50 rounded-lg">
              <div className="flex flex-col lg:flex-row gap-4 items-center justify-between">
                <div className="flex items-center gap-4">
                  <span className="text-sm font-medium text-orange-800">
                    Actions en masse ({selectedProspects.length} sélectionné{selectedProspects.length > 1 ? 's' : ''})
                  </span>
                  {selectedProspects.length > 0 && (
                    <div className="flex gap-2">
                      <Button 
                        size="sm" 
                        variant="destructive"
                        onClick={() => handleBulkAction('delete')}
                      >
                        <Trash2 className="h-4 w-4 mr-1" />
                        Supprimer
                      </Button>
                      <Button 
                        size="sm" 
                        variant="outline"
                        onClick={() => handleBulkAction('change_ville')}
                      >
                        Changer ville
                      </Button>
                      <Button 
                        size="sm" 
                        variant="outline"
                        onClick={() => handleBulkAction('change_segment')}
                      >
                        Changer segment
                      </Button>
                      <Button 
                        size="sm" 
                        variant="outline"
                        onClick={() => handleBulkAction('change_statut')}
                      >
                        Changer statut
                      </Button>
                    </div>
                  )}
                </div>
                {selectedProspects.length > 0 && (
                  <Button 
                    size="sm" 
                    variant="ghost"
                    onClick={() => {
                      setSelectedProspects([]);
                      setSelectAll(false);
                    }}
                  >
                    Désélectionner tout
                  </Button>
                )}
              </div>
            </div>
          )}

          {/* Table des prospects */}
          <div className="rounded-md border overflow-hidden">
            <Table className="data-table">
              <TableHeader>
                <TableRow>
                  <TableHead className="w-12">
                    <Checkbox
                      checked={selectAll}
                      onCheckedChange={handleSelectAll}
                    />
                  </TableHead>
                  <TableHead>ID</TableHead>
                  <TableHead>Nom & Prénom</TableHead>
                  <TableHead>Téléphone</TableHead>
                  <TableHead>Ville</TableHead>
                  <TableHead>Segment</TableHead>
                  <TableHead>Contact statut</TableHead>
                  <TableHead className="numeric">Durée d'appel</TableHead>
                  <TableHead>RDV Le</TableHead>
                  <TableHead>Date d'insertion</TableHead>
                  <TableHead>Statut</TableHead>
                  <TableHead className="text-center">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {paginatedProspects.map((prospect) => (
                  <TableRow key={prospect.id} className="hover:bg-primary/2 transition-all duration-200">
                    <TableCell>
                      <Checkbox
                        checked={selectedProspects.includes(prospect.id)}
                        onCheckedChange={(checked) => handleSelectProspect(prospect.id, !!checked)}
                      />
                    </TableCell>
                    <TableCell className="font-mono text-sm font-medium">
                      {formatCustomId(prospect)}
                    </TableCell>
                    <TableCell className="font-semibold">
                      {prospect.nom} {prospect.prenom}
                    </TableCell>
                    <TableCell className="font-mono text-sm">{prospect.telephone}</TableCell>
                    <TableCell className="font-medium">{prospect.villes?.nom_ville || prospect.ville}</TableCell>
                    <TableCell>
                      <Badge variant="outline" className="bg-primary/10 text-primary border-primary/20 font-medium">
                        {prospect.segments?.nom || 'Non défini'}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <Badge className={getStatutContactColor(prospect.statut_contact || 'Non Contacté')}>
                        {prospect.statut_contact || 'Non Contacté'}
                      </Badge>
                     </TableCell>
                     <TableCell className="numeric">
                       {prospect.duree_appel ? (
                         <Badge variant="secondary" className="font-mono font-bold">
                           {Math.floor(prospect.duree_appel / 60)}:
                           {(prospect.duree_appel % 60).toString().padStart(2, '0')}
                         </Badge>
                       ) : (
                         <span className="text-muted-foreground text-sm">-</span>
                       )}
                     </TableCell>
                     <TableCell className="font-medium">
                       {prospect.rdv_le ? new Date(prospect.rdv_le).toLocaleDateString('fr-FR') : '-'}
                     </TableCell>
                     <TableCell className="font-medium">
                       {new Date(prospect.created_at).toLocaleDateString('fr-FR')}
                     </TableCell>
                      <TableCell>
                        <Badge 
                          variant={prospect.statut_inscription === 'Inscrit' ? 'default' : 'secondary'}
                          className="font-medium"
                        >
                          {prospect.statut_inscription === 'Inscrit' ? 'Inscrit' : 'Non inscrit'}
                        </Badge>
                      </TableCell>
                     <TableCell>
                       <div className="flex gap-1 justify-center">
                         <Button
                           variant="outline"
                           size="sm"
                           onClick={() => handleCall(prospect)}
                           title="Faire un appel"
                           className="btn-icon-enhanced h-8 w-8"
                         >
                           <Phone className="h-4 w-4" />
                         </Button>
                         <Button
                           variant="outline"
                           size="sm"
                           onClick={() => handleMessage(prospect)}
                           title="Envoyer message"
                           className="btn-icon-enhanced h-8 w-8"
                         >
                           <MessageSquare className="h-4 w-4" />
                         </Button>
                         <Button
                           variant="outline"
                           size="sm"
                           onClick={() => handleEdit(prospect)}
                           title="Modifier"
                           className="btn-icon-enhanced h-8 w-8"
                         >
                           <Edit className="h-4 w-4" />
                         </Button>
                         <Button
                           variant="destructive"
                           size="sm"
                           onClick={() => handleDelete(prospect)}
                           title="Supprimer"
                           className="h-8 w-8 p-0 hover:scale-110 transition-transform duration-200"
                         >
                           <Trash2 className="h-4 w-4" />
                         </Button>
                       </div>
                     </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>

          {/* Pagination */}
          <div className="flex items-center justify-between space-x-2 py-4">
            <div className="text-sm text-muted-foreground">
              Affichage de {((currentPage - 1) * itemsPerPage) + 1} à {Math.min(currentPage * itemsPerPage, filteredProspects.length)} sur {filteredProspects.length} prospects
            </div>
            <div className="flex items-center space-x-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setCurrentPage(prev => Math.max(prev - 1, 1))}
                disabled={currentPage === 1}
              >
                Précédent
              </Button>
              <div className="text-sm">
                Page {currentPage} sur {totalPages}
              </div>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setCurrentPage(prev => Math.min(prev + 1, totalPages))}
                disabled={currentPage === totalPages}
              >
                Suivant
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Modal d'appel */}
      <Dialog open={isCallModalOpen} onOpenChange={handleCloseCallModal}>
        <DialogContent className="max-w-4xl w-full">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              Détails de prospect ID ({currentProspect?.villes?.nom_ville || ''} {currentProspect?.prospect_id_unique?.slice(-6) || ''}) : {currentProspect?.telephone} - 
              <span className="text-blue-500">
                Appel time ({formatCallTime(callDuration)})
              </span>
            </DialogTitle>
          </DialogHeader>
          
          <div className="space-y-6">
            {/* Section Informations personnelles */}
            <div className="bg-muted/30 p-4 rounded-lg">
              <h3 className="text-lg font-semibold mb-4 text-primary">Informations personnelles</h3>
              <div className="grid grid-cols-3 gap-4">
                <div>
                  <Label htmlFor="nom">Nom :</Label>
                  <Input
                    id="nom"
                    value={currentProspect?.nom || ''}
                    disabled
                    className="bg-muted"
                  />
                </div>
                <div>
                  <Label htmlFor="prenom">Prénom :</Label>
                  <Input
                    id="prenom"
                    value={currentProspect?.prenom || ''}
                    disabled
                    className="bg-muted"
                  />
                </div>
                <div>
                  <Label htmlFor="cin">CIN :</Label>
                  <Input
                    id="cin"
                    value={currentProspect?.cin || ''}
                    disabled
                    className="bg-muted"
                  />
                </div>
              </div>
            </div>

            {/* Section Localisation */}
            <div className="bg-muted/30 p-4 rounded-lg">
              <h3 className="text-lg font-semibold mb-4 text-primary">Localisation</h3>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label htmlFor="ville">Ville :</Label>
                  <div className="relative ville-dropdown-container">
                    <div className="flex">
                      <Input
                        placeholder="Rechercher par nom ou code ville..."
                        value={callModalVilleSearch}
                        onChange={(e) => {
                          setCallModalVilleSearch(e.target.value);
                          if (e.target.value.trim()) {
                            setShowCallModalVilleDropdown(true);
                          } else {
                            setCallModalVilleId('');
                            setShowCallModalVilleDropdown(callModalVillesDisponibles.length > 0);
                          }
                        }}
                        onFocus={() => {
                          if (callModalVilleSearch.trim()) {
                            setShowCallModalVilleDropdown(callModalVillesDisponibles.length > 0);
                          }
                        }}
                        className="pr-10"
                      />
                      <Button 
                        type="button"
                        variant="ghost" 
                        size="sm" 
                        className="absolute right-0 top-0 h-full px-3"
                        onClick={() => setShowCallModalVilleDropdown(!showCallModalVilleDropdown)}
                      >
                        <Search className="h-4 w-4" />
                      </Button>
                    </div>
                    
                    {showCallModalVilleDropdown && callModalFilteredVilles.length > 0 && (
                      <div className="absolute z-50 w-full mt-1 bg-background border border-border rounded-md shadow-lg max-h-60 overflow-auto">
                        {callModalFilteredVilles.map((ville) => (
                          <div
                            key={ville.id}
                            className="px-3 py-2 hover:bg-muted cursor-pointer text-sm"
                            onClick={() => {
                              handleCallModalVilleChange(ville.id);
                              setCallModalVilleSearch(ville.nom_ville);
                            }}
                          >
                            {ville.nom_ville} ({ville.code_ville})
                          </div>
                        ))}
                      </div>
                    )}
                    
                    {showCallModalVilleDropdown && callModalFilteredVilles.length === 0 && callModalVilleSearch && (
                      <div className="absolute z-50 w-full mt-1 bg-background border border-border rounded-md shadow-lg">
                        <div className="px-3 py-2 text-sm text-muted-foreground">
                          Aucune ville trouvée
                        </div>
                      </div>
                    )}
                  </div>
                </div>
                <div>
                  <Label htmlFor="segment">Segment :</Label>
                  <Input
                    id="segment"
                    value={currentProspect?.segments?.nom || 'Non défini'}
                    disabled
                    className="bg-muted"
                  />
                </div>
              </div>
            </div>

            {/* Section Statut de contact */}
            <div className="bg-muted/30 p-4 rounded-lg">
              <h3 className="text-lg font-semibold mb-4 text-primary">Statut de contact</h3>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label htmlFor="statut_contact">Statut de contact:</Label>
                  <Select value={contactStatus} onValueChange={(value) => {
                    setContactStatus(value);
                    // Sauvegarde automatique quand le statut change et qu'il y a une durée d'appel
                    if (callDuration > 0 && currentProspect) {
                      handleAutoSave(value);
                    }
                  }}>
                    <SelectTrigger>
                      <SelectValue placeholder="Sélectionner un statut" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="Non Contacté">Non Contacté</SelectItem>
                      <SelectItem value="Contacté avec RDV">Contacté avec RDV</SelectItem>
                      <SelectItem value="Contacté sans RDV">Contacté sans RDV</SelectItem>
                      <SelectItem value="Contacté sans réponse">Contacté sans réponse</SelectItem>
                      <SelectItem value="Boite vocale">Boite vocale</SelectItem>
                      <SelectItem value="Non intéressé">Non intéressé</SelectItem>
                      <SelectItem value="Déjà inscrit">Déjà inscrit</SelectItem>
                      <SelectItem value="À recontacter">À recontacter</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <Label htmlFor="commentaire">Commentaire:</Label>
                  <Textarea
                    id="commentaire"
                    value={comment}
                    onChange={(e) => setComment(e.target.value)}
                    placeholder="Ajouter un commentaire..."
                    rows={3}
                  />
                </div>
              </div>
            </div>

            {/* Section Rendez-vous */}
            <div className="bg-muted/30 p-4 rounded-lg">
              <h3 className="text-lg font-semibold mb-4 text-primary">Rendez-vous</h3>
              <div className="grid grid-cols-3 gap-4">
                <div>
                  <Label htmlFor="rendez_vous_a">Rendez-vous À:</Label>
                  <Input
                    id="rendez_vous_a"
                    value="Choisissez le centre de formation"
                    disabled
                    className="bg-muted text-sm"
                  />
                </div>
                <div>
                  <Label htmlFor="rendez_vous_le">Rendez-vous le:</Label>
                  <Popover>
                    <PopoverTrigger asChild>
                      <Button
                        variant={"outline"}
                        className={cn(
                          "w-full justify-start text-left font-normal",
                          !appointmentDate && "text-muted-foreground"
                        )}
                      >
                        <CalendarIcon className="mr-2 h-4 w-4" />
                        {appointmentDate ? format(new Date(appointmentDate), "dd/MM/yyyy") : <span>Choisir une date</span>}
                      </Button>
                    </PopoverTrigger>
                    <PopoverContent className="w-auto p-0" align="start">
                      <Calendar
                        mode="single"
                        selected={appointmentDate ? new Date(appointmentDate) : undefined}
                        onSelect={(date) => {
                          if (date) {
                            setAppointmentDate(format(date, "yyyy-MM-dd"));
                          }
                        }}
                        disabled={(date) => date < new Date()}
                        initialFocus
                        className={cn("p-3 pointer-events-auto")}
                      />
                    </PopoverContent>
                  </Popover>
                </div>
                <div>
                  <Label htmlFor="rendez_vous_heure">Heure:</Label>
                  <Input
                    id="rendez_vous_heure"
                    type="time"
                    value={appointmentTime}
                    onChange={(e) => setAppointmentTime(e.target.value)}
                  />
                </div>
              </div>
            </div>
          </div>
          
          <div className="flex justify-between gap-2 mt-6">
            <Button 
              variant="outline" 
              onClick={handleCancelCall}
              className="bg-red-500 hover:bg-red-600 text-white"
            >
              Raccrocher l'appel
            </Button>
            <Button 
              onClick={handleCloseCallModal}
              className="bg-green-500 hover:bg-green-600 text-white"
            >
              Enregistrer & raccrocher l'appel
            </Button>
          </div>
        </DialogContent>
      </Dialog>

      {/* Modal d'actions en masse */}
      <Dialog open={isBulkModalOpen} onOpenChange={setIsBulkModalOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>
              {bulkAction === 'delete' && 'Supprimer les prospects sélectionnés'}
              {bulkAction === 'change_ville' && 'Changer la ville'}
              {bulkAction === 'change_segment' && 'Changer le segment'}  
              {bulkAction === 'change_statut' && 'Changer le statut de contact'}
            </DialogTitle>
          </DialogHeader>
          
          <div className="space-y-4">
            <div className="p-4 bg-yellow-50 border border-yellow-200 rounded-lg">
              <p className="text-sm text-yellow-800">
                <strong>Attention :</strong> Cette action va automatiquement :
              </p>
              <ul className="text-sm text-yellow-700 mt-2 list-disc list-inside">
                <li>Remettre la date d'insertion à maintenant</li>
                <li>Supprimer les rendez-vous programmés</li>
                <li>Remettre à zéro les durées d'appel</li>
              </ul>
            </div>

            {bulkAction === 'delete' && (
              <div className="p-4 bg-red-50 border border-red-200 rounded-lg">
                <p className="text-sm text-red-800">
                  Êtes-vous sûr de vouloir supprimer définitivement {selectedProspects.length} prospect{selectedProspects.length > 1 ? 's' : ''} ?
                  Cette action est irréversible.
                </p>
              </div>
            )}

            {bulkAction === 'change_ville' && (
              <div>
                <Label>Nouvelle ville</Label>
                <Select value={bulkVille} onValueChange={setBulkVille}>
                  <SelectTrigger>
                    <SelectValue placeholder="Sélectionnez une ville" />
                  </SelectTrigger>
                  <SelectContent>
                    {toutesLesVilles.map(ville => (
                      <SelectItem key={ville.id} value={ville.id}>
                        {ville.nom_ville}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            )}

            {bulkAction === 'change_segment' && (
              <div>
                <Label>Nouveau segment</Label>
                <Select value={bulkSegment} onValueChange={setBulkSegment}>
                  <SelectTrigger>
                    <SelectValue placeholder="Sélectionnez un segment" />
                  </SelectTrigger>
                  <SelectContent>
                    {segments.map(segment => (
                      <SelectItem key={segment.id} value={segment.id}>
                        {segment.nom}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            )}

            {bulkAction === 'change_statut' && (
              <div>
                <Label>Nouveau statut de contact</Label>
                <Select value={bulkStatutContact} onValueChange={setBulkStatutContact}>
                  <SelectTrigger>
                    <SelectValue placeholder="Sélectionnez un statut" />
                  </SelectTrigger>
                  <SelectContent>
                    {STATUTS_CONTACT.map(statut => (
                      <SelectItem key={statut} value={statut}>
                        {statut}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            )}
          </div>

          <div className="flex justify-end gap-2 mt-6">
            <Button variant="outline" onClick={resetBulkStates}>
              Annuler
            </Button>
            <Button 
              onClick={executeBulkAction}
              variant={bulkAction === 'delete' ? 'destructive' : 'default'}
            >
              {bulkAction === 'delete' ? 'Supprimer' : 'Appliquer'}
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
