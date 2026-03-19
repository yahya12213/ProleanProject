import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { Calendar } from "@/components/ui/calendar";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { cn } from "@/lib/utils";
import { format } from "date-fns";
import { fr } from "date-fns/locale";
import { useToast } from "@/hooks/use-toast";
// Supabase supprimé, toute la logique doit passer par l'API Express locale
import { useCurrentProfile } from "@/hooks/useCurrentProfile";
import { usePointageDeletePermission } from "@/hooks/usePointageDeletePermission";
import { usePointageHours, type HoraireActif } from "@/hooks/usePointageHours";
import { type PointageRecord, type DemandeHeuresSup, getDayKey } from "@/lib/pointage-calculations";
import { 
  detectMissingDatesAndFill, 
  getMonthDateRange, 
  getYearDateRange,
  isVirtualPointage,
  type VirtualPointageRecord 
} from "@/lib/pointage-gap-detection";
import { PointageHoursCell } from "./PointageHoursCell";
import { ConfiguredHourCell } from "./ConfiguredHourCell";
import { 
  Clock, 
  Calendar as CalendarIcon, 
  Plus, 
  Edit2, 
  FileText, 
  User,
  AlertCircle,
  CheckCircle,
  XCircle,
  Eye,
  Trash2,
  Play,
  Pause,
  PauseCircle,
  Upload,
  Download
} from "lucide-react";
import { Checkbox } from "@/components/ui/checkbox";
import { CorrectionStatusButton } from "./CorrectionStatusButton";
import { ImprovedDemandeDetailModal } from "./ImprovedDemandeDetailModal";
import { PointageFilters } from "./PointageFilters";
import { PointageImportModal } from "./PointageImportModal";
import { PointageExportModal } from "./PointageExportModal";

interface Pointage {
  id: string;
  profile_id: string;
  type_pointage: string;
  timestamp_pointage: string;
  localisation?: string;
  notes?: string;
  valide_par?: string;
  created_at: string;
  ecart_minutes?: number;
  heures_reelles?: number;
  heures_configurees?: number;
  heure_configuree_entree?: string;
  heure_configuree_sortie?: string;
}

interface PointageAutomatique {
  id: string;
  profile_id: string;
  date_pointage: string;
  type_pointage: string;
  horaire_debut?: string;
  horaire_fin?: string;
  heures_travaillees: number;
  motif?: string;
  created_at: string;
}

interface DemandeRh {
  id: string;
  demandeur_id: string;
  type_demande: string;
  titre: string;
  description: string | null;
  date_debut?: string | null;
  date_fin?: string | null;
  statut: string;
  created_at: string;
  updated_at: string;
}

export function PortailEmployeRh() {
  const [isPointageDialogOpen, setIsPointageDialogOpen] = useState(false);
  const [isDemandeDialogOpen, setIsDemandeDialogOpen] = useState(false);
  const [selectedDate, setSelectedDate] = useState<Date>();
  const [selectedEndDate, setSelectedEndDate] = useState<Date>();
  const [leaveType, setLeaveType] = useState<string>("");
  const [leaveReason, setLeaveReason] = useState<string>("");
  const [typePointage, setTypePointage] = useState<"entree" | "sortie">("entree");
  const [isPointing, setIsPointing] = useState(false);
  const [pointages, setPointages] = useState<Pointage[]>([]);
  const [pointagesAutomatiques, setPointagesAutomatiques] = useState<PointageAutomatique[]>([]);
  const [demandes, setDemandes] = useState<DemandeRh[]>([]);
  const [loading, setLoading] = useState(true);
  const [horaireActif, setHoraireActif] = useState<HoraireActif | null>(null);
  const [demandesHeuresSup, setDemandesHeuresSup] = useState<DemandeHeuresSup[]>([]);
  
  // États pour les filtres
  const [selectedYear, setSelectedYear] = useState<string>("all");
  const [selectedMonth, setSelectedMonth] = useState<string>("all");
  const [dateDebut, setDateDebut] = useState<Date | undefined>();
  const [dateFin, setDateFin] = useState<Date | undefined>();
  const [availableYears, setAvailableYears] = useState<string[]>([]);
  const [filteredPointages, setFilteredPointages] = useState<VirtualPointageRecord[]>([]);
  const [heuresCalculees, setHeuresCalculees] = useState<number | undefined>();
  
  // États pour import/export
  const [isImportModalOpen, setIsImportModalOpen] = useState(false);
  const [isExportModalOpen, setIsExportModalOpen] = useState(false);
  
  // États pour le formulaire de correction
  const [selectedPointage, setSelectedPointage] = useState<VirtualPointageRecord | null>(null);
  const [correctionForm, setCorrectionForm] = useState({
    type_pointage: '',
    timestamp_pointage: '',
    localisation: '',
    notes: '',
    justification: ''
  });
  
  // États pour le modal de détails des demandes
  const [selectedDemandeDetail, setSelectedDemandeDetail] = useState<DemandeRh | null>(null);
  const [isDemandeDetailOpen, setIsDemandeDetailOpen] = useState(false);

  // États pour la sélection multiple des pointages
  const [selectedPointages, setSelectedPointages] = useState<string[]>([]);
  const [isDeleting, setIsDeleting] = useState(false);

  const { toast } = useToast();
  const { data: profile } = useCurrentProfile();
  const { canDeletePointages, loading: permissionLoading } = usePointageDeletePermission();

  useEffect(() => {
    if (profile?.id) {
      loadData();
    } else if (profile === null) {
      // Profil n'existe pas, afficher un message d'erreur ou rediriger
      toast({
        title: "Profil manquant",
        description: "Votre profil utilisateur n'a pas été trouvé. Contactez l'administrateur.",
        variant: "destructive"
      });
    }
  }, [profile]);

  // Effet pour appliquer les filtres
  useEffect(() => {
    applyFilters();
  }, [pointages, selectedYear, selectedMonth, dateDebut, dateFin]);

  // Effet pour recharger les données quand les filtres changent
  useEffect(() => {
    if (profile?.id && (selectedYear !== "all" || selectedMonth !== "all" || dateDebut || dateFin)) {
      loadData(selectedYear, selectedMonth);
    }
  }, [profile?.id, selectedYear, selectedMonth, dateDebut, dateFin]);

  const applyFilters = () => {
    let filtered = [...pointages];

    // Filtre par fourchette de dates personnalisée (prioritaire)
    if (dateDebut && dateFin) {
      const debutStr = dateDebut.toISOString().split('T')[0];
      const finStr = dateFin.toISOString().split('T')[0];
      
      filtered = filtered.filter(p => {
        const pointageDate = p.timestamp_pointage.split('T')[0];
        return pointageDate >= debutStr && pointageDate <= finStr;
      });
    } else {
      // Filtres traditionnels (année/mois)
      if (selectedYear !== "all") {
        filtered = filtered.filter(p => 
          new Date(p.timestamp_pointage).getFullYear().toString() === selectedYear
        );
      }

      if (selectedMonth !== "all") {
        filtered = filtered.filter(p => 
          (new Date(p.timestamp_pointage).getMonth() + 1).toString() === selectedMonth
        );
      }
    }

    // Calculer les heures pour la période sélectionnée
    if (dateDebut && dateFin) {
      const totalHeuresReelles = filtered.reduce((total, p) => {
        return total + (p.heures_reelles || 0);
      }, 0);
      
      // Diviser par 2 comme demandé
      setHeuresCalculees(totalHeuresReelles / 2);
    } else {
      setHeuresCalculees(undefined);
    }

    // Détecter et combler les dates manquantes
    let dateRange = null;
    if (dateDebut && dateFin) {
      // Pour une fourchette personnalisée, ne pas combler automatiquement
      dateRange = null;
    } else if (selectedYear !== "all" && selectedMonth !== "all") {
      dateRange = getMonthDateRange(selectedYear, selectedMonth);
    } else if (selectedYear !== "all") {
      dateRange = getYearDateRange(selectedYear);
    }

    // Convertir les pointages normaux en VirtualPointageRecord et combler les dates manquantes
    const virtualPointages = detectMissingDatesAndFill(
      filtered.map(p => ({
        ...p, // Copier TOUS les champs du pointage, y compris les champs calculés
        id: p.id,
        timestamp_pointage: p.timestamp_pointage,
        type_pointage: p.type_pointage,
        profile_id: p.profile_id,
        localisation: p.localisation,
        notes: p.notes
      })),
      dateRange
    );

    setFilteredPointages(virtualPointages);
  };

  // Fonction pour calculer et sauvegarder les valeurs calculées
  const calculateAndSavePointageValues = async (
    pointagesData: Pointage[], 
    horaireActif: HoraireActif, 
    demandesHeuresSup: DemandeHeuresSup[]
  ) => {
    try {
      const updates = [];
      
      // Grouper les pointages par date
      const pointagesByDate = new Map<string, Pointage[]>();
      
      for (const pointage of pointagesData) {
        // Ignorer les pointages virtuels
        if (isVirtualPointage(pointage)) continue;
        
        const currentDate = pointage.timestamp_pointage.split('T')[0];
        
        if (!pointagesByDate.has(currentDate)) {
          pointagesByDate.set(currentDate, []);
        }
        pointagesByDate.get(currentDate)!.push(pointage);
      }
      
      // Traiter chaque date
      for (const [currentDate, pointagesJour] of pointagesByDate) {
        const dayKey = getDayKey(currentDate);
        const horaireJour = horaireActif.horaires_semaine?.[dayKey];
        
        if (!horaireJour || !horaireJour.heureDebut || !horaireJour.heureFin) continue;
        
        // Calculer les heures configurées
        const [debutH, debutM] = horaireJour.heureDebut.split(':').map(Number);
        const [finH, finM] = horaireJour.heureFin.split(':').map(Number);
        const debutMinutes = debutH * 60 + debutM;
        const finMinutes = finH * 60 + finM;
        const heuresConfigurees = (finMinutes - debutMinutes) / 60;
        
        // Calculer les écarts totaux de la journée
        const entries = pointagesJour.filter(p => p.type_pointage === 'entree').sort((a, b) => a.timestamp_pointage.localeCompare(b.timestamp_pointage));
        const exits = pointagesJour.filter(p => p.type_pointage === 'sortie').sort((a, b) => a.timestamp_pointage.localeCompare(b.timestamp_pointage));
        
        let totalEcartsMinutes = 0;
        let employePresent = entries.length > 0 && exits.length > 0;
        
        // Calculer les écarts pour les entrées (retards)
        for (const entry of entries) {
          const entryTime = new Date(entry.timestamp_pointage);
          const entryMinutes = entryTime.getHours() * 60 + entryTime.getMinutes();
          const [configH, configM] = horaireJour.heureDebut.split(':').map(Number);
          const configMinutes = configH * 60 + configM;
          const ecartEntree = configMinutes - entryMinutes; // Négatif si retard
          if (ecartEntree < 0) totalEcartsMinutes += Math.abs(ecartEntree);
        }
        
        // Calculer les écarts pour les sorties (sorties anticipées)
        for (const exit of exits) {
          const exitTime = new Date(exit.timestamp_pointage);
          const exitMinutes = exitTime.getHours() * 60 + exitTime.getMinutes();
          const [configH, configM] = horaireJour.heureFin.split(':').map(Number);
          const configMinutes = configH * 60 + configM;
          const ecartSortie = exitMinutes - configMinutes; // Négatif si sortie anticipée
          if (ecartSortie < 0) totalEcartsMinutes += Math.abs(ecartSortie);
        }
        
        // Calculer les pauses non rémunérées et rémunérées
        let pausesNonRemunerees = 0;
        let pausesRemunerees = 0;
        if (employePresent && horaireJour.pauses) {
          for (const pause of horaireJour.pauses) {
            const [debutH, debutM] = pause.heureDebut.split(':').map(Number);
            const [finH, finM] = pause.heureFin.split(':').map(Number);
            const dureeMinutes = (finH * 60 + finM) - (debutH * 60 + debutM);
            
            if (pause.remuneree) {
              pausesRemunerees += dureeMinutes;
            } else {
              pausesNonRemunerees += dureeMinutes;
            }
          }
        }
        
        // Calculer les heures théoriques : heures configurées - pauses non rémunérées
        const heuresTheoriques = heuresConfigurees - (pausesNonRemunerees / 60);
        
        // En cas de retard ou sortie anticipée, soustraire aussi les pauses rémunérées
        const hasEcarts = totalEcartsMinutes > 0;
        const pausesRemuneresADeduire = hasEcarts ? (pausesRemunerees / 60) : 0;
        
        // Debug pour 19/08/2025
        if (currentDate === '2025-08-19') {
          console.log(`🔢 DEBUG CALCUL 19/08:`, {
            heuresConfigurees,
            pausesNonRemunerees,
            pausesRemunerees,
            totalEcartsMinutes,
            hasEcarts,
            heuresTheoriques,
            pausesRemuneresADeduire,
            calculFinal: heuresTheoriques - (totalEcartsMinutes / 60) - pausesRemuneresADeduire
          });
        }
        
        // Calculer les heures réelles : heures théoriques - écarts - pauses rémunérées (si écarts)
        const heuresReelles = Math.max(0, heuresTheoriques - (totalEcartsMinutes / 60) - pausesRemuneresADeduire);
        
        // Traiter chaque pointage de la journée
        for (const pointage of pointagesJour) {
          // Calculer l'heure configurée selon le type de pointage
          const heureConfiguree = pointage.type_pointage === "entree" 
            ? horaireJour.heureDebut 
            : horaireJour.heureFin;
          
          // Calculer l'écart en minutes selon la logique correcte
          const pointageTime = new Date(pointage.timestamp_pointage);
          const pointageHour = pointageTime.getHours();
          const pointageMinute = pointageTime.getMinutes();
          
          const [configHour, configMinute] = heureConfiguree.split(':').map(Number);
          const pointageMinutes = pointageHour * 60 + pointageMinute;
          const configMinutes = configHour * 60 + configMinute;
          
          // Logique correcte des écarts :
          // Entrée : configMinutes - pointageMinutes (négatif si retard)
          // Sortie : pointageMinutes - configMinutes (négatif si sortie anticipée)
          const ecartMinutes = pointage.type_pointage === "entree" 
            ? configMinutes - pointageMinutes 
            : pointageMinutes - configMinutes;
          
          // Debug pour 19/08/2025
          if (currentDate === '2025-08-19') {
            console.log(`💾 SAUVEGARDE 19/08 - ${pointage.type_pointage}:`, {
              heuresReelles,
              heuresReellesArrondies: Math.round(heuresReelles * 100) / 100,
              pointageId: pointage.id
            });
          }
          
          // Préparer la mise à jour
          const updateData: any = {
            ecart_minutes: ecartMinutes,
            heures_reelles: Math.round(heuresReelles * 100) / 100,
            heures_configurees: Math.round(heuresConfigurees * 100) / 100,
          };
          
          if (pointage.type_pointage === 'entree') {
            updateData.heure_configuree_entree = heureConfiguree;
          } else if (pointage.type_pointage === 'sortie') {
            updateData.heure_configuree_sortie = heureConfiguree;
          }
          
          updates.push({
            id: pointage.id,
            ...updateData
          });
        }
      }
      
      // Effectuer les mises à jour par batch
      if (updates.length > 0) {
        console.log(`Mise à jour de ${updates.length} pointages avec les valeurs calculées`);
        
        for (const update of updates) {
          // Remplacement Supabase: mise à jour via API Express
          try {
            const res = await fetch(`/api/pointages/${update.id}`, {
              method: 'PUT',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                ecart_minutes: update.ecart_minutes,
                heures_reelles: update.heures_reelles,
                heures_configurees: update.heures_configurees,
                heure_configuree_entree: update.heure_configuree_entree || null,
                heure_configuree_sortie: update.heure_configuree_sortie || null
              })
            });
            if (!res.ok) {
              const error = await res.text();
              console.error('Erreur mise à jour pointage:', error);
            } else {
              console.log(`Pointage ${update.id} mis à jour:`, update);
            }
          } catch (error) {
            console.error('Erreur mise à jour pointage:', error);
          }
        }
      }
      
      // Traiter aussi les pointages virtuels pour s'assurer qu'ils ont les heures configurées
      for (const pointage of pointagesData) {
        if (isVirtualPointage(pointage)) {
          const currentDate = pointage.timestamp_pointage.split('T')[0];
          const dayKey = getDayKey(currentDate);
          const horaireJour = horaireActif.horaires_semaine?.[dayKey];
          
          if (horaireJour && horaireJour.heureDebut && horaireJour.heureFin) {
            // Calculer les heures configurées pour ce jour
            const [debutH, debutM] = horaireJour.heureDebut.split(':').map(Number);
            const [finH, finM] = horaireJour.heureFin.split(':').map(Number);
            const debutMinutes = debutH * 60 + debutM;
            const finMinutes = finH * 60 + finM;
            const heuresConfigurees = (finMinutes - debutMinutes) / 60;
            
            // Assigner les valeurs calculées directement au pointage virtuel
            pointage.heures_configurees = Math.round(heuresConfigurees * 100) / 100;
            pointage.heures_reelles = 0; // Pas de travail effectif pour les jours non travaillés
            pointage.ecart_minutes = 0;
            
            if (pointage.type_pointage === 'entree') {
              pointage.heure_configuree_entree = horaireJour.heureDebut;
            } else if (pointage.type_pointage === 'sortie') {
              pointage.heure_configuree_sortie = horaireJour.heureFin;
            }
          }
        }
      }
    } catch (error) {
      console.error('Erreur lors du calcul des valeurs:', error);
    }
  };

  const loadData = async (year?: string, month?: string) => {
    try {
      setLoading(true);
      
      // Construire la requête avec filtres
      // Remplacement Supabase: fetch pointages depuis l'API Express
      let pointagesRes = await fetch(`/api/pointages?profile_id=${profile?.id}${year && year !== "all" ? `&year=${year}` : ''}${month && month !== "all" ? `&month=${month}` : ''}`);
      let pointagesData = await pointagesRes.json();

      // Appliquer les filtres de date si spécifiés
      if (year && year !== "all") {
  // Filtrage déjà inclus dans l'API Express
      }

      if (month && month !== "all" && year && year !== "all") {
  // Filtrage déjà inclus dans l'API Express
      }

  // pointagesData already loaded above

      // Charger les pointages automatiques
  // Remplacement Supabase: fetch pointages automatiques depuis l'API Express
  let pointagesAutoRes = await fetch(`/api/pointages_automatiques?profile_id=${profile?.id}`);
  let pointagesAutoData = await pointagesAutoRes.json();

      // Charger les demandes RH
  // Remplacement Supabase: fetch demandes RH depuis l'API Express
  let demandesRes = await fetch(`/api/demandes_rh?demandeur_id=${profile?.id}`);
  let demandesData = await demandesRes.json();

      // Charger l'horaire actif
      // Remplacement Supabase: fetch horaire actif depuis l'API Express
      let horaireRes = await fetch(`/api/horaires_modeles?is_active=true`);
      let horaireData = await horaireRes.json();

      // Charger les demandes d'heures supplémentaires validées
      // Remplacement Supabase: fetch heures supplémentaires depuis l'API Express
      let heuresSupRes = await fetch(`/api/declarations_heures_sup?profile_id=${profile?.id}&statut=approuve&is_active=true`);
      let heuresSupData = await heuresSupRes.json();

      setPointages(pointagesData || []);
  setPointagesAutomatiques(pointagesAutoData || []);
  setDemandes(demandesData || []);
  setHoraireActif(horaireData as unknown as HoraireActif);
  setDemandesHeuresSup(heuresSupData || []);

      // Calculer et sauvegarder les valeurs calculées pour les pointages
      if (pointagesData && horaireData) {
        await calculateAndSavePointageValues(pointagesData, horaireData as unknown as HoraireActif, heuresSupData || []);
        // Les valeurs calculées sont déjà dans pointagesData
      }

      // Extraire les années disponibles pour le filtre
      const years = Array.from(new Set(
        (pointagesData || []).map(p => new Date(p.timestamp_pointage).getFullYear().toString())
      )).sort((a, b) => parseInt(b) - parseInt(a));
      setAvailableYears(years);

    } catch (error) {
      console.error('Error loading data:', error);
      toast({
        title: "Erreur",
        description: "Impossible de charger les données",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };


  const getStatusColor = (statut: string) => {
    switch (statut) {
      case "valide":
      case "approuve": return "bg-green-100 text-green-800 border-green-300";
      case "en_attente":
      case "en_cours": return "bg-yellow-100 text-yellow-800 border-yellow-300";
      case "erreur":
      case "refuse": return "bg-red-100 text-red-800 border-red-300";
      default: return "bg-gray-100 text-gray-800 border-gray-300";
    }
  };

  const getStatusLabel = (statut: string) => {
    switch (statut) {
      case "valide": return "Validé";
      case "en_attente": return "En attente";
      case "erreur": return "Erreur";
      case "en_cours": return "En cours";
      case "approuve": return "Approuvé";
      case "refuse": return "Refusé";
      default: return statut;
    }
  };

  const getTypeLabel = (type: string) => {
    switch (type) {
      case "conges": return "Congé";
      case "formation": return "Formation";
      case "materiel": return "Matériel";
      case "correction_pointage": return "Correction Pointage";
      case "autre": return "Autre";
      default: return type;
    }
  };

  const heures_semaine = pointagesAutomatiques.reduce((total, p) => total + p.heures_travaillees, 0);
  const heures_theoriques = 35; // Horaire hebdo théorique

  // Pointage réel avec sauvegarde en base
  const handlePointage = async (type: "entree" | "sortie") => {
    if (!profile?.id) return;

    setIsPointing(true);
    try {
      // Remplacement Supabase: enregistrement du pointage via API Express
      const res = await fetch('/api/pointages', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          profile_id: profile.id,
          type_pointage: type,
          timestamp_pointage: new Date().toISOString(),
          localisation: "Bureau",
          notes: `Pointage ${type} automatique`
        })
      });
      if (!res.ok) throw new Error('Erreur lors de l\'enregistrement du pointage');
      toast({
        title: "Pointage enregistré",
        description: `Pointage ${type} enregistré avec succès`
      });
      // Recharger les données
      loadData();
    } catch (error) {
      console.error('Error saving pointage:', error);
      toast({
        title: "Erreur",
        description: "Impossible d'enregistrer le pointage",
        variant: "destructive"
      });
    } finally {
      setIsPointing(false);
    }
  };

  const openCorrectionDialog = (pointage: VirtualPointageRecord) => {
    setSelectedPointage(pointage);
    
    // Pour les pointages virtuels, pré-remplir avec des valeurs par défaut appropriées
    if (isVirtualPointage(pointage)) {
      const dateKey = format(new Date(pointage.timestamp_pointage), 'yyyy-MM-dd');
      
      // Heures par défaut selon le type de jour
      let defaultStartTime = '09:00';
      let defaultEndTime = '17:00';
      let defaultLocation = 'Bureau';
      let defaultNotes = '';
      
      if (pointage.isWeekend) {
        defaultNotes = 'Travail exceptionnellement le week-end';
        defaultLocation = 'Bureau - Week-end';
      } else if (pointage.isHoliday) {
        defaultNotes = 'Travail exceptionnellement le jour férié';
        defaultLocation = 'Bureau - Jour férié';
      }
      
      setCorrectionForm({
        type_pointage: 'entree',
        timestamp_pointage: `${dateKey}T${defaultStartTime}`,
        localisation: defaultLocation,
        notes: defaultNotes,
        justification: `Création de pointage pour ${pointage.isWeekend ? 'week-end' : pointage.isHoliday ? 'jour férié' : 'jour manquant'}`
      });
    } else {
      // Logique existante pour les pointages réels
      const dateTime = new Date(pointage.timestamp_pointage);
      
      // Convertir en heure locale pour l'affichage dans datetime-local
      const year = dateTime.getFullYear();
      const month = String(dateTime.getMonth() + 1).padStart(2, '0');
      const day = String(dateTime.getDate()).padStart(2, '0');
      const hours = String(dateTime.getHours()).padStart(2, '0');
      const minutes = String(dateTime.getMinutes()).padStart(2, '0');
      
      const localDateTimeString = `${year}-${month}-${day}T${hours}:${minutes}`;
      
      setCorrectionForm({
        type_pointage: pointage.type_pointage,
        timestamp_pointage: localDateTimeString,
        localisation: pointage.localisation || '',
        notes: pointage.notes || '',
        justification: ''
      });
    }
    
    setIsPointageDialogOpen(true);
  };

  const handleDemandeCorrection = async (pointageId: string, corrections: any) => {
    if (!profile?.id) return;

    try {
      // Vérifier si c'est un pointage virtuel
      const isVirtual = pointageId.startsWith('virtual-');
      
      if (isVirtual) {
        // Pour les pointages virtuels, créer de vrais pointages
        return await handleCreateRealPointageFromVirtual(corrections);
      }

      // Logique existante pour les pointages réels
      // Récupérer les données originales du pointage
  // Remplacement Supabase: récupérer le pointage via API Express
  const res = await fetch(`/api/pointages/${pointageId}`);
  if (!res.ok) throw new Error('Erreur lors de la récupération du pointage');
  const pointageData = await res.json();

      const donnees_originales = {
        type_pointage: pointageData.type_pointage,
        timestamp_pointage: pointageData.timestamp_pointage,
        localisation: pointageData.localisation,
        notes: pointageData.notes
      };

      // Convertir le timestamp du formulaire (datetime-local) en ISO string
      let correctedTimestamp = pointageData.timestamp_pointage;
      if (corrections.timestamp_pointage && corrections.timestamp_pointage !== pointageData.timestamp_pointage) {
        // Le datetime-local donne une date locale, on la convertit en ISO
        const localDate = new Date(corrections.timestamp_pointage);
        correctedTimestamp = localDate.toISOString();
      }

      const donnees_corrigees = {
        type_pointage: corrections.type_pointage || pointageData.type_pointage,
        timestamp_pointage: correctedTimestamp,
        localisation: corrections.localisation || pointageData.localisation,
        notes: corrections.notes || pointageData.notes,
        justification: corrections.justification
      };

      // Générer un titre descriptif pour la demande
      const datePointage = format(new Date(pointageData.timestamp_pointage), "dd/MM/yyyy à HH:mm");
      const typeOriginal = pointageData.type_pointage === 'entree' ? 'Entrée' : 
                          pointageData.type_pointage === 'sortie' ? 'Sortie' : 
                          pointageData.type_pointage === 'pause_debut' ? 'Début pause' : 'Fin pause';
      
      const typeCorrige = corrections.type_pointage ? 
                         (corrections.type_pointage === 'entree' ? 'Entrée' : 
                          corrections.type_pointage === 'sortie' ? 'Sortie' : 
                          corrections.type_pointage === 'pause_debut' ? 'Début pause' : 'Fin pause') : 
                         typeOriginal;

      let titre = `Correction pointage ${datePointage}`;
      
      if (corrections.type_pointage && corrections.type_pointage !== pointageData.type_pointage) {
        titre += ` - ${typeOriginal} vers ${typeCorrige}`;
      }
      
      if (corrections.timestamp_pointage && corrections.timestamp_pointage !== pointageData.timestamp_pointage) {
        const nouvelleHeure = format(new Date(corrections.timestamp_pointage), "HH:mm");
        titre += ` (nouvelle heure: ${nouvelleHeure})`;
      }

  // TODO: Remplacer par appel API Express ou mock
      const res = await fetch('/api/demandes_rh', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          demandeur_id: profile.id,
          type_demande: 'correction_pointage',
          titre,
          description: corrections.justification || 'Demande de correction',
          pointage_id: pointageId,
          donnees_originales,
          donnees_corrigees
        })
      });
      if (!res.ok) throw new Error('Erreur lors de la création de la demande de correction');

      toast({
        title: "Demande envoyée",
        description: "Votre demande de correction a été envoyée pour validation"
      });

      setIsPointageDialogOpen(false);
      loadData();
    } catch (error) {
      console.error('Error submitting correction request:', error);
      toast({
        title: "Erreur",
        description: "Impossible d'envoyer la demande de correction",
        variant: "destructive"
      });
    }
  };

  const handleDeleteDemande = async (demandeId: string) => {
    try {
  // TODO: Remplacer par appel API Express ou mock
      const res = await fetch(`/api/demandes_rh/${demandeId}`, {
        method: 'DELETE'
      });
      if (!res.ok) throw new Error('Erreur lors de la suppression de la demande');

      toast({
        title: "Succès",
        description: "Demande supprimée avec succès"
      });

      loadData();
    } catch (error) {
      console.error('Error deleting demande:', error);
      toast({
        title: "Erreur",
        description: "Impossible de supprimer la demande",
        variant: "destructive"
      });
    }
  };

  const handleImportPointages = async (importedPointages: any[]) => {
    if (!profile?.id) return;

    try {
      const pointagesToInsert = importedPointages.map(p => ({
        profile_id: profile.id,
        type_pointage: p.type,
        // Ajouter explicitement le fuseau horaire UTC+1 (Maroc) pour éviter la conversion automatique
        timestamp_pointage: `${p.date}T${p.heure}:00+01:00`,
        localisation: p.localisation || "Importé",
        notes: p.notes || "Pointage importé"
      }));

  // TODO: Remplacer par appel API Express ou mock
      const res = await fetch('/api/pointages/import', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pointages: pointagesToInsert })
      });
      if (!res.ok) throw new Error('Erreur lors de l\'import des pointages');

      toast({
        title: "Import réussi",
        description: `${importedPointages.length} pointages importés avec succès`
      });

      loadData(selectedYear, selectedMonth);
    } catch (error) {
      console.error('Error importing pointages:', error);
      toast({
        title: "Erreur d'import",
        description: "Impossible d'importer les pointages",
        variant: "destructive"
      });
    }
  };

  const resetFilters = () => {
    setSelectedYear("all");
    setSelectedMonth("all");
    setDateDebut(undefined);
    setDateFin(undefined);
    setHeuresCalculees(undefined);
    loadData();
  };

  const calculateTotalHours = (pointagesList: VirtualPointageRecord[]) => {
    // Grouper par jour et calculer les heures
    const dayGroups: { [key: string]: VirtualPointageRecord[] } = {};
    
    pointagesList.forEach(p => {
      const date = format(new Date(p.timestamp_pointage), "yyyy-MM-dd");
      if (!dayGroups[date]) dayGroups[date] = [];
      dayGroups[date].push(p);
    });

    let totalHours = 0;
    Object.values(dayGroups).forEach(dayPointages => {
      const sortedPointages = dayPointages.sort((a, b) => 
        new Date(a.timestamp_pointage).getTime() - new Date(b.timestamp_pointage).getTime()
      );
      
      let dayHours = 0;
      let lastEntree: Date | null = null;
      
      sortedPointages.forEach(p => {
        const timestamp = new Date(p.timestamp_pointage);
        if (p.type_pointage === 'entree') {
          lastEntree = timestamp;
        } else if (p.type_pointage === 'sortie' && lastEntree) {
          const diff = timestamp.getTime() - lastEntree.getTime();
          dayHours += diff / (1000 * 60 * 60); // Convert to hours
          lastEntree = null;
        }
      });
      
      totalHours += dayHours;
    });

    return totalHours;
  };

  const handleLeaveRequest = async () => {
    if (!profile?.id || !selectedDate || !selectedEndDate || !leaveType) {
      toast({
        title: "Erreur",
        description: "Veuillez remplir tous les champs obligatoires",
        variant: "destructive"
      });
      return;
    }

    if (selectedEndDate < selectedDate) {
      toast({
        title: "Erreur",
        description: "La date de fin doit être postérieure à la date de début",
        variant: "destructive"
      });
      return;
    }

    try {
  // TODO: Remplacer par appel API Express ou mock
      const res = await fetch('/api/demandes_rh', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          demandeur_id: profile.id,
          type_demande: 'conges',
          titre: `Demande de ${leaveType === 'cp' ? 'congés payés' : leaveType === 'rtt' ? 'RTT' : leaveType === 'recuperation' ? 'récupération' : 'congé sans solde'}`,
          description: leaveReason || 'Demande de congé',
          date_debut: selectedDate.toISOString().split('T')[0],
          date_fin: selectedEndDate.toISOString().split('T')[0]
        })
      });
      if (!res.ok) throw new Error('Erreur lors de la création de la demande de congé');

      toast({
        title: "Succès",
        description: "Demande de congé soumise avec succès"
      });

      // Reset form
      setSelectedDate(undefined);
      setSelectedEndDate(undefined);
      setLeaveType("");
      setLeaveReason("");
      setIsDemandeDialogOpen(false);
      loadData();
    } catch (error) {
      console.error('Error submitting leave request:', error);
      toast({
        title: "Erreur",
        description: "Impossible de soumettre la demande",
        variant: "destructive"
      });
    }
  };

  // Fonctions pour la sélection multiple des pointages
  const handleSelectPointage = (pointageId: string, checked: boolean) => {
    setSelectedPointages(prev => 
      checked 
        ? [...prev, pointageId]
        : prev.filter(id => id !== pointageId)
    );
  };

  const handleSelectAllPointages = (checked: boolean) => {
    setSelectedPointages(checked ? filteredPointages.map(p => p.id) : []);
  };

  // Analyser les types de pointages sélectionnés
  const getSelectedPointagesInfo = () => {
    const selectedVirtualPointages = filteredPointages.filter(p => 
      selectedPointages.includes(p.id) && isVirtualPointage(p)
    );
    const selectedRealPointages = filteredPointages.filter(p => 
      selectedPointages.includes(p.id) && !isVirtualPointage(p)
    );
    
    const weekendCount = selectedVirtualPointages.filter(p => p.isWeekend).length;
    const holidayCount = selectedVirtualPointages.filter(p => p.isHoliday).length;
    const absentCount = selectedVirtualPointages.filter(p => !p.isWeekend && !p.isHoliday).length;
    
    return {
      total: selectedPointages.length,
      real: selectedRealPointages.length,
      virtual: selectedVirtualPointages.length,
      weekend: weekendCount,
      holiday: holidayCount,
      absent: absentCount
    };
  };

  // Fonction pour créer un vrai pointage à partir d'un pointage virtuel
  const handleCreateRealPointageFromVirtual = async (corrections: any) => {
    if (!profile?.id) return;

    try {
      // Convertir le timestamp du formulaire (datetime-local) en ISO string
      const localDate = new Date(corrections.timestamp_pointage);
      const correctedTimestamp = localDate.toISOString();

      // Créer les pointages d'entrée et de sortie
      const dateKey = format(localDate, 'yyyy-MM-dd');
      
      // Créer pointage d'entrée
  // TODO: Remplacer par appel API Express ou mock
      const resEntree = await fetch('/api/pointages', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          profile_id: profile.id,
          type_pointage: 'entree',
          timestamp_pointage: correctedTimestamp,
          localisation: corrections.localisation || 'Bureau',
          notes: `${corrections.notes} - Créé depuis ${selectedPointage?.isWeekend ? 'week-end' : selectedPointage?.isHoliday ? 'jour férié' : 'jour absent'}`
        })
      });
      if (!resEntree.ok) throw new Error('Erreur lors de la création du pointage d\'entrée');

      // Créer pointage de sortie (8 heures plus tard par défaut)
      const exitTime = new Date(localDate);
      exitTime.setHours(exitTime.getHours() + 8);
      
  // TODO: Remplacer par appel API Express ou mock
      const resSortie = await fetch('/api/pointages', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          profile_id: profile.id,
          type_pointage: 'sortie',
          timestamp_pointage: exitTime.toISOString(),
          localisation: corrections.localisation || 'Bureau',
          notes: `${corrections.notes} - Créé depuis ${selectedPointage?.isWeekend ? 'week-end' : selectedPointage?.isHoliday ? 'jour férié' : 'jour absent'}`
        })
      });
      if (!resSortie.ok) throw new Error('Erreur lors de la création du pointage de sortie');

      toast({
        title: "Pointages créés",
        description: `Pointages d'entrée et de sortie créés pour le ${format(localDate, "dd/MM/yyyy", { locale: fr })}`,
      });

      // Recharger les données et fermer le dialog
      await loadData();
      setIsPointageDialogOpen(false);
      setCorrectionForm({
        type_pointage: '',
        timestamp_pointage: '',
        localisation: '',
        notes: '',
        justification: ''
      });

    } catch (error) {
      console.error('Erreur lors de la création des pointages:', error);
      toast({
        title: "Erreur",
        description: "Impossible de créer les pointages",
        variant: "destructive"
      });
    }
  };

  const selectedInfo = getSelectedPointagesInfo();

  // Fonction pour créer des pointages pour les jours sélectionnés
  const handleCreatePointagesForSelected = async () => {
    const selectedVirtualPointages = filteredPointages.filter(p => 
      selectedPointages.includes(p.id) && isVirtualPointage(p)
    );
    
    if (selectedVirtualPointages.length === 0) {
      toast({
        title: "Aucune sélection",
        description: "Veuillez sélectionner des week-ends ou jours fériés",
        variant: "destructive"
      });
      return;
    }

    try {
      // Créer des pointages automatiques pour les jours sélectionnés
      for (const virtualPointage of selectedVirtualPointages) {
        const date = format(new Date(virtualPointage.timestamp_pointage), 'yyyy-MM-dd');
        
        // Créer un pointage automatique avec 8 heures standard
  // TODO: Remplacer par appel API Express ou mock
          profile_id: profile!.id,
          date_pointage: date,
          horaire_debut: '09:00:00',
          horaire_fin: '17:00:00',
          heures_travaillees: 8,
          type_pointage: virtualPointage.isHoliday ? 'jour_ferie' : virtualPointage.isWeekend ? 'weekend' : 'rattrapage',
          motif: virtualPointage.notes || 'Créé automatiquement'
        });
      }

      toast({
        title: "Pointages créés",
        description: `${selectedVirtualPointages.length} pointage(s) automatique(s) créé(s)`,
      });

      // Recharger les données
      loadData();
      setSelectedPointages([]);
    } catch (error) {
      console.error('Erreur lors de la création des pointages:', error);
      toast({
        title: "Erreur",
        description: "Impossible de créer les pointages automatiques",
        variant: "destructive"
      });
    }
  };

  const handleDeleteSelectedPointages = async () => {
    if (selectedPointages.length === 0) return;

    // Filtrer uniquement les pointages réels (non virtuels) avec des UUIDs valides
    const realPointageIds = filteredPointages
      .filter(p => selectedPointages.includes(p.id) && !isVirtualPointage(p))
      .map(p => p.id)
      .filter(id => {
        // Vérifier que l'ID est un UUID valide
        const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
        return uuidRegex.test(id);
      });

    if (realPointageIds.length === 0) {
      toast({
        title: "Information",
        description: "Aucun pointage réel sélectionné à supprimer",
        variant: "default"
      });
      return;
    }

    setIsDeleting(true);
    
    try {
      // Remplacement Supabase: récupérer les demandes RH liées via API Express
      const res = await fetch(`/api/demandes_rh/linked_by_pointage_ids`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pointage_ids: realPointageIds })
      });
      if (!res.ok) throw new Error('Erreur lors de la récupération des demandes RH liées');
      const linkedDemandes = await res.json();

      if (linkedDemandes && linkedDemandes.length > 0) {
        const confirmed = confirm(
          `Attention : ${linkedDemandes.length} demande(s) RH sont liées à ces pointages. Voulez-vous les supprimer également ? Cette action est irréversible.`
        );

        if (!confirmed) {
          setIsDeleting(false);
          return;
        }

        // Supprimer d'abord les demandes RH liées
        // Remplacement Supabase: suppression des demandes RH liées via API Express
        await fetch(`/api/demandes_rh/delete_by_pointage_ids`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ pointage_ids: realPointageIds })
        });
      } else {
        const confirmed = confirm(
          `Êtes-vous sûr de vouloir supprimer ${realPointageIds.length} pointage(s) réel(s) sélectionné(s) ? Cette action est irréversible.`
        );

        if (!confirmed) {
          setIsDeleting(false);
          return;
        }
      }

      // Maintenant supprimer les pointages réels
      // Remplacement Supabase: suppression des pointages réels via API Express
      await fetch(`/api/pointages/delete_by_ids`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ids: realPointageIds })
      });

      toast({
        title: "Succès",
        description: `${realPointageIds.length} pointage(s) réel(s) supprimé(s) avec succès`,
      });

      setSelectedPointages([]);
      loadData();
    } catch (error) {
      console.error('Error deleting pointages:', error);
      toast({
        title: "Erreur",
        description: "Impossible de supprimer les pointages sélectionnés",
        variant: "destructive"
      });
    } finally {
      setIsDeleting(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Vue d'ensemble */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Heures cette semaine</p>
                <p className="text-2xl font-bold">{heures_semaine}h</p>
                <p className="text-sm text-muted-foreground">/ {heures_theoriques}h théoriques</p>
              </div>
              <Clock className="h-8 w-8 text-blue-600" />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Demandes en cours</p>
                <p className="text-2xl font-bold">{demandes.filter(d => d.statut === "en_cours").length}</p>
              </div>
              <FileText className="h-8 w-8 text-orange-600" />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Solde congés</p>
                <p className="text-2xl font-bold">22j</p>
                <p className="text-sm text-muted-foreground">restants</p>
              </div>
              <CalendarIcon className="h-8 w-8 text-green-600" />
            </div>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="pointage" className="space-y-4">
        <TabsList>
          <TabsTrigger value="pointage">Pointage</TabsTrigger>
          <TabsTrigger value="demandes">Mes Demandes</TabsTrigger>
          <TabsTrigger value="nouvelles">Nouvelles Demandes</TabsTrigger>
        </TabsList>

        <TabsContent value="pointage" className="space-y-4">
          {/* Filtres */}
          <PointageFilters
            selectedYear={selectedYear}
            selectedMonth={selectedMonth}
            dateDebut={dateDebut}
            dateFin={dateFin}
            onYearChange={setSelectedYear}
            onMonthChange={setSelectedMonth}
            onDateDebutChange={setDateDebut}
            onDateFinChange={setDateFin}
            onReset={resetFilters}
            availableYears={availableYears}
            totalPointages={filteredPointages.length}
            totalHeures={calculateTotalHours(filteredPointages)}
            heuresCalculees={heuresCalculees}
          />

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Clock className="h-5 w-5" />
                Pointage en Temps Réel
              </CardTitle>
              <CardDescription>
                Enregistrez vos heures d'arrivée et de départ
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex flex-col sm:flex-row gap-4 items-center justify-center p-8 bg-muted/50 rounded-lg">
                <div className="text-center">
                  <div className="text-3xl font-bold mb-2">
                    {new Date().toLocaleTimeString('fr-FR', { 
                      hour: '2-digit', 
                      minute: '2-digit',
                      second: '2-digit' 
                    })}
                  </div>
                  <div className="text-muted-foreground">
                    {new Date().toLocaleDateString('fr-FR', { 
                      weekday: 'long',
                      year: 'numeric',
                      month: 'long',
                      day: 'numeric'
                    })}
                  </div>
                </div>
                
                <div className="flex gap-2">
                  <Button
                    size="lg"
                    className="bg-green-600 hover:bg-green-700"
                    onClick={() => handlePointage("entree")}
                    disabled={isPointing}
                  >
                    {isPointing ? (
                      <PauseCircle className="h-5 w-5 mr-2" />
                    ) : (
                      <Play className="h-5 w-5 mr-2" />
                    )}
                    {isPointing ? "Pointage..." : "Pointer Entrée"}
                  </Button>
                  
                  <Button
                    size="lg"
                    variant="outline"
                    className="border-red-200 text-red-600 hover:bg-red-50"
                    onClick={() => handlePointage("sortie")}
                    disabled={isPointing}
                  >
                    {isPointing ? (
                      <PauseCircle className="h-5 w-5 mr-2" />
                    ) : (
                      <Pause className="h-5 w-5 mr-2" />
                    )}
                    {isPointing ? "Pointage..." : "Pointer Sortie"}
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>Historique des Pointages</CardTitle>
                  <CardDescription>
                    {selectedYear !== "all" || selectedMonth !== "all" 
                      ? "Pointages filtrés" 
                      : "Vos derniers pointages"
                    }
                  </CardDescription>
                </div>
                <div className="flex gap-2 flex-wrap">
                  {canDeletePointages && selectedPointages.length > 0 && (
                    <>
                      {selectedInfo.real > 0 && (
                        <Button
                          variant="destructive"
                          size="sm"
                          onClick={handleDeleteSelectedPointages}
                          disabled={isDeleting}
                        >
                          <Trash2 className="h-4 w-4 mr-2" />
                          {isDeleting ? "Suppression..." : `Supprimer (${selectedInfo.real})`}
                        </Button>
                      )}
                      
                      {selectedInfo.virtual > 0 && (
                        <Button
                          variant="secondary"
                          size="sm"
                          onClick={handleCreatePointagesForSelected}
                          className="bg-blue-100 text-blue-800 hover:bg-blue-200"
                        >
                          <Plus className="h-4 w-4 mr-2" />
                          Créer pointages ({selectedInfo.virtual})
                        </Button>
                      )}
                      
                      {selectedInfo.weekend > 0 && (
                        <Badge variant="outline" className="px-2 py-1 bg-gray-100 text-gray-700">
                          {selectedInfo.weekend} week-end{selectedInfo.weekend > 1 ? 's' : ''}
                        </Badge>
                      )}
                      
                      {selectedInfo.holiday > 0 && (
                        <Badge variant="outline" className="px-2 py-1 bg-yellow-100 text-yellow-700">
                          {selectedInfo.holiday} jour{selectedInfo.holiday > 1 ? 's' : ''} férié{selectedInfo.holiday > 1 ? 's' : ''}
                        </Badge>
                      )}
                    </>
                  )}
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setIsImportModalOpen(true)}
                  >
                    <Upload className="h-4 w-4 mr-2" />
                    Importer
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setIsExportModalOpen(true)}
                    disabled={filteredPointages.length === 0}
                  >
                    <Download className="h-4 w-4 mr-2" />
                    Exporter
                  </Button>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    {canDeletePointages && (
                      <TableHead className="w-[50px]">
                        <Checkbox
                          checked={selectedPointages.length === filteredPointages.length && filteredPointages.length > 0}
                          onCheckedChange={handleSelectAllPointages}
                          aria-label="Sélectionner tout"
                        />
                      </TableHead>
                    )}
                     <TableHead>Date</TableHead>
                     <TableHead>Type</TableHead>
                     <TableHead>Heure</TableHead>
                     <TableHead>Heure configurée</TableHead>
                     <TableHead>Écart</TableHead>
                     <TableHead>Pause Rém.</TableHead>
                     <TableHead>Pause Non Rém.</TableHead>
                     <TableHead>Heures réelles</TableHead>
                     <TableHead>Localisation</TableHead>
                     <TableHead>Notes</TableHead>
                     <TableHead>Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                   {filteredPointages.length === 0 ? (
                     <TableRow>
                       <TableCell colSpan={canDeletePointages ? 11 : 10} className="text-center py-8 text-muted-foreground">
                        {pointages.length === 0 ? "Aucun pointage enregistré" : "Aucun pointage trouvé pour les filtres sélectionnés"}
                      </TableCell>
                    </TableRow>
                  ) : (
                    filteredPointages.map((pointage) => {
                      const getRowClassName = () => {
                        if (!isVirtualPointage(pointage)) return "";
                        
                        if (pointage.isHoliday) {
                          return "bg-yellow-50 border-l-4 border-yellow-400 text-gray-700";
                        }
                        if (pointage.isWeekend) {
                          return "bg-gray-50 border-l-4 border-gray-400 text-gray-600";
                        }
                        return "bg-gray-50 text-gray-500";
                      };

                      return (
                      <TableRow 
                        key={pointage.id} 
                        className={getRowClassName()}
                      >
                        {canDeletePointages && (
                          <TableCell>
                            <Checkbox
                              checked={selectedPointages.includes(pointage.id)}
                              onCheckedChange={(checked) => handleSelectPointage(pointage.id, checked as boolean)}
                              aria-label={`Sélectionner ${isVirtualPointage(pointage) ? 
                                (pointage.isHoliday ? 'jour férié' : pointage.isWeekend ? 'week-end' : 'absence') 
                                : 'pointage'} du ${format(new Date(pointage.timestamp_pointage), "dd/MM/yyyy", { locale: fr })}`}
                              className={isVirtualPointage(pointage) ? 
                                (pointage.isHoliday ? 'accent-yellow-500' : pointage.isWeekend ? 'accent-gray-500' : '') 
                                : ''}
                            />
                          </TableCell>
                        )}
                        <TableCell>
                          {format(new Date(pointage.timestamp_pointage), "dd/MM/yyyy", { locale: fr })}
                        </TableCell>
                        <TableCell>
                          {isVirtualPointage(pointage) ? (
                            // Badge pour jours fériés (jaune)
                            pointage.isHoliday ? (
                              pointage.type_pointage === "entree" ? (
                                <Badge className="bg-yellow-100 text-yellow-800 border-yellow-300">
                                  🟡 Férié - Entrée
                                </Badge>
                              ) : (
                                <Badge className="bg-yellow-100 text-yellow-800 border-yellow-300">
                                  🟡 Férié - Sortie
                                </Badge>
                              )
                            // Badge pour week-ends (gris)
                            ) : pointage.isWeekend ? (
                              pointage.type_pointage === "entree" ? (
                                <Badge className="bg-gray-100 text-gray-600 border-gray-300">
                                  ⚫ Week-end - Entrée
                                </Badge>
                              ) : (
                                <Badge className="bg-gray-100 text-gray-600 border-gray-300">
                                  ⚫ Week-end - Sortie
                                </Badge>
                              )
                            // Badge pour autres absences
                            ) : pointage.type_pointage === "entree" ? (
                              <Badge className="bg-gray-100 text-gray-600 border-gray-300">
                                ⚫ Absent - Entrée
                              </Badge>
                            ) : (
                              <Badge className="bg-gray-100 text-gray-600 border-gray-300">
                                ⚫ Absent - Sortie
                              </Badge>
                            )
                          ) : pointage.type_pointage === "entree" ? (
                            <Badge className="bg-green-100 text-green-800 border-green-300">
                              🟢 Entrée
                            </Badge>
                          ) : pointage.type_pointage === "sortie" ? (
                            <Badge className="bg-red-100 text-red-800 border-red-300">
                              🔴 Sortie
                            </Badge>
                          ) : pointage.type_pointage === "pause_debut" ? (
                            <Badge className="bg-blue-100 text-blue-800 border-blue-300">
                              🔵 Début pause
                            </Badge>
                          ) : (
                            <Badge className="bg-blue-100 text-blue-800 border-blue-300">
                              🔵 Fin pause
                            </Badge>
                          )}
                        </TableCell>
                          <TableCell>
                            {isVirtualPointage(pointage) ? (
                              (() => {
                                if (pointage.isHoliday) {
                                  const currentDate = pointage.timestamp_pointage.split('T')[0];
                                  const dayKey = getDayKey(currentDate);
                                  const horaireJour = horaireActif?.horaires_semaine?.[dayKey];
                                  
                                  if (horaireJour && horaireJour.heureDebut && horaireJour.heureFin) {
                                    const configuredHour = pointage.type_pointage === "entree" 
                                      ? horaireJour.heureDebut 
                                      : horaireJour.heureFin;
                                    return <span className="text-yellow-600">{configuredHour}:00</span>;
                                  }
                                }
                                return "00:00:00";
                              })()
                            ) : (
                              format(new Date(pointage.timestamp_pointage), "HH:mm:ss", { locale: fr })
                            )}
                           </TableCell>
                           <TableCell>
                             {isVirtualPointage(pointage) ? (
                               (() => {
                                 const currentDate = pointage.timestamp_pointage.split('T')[0];
                                 const dayKey = getDayKey(currentDate);
                                 const horaireJour = horaireActif?.horaires_semaine?.[dayKey];
                                 
                                 if (!horaireJour || !horaireJour.heureDebut || !horaireJour.heureFin) {
                                   return <span className="text-gray-500">-</span>;
                                 }
                                 
                                 // Pour les jours fériés, afficher selon le type de pointage
                                 if (pointage.isHoliday) {
                                   const configuredHour = pointage.type_pointage === "entree" 
                                     ? horaireJour.heureDebut 
                                     : horaireJour.heureFin;
                                   return <span className="text-yellow-600">{configuredHour}</span>;
                                 }
                                 
                                 // Pour les autres (week-end, absent), garder la logique actuelle
                                 const configuredHour = pointage.type_pointage === "entree" 
                                   ? horaireJour.heureDebut 
                                   : horaireJour.heureFin;
                                 
                                 return <span className="text-gray-500">{configuredHour}</span>;
                               })()
                             ) : (
                               <ConfiguredHourCell
                                 pointage={pointage as PointageRecord}
                                 horaireActif={horaireActif}
                               />
                             )}
                           </TableCell>
                           <TableCell>
                             {isVirtualPointage(pointage) ? (
                               <span className="text-gray-500">-</span>
                             ) : (pointage.type_pointage !== "entree" && pointage.type_pointage !== "sortie") ? (
                               <span className="text-gray-500">-</span>
                             ) : (
                               (() => {
                                 const currentDate = pointage.timestamp_pointage.split('T')[0];
                                 const dayKey = getDayKey(currentDate);
                                 const horaireJour = horaireActif?.horaires_semaine?.[dayKey];
                                 
                                 if (!horaireJour || !horaireJour.heureDebut || !horaireJour.heureFin) {
                                   return <span className="text-gray-500">-</span>;
                                 }
                                 
                                 const configuredHour = pointage.type_pointage === "entree" 
                                   ? horaireJour.heureDebut 
                                   : horaireJour.heureFin;
                                 
                                 const pointageTime = format(new Date(pointage.timestamp_pointage), "HH:mm");
                                 const [configHour, configMin] = configuredHour.split(':').map(Number);
                                 const [pointageHour, pointageMin] = pointageTime.split(':').map(Number);
                                 
                                 const configMinutes = configHour * 60 + configMin;
                                 const pointageMinutes = pointageHour * 60 + pointageMin;
                                 
                                 let ecartMinutes;
                                 if (pointage.type_pointage === "entree") {
                                   ecartMinutes = configMinutes - pointageMinutes; // Entrée: positif = avance, négatif = retard
                                 } else {
                                   ecartMinutes = pointageMinutes - configMinutes; // Sortie: positif = après, négatif = avant
                                 }
                                 
                                 if (ecartMinutes === 0) {
                                   return <span className="text-green-600 font-medium">0</span>;
                                 } else if (ecartMinutes > 0) {
                                   const hours = Math.floor(ecartMinutes / 60);
                                   const mins = ecartMinutes % 60;
                                   return <span className="text-blue-600 font-medium">+{hours > 0 ? `${hours}h` : ''}${mins > 0 ? `${mins}min` : hours === 0 ? `${mins}min` : ''}</span>;
                                 } else {
                                   const absEcart = Math.abs(ecartMinutes);
                                   const hours = Math.floor(absEcart / 60);
                                   const mins = absEcart % 60;
                                   return <span className="text-red-600 font-medium">-{hours > 0 ? `${hours}h` : ''}${mins > 0 ? `${mins}min` : hours === 0 ? `${mins}min` : ''}</span>;
                                 }
                               })()
                             )}
                            </TableCell>
                            <TableCell>
                              {isVirtualPointage(pointage) ? (
                                <span className="text-gray-500">-</span>
                              ) : (
                                (() => {
                                  const currentDate = pointage.timestamp_pointage.split('T')[0];
                                  const dayKey = getDayKey(currentDate);
                                  const horaireJour = horaireActif?.horaires_semaine?.[dayKey];
                                  
                                  if (horaireJour && horaireJour.pauses && horaireJour.pauses.length > 0) {
                                    const pauseRem = horaireJour.pauses
                                      .filter(pause => pause.remuneree)
                                      .reduce((total, pause) => {
                                        const [startHour, startMin] = pause.heureDebut.split(':').map(Number);
                                        const [endHour, endMin] = pause.heureFin.split(':').map(Number);
                                        const pauseMinutes = (endHour * 60 + endMin) - (startHour * 60 + startMin);
                                        return total + pauseMinutes;
                                      }, 0);
                                    
                                    return <span className="text-green-600 font-medium">{pauseRem}min</span>;
                                  }
                                  return <span className="text-gray-500">0min</span>;
                                })()
                              )}
                            </TableCell>
                            <TableCell>
                              {isVirtualPointage(pointage) ? (
                                <span className="text-gray-500">-</span>
                              ) : (
                                (() => {
                                  const currentDate = pointage.timestamp_pointage.split('T')[0];
                                  const dayKey = getDayKey(currentDate);
                                  const horaireJour = horaireActif?.horaires_semaine?.[dayKey];
                                  
                                  if (horaireJour && horaireJour.pauses && horaireJour.pauses.length > 0) {
                                    const pauseNonRem = horaireJour.pauses
                                      .filter(pause => !pause.remuneree)
                                      .reduce((total, pause) => {
                                        const [startHour, startMin] = pause.heureDebut.split(':').map(Number);
                                        const [endHour, endMin] = pause.heureFin.split(':').map(Number);
                                        const pauseMinutes = (endHour * 60 + endMin) - (startHour * 60 + startMin);
                                        return total + pauseMinutes;
                                      }, 0);
                                    
                                    return <span className="text-blue-600 font-medium">{pauseNonRem}min</span>;
                                  }
                                  return <span className="text-gray-500">0min</span>;
                                })()
                              )}
                            </TableCell>
                               <TableCell>
                                {isVirtualPointage(pointage) ? (
                                 (() => {
                                   if (pointage.isHoliday) {
                                     const currentDate = pointage.timestamp_pointage.split('T')[0];
                                     const dayKey = getDayKey(currentDate);
                                     const horaireJour = horaireActif?.horaires_semaine?.[dayKey];
                                     
                                     if (horaireJour && horaireJour.heureDebut && horaireJour.heureFin) {
                                       const [startHour, startMin] = horaireJour.heureDebut.split(':').map(Number);
                                       const [endHour, endMin] = horaireJour.heureFin.split(':').map(Number);
                                       
                                       const startMinutes = startHour * 60 + startMin;
                                       const endMinutes = endHour * 60 + endMin;
                                       const totalMinutes = endMinutes - startMinutes;
                                       // Soustraire 1 heure de pause non rémunérée (60 minutes)
                                       const pauseMinutes = 60;
                                       const hoursWorked = (totalMinutes - pauseMinutes) / 60;
                                       
                                       return <span className="text-yellow-600 font-medium">{hoursWorked.toFixed(2)}h</span>;
                                     }
                                   }
                                   return <span className="text-gray-500">0.00h</span>;
                                 })()
                               ) : (
                                 <PointageHoursCell
                                   pointage={pointage as PointageRecord}
                                   allPointages={filteredPointages.filter(p => !isVirtualPointage(p)) as PointageRecord[]}
                                   horaireActif={horaireActif}
                                   demandesHeuresSup={demandesHeuresSup}
                                 />
                               )}
                             </TableCell>
                         <TableCell>{pointage.localisation || "-"}</TableCell>
                         <TableCell>
                           {pointage.notes || "-"}
                           {!isVirtualPointage(pointage) && (pointage.type_pointage === "entree" || pointage.type_pointage === "sortie") && (() => {
                             const currentDate = pointage.timestamp_pointage.split('T')[0];
                             const dayKey = getDayKey(currentDate);
                             const horaireJour = horaireActif?.horaires_semaine?.[dayKey];
                             
                             if (horaireJour && horaireJour.heureDebut && horaireJour.heureFin) {
                               const configuredHour = pointage.type_pointage === "entree" 
                                 ? horaireJour.heureDebut 
                                 : horaireJour.heureFin;
                               const pointageTime = format(new Date(pointage.timestamp_pointage), "HH:mm");
                               const [configHour, configMin] = configuredHour.split(':').map(Number);
                               const [pointageHour, pointageMin] = pointageTime.split(':').map(Number);
                               
                               const configMinutes = configHour * 60 + configMin;
                               const pointageMinutes = pointageHour * 60 + pointageMin;
                               
                               let ecartMinutes;
                               let message;
                               if (pointage.type_pointage === "entree") {
                                 ecartMinutes = configMinutes - pointageMinutes;
                                 message = "Arrivée en retard";
                               } else {
                                 ecartMinutes = pointageMinutes - configMinutes;
                                 message = "Sortie avant l'heure";
                               }
                               
                               if (ecartMinutes < 0) {
                                 return (
                                   <div className="mt-1">
                                     <span className="text-red-600 text-xs font-medium bg-red-50 px-2 py-1 rounded">
                                       {message}
                                     </span>
                                   </div>
                                 );
                               }
                             }
                             return null;
                           })()}
                         </TableCell>
                        <TableCell>
                           <CorrectionStatusButton 
                             pointageId={pointage.id}
                             onOpenDialog={() => openCorrectionDialog(pointage)}
                             isVirtual={isVirtualPointage(pointage)}
                             virtualType={isVirtualPointage(pointage) ? 
                               (pointage.isHoliday ? 'holiday' : pointage.isWeekend ? 'weekend' : 'absent') 
                               : undefined}
                           />
                           <Dialog open={isPointageDialogOpen} onOpenChange={setIsPointageDialogOpen}>
                             <DialogContent className="max-w-md">
                               <DialogHeader>
                                  <DialogTitle>
                                    {selectedPointage && isVirtualPointage(selectedPointage) 
                                      ? "Créer Pointage" 
                                      : "Correction de Pointage"}
                                  </DialogTitle>
                                  <DialogDescription>
                                    {selectedPointage && (
                                      isVirtualPointage(selectedPointage) ? (
                                        <>Créer des pointages pour le {format(new Date(selectedPointage.timestamp_pointage), "dd/MM/yyyy", { locale: fr })} - {selectedPointage.isWeekend ? 'Week-end' : selectedPointage.isHoliday ? 'Jour férié' : 'Jour absent'}</>
                                      ) : (
                                        <>Corriger le pointage {selectedPointage.type_pointage} du {format(new Date(selectedPointage.timestamp_pointage), "dd/MM/yyyy 'à' HH:mm", { locale: fr })}</>
                                      )
                                    )}
                                  </DialogDescription>
                               </DialogHeader>
                               <div className="space-y-4">
                                 <div>
                                   <Label htmlFor="type_correction">Type de pointage</Label>
                                   <Select 
                                     value={correctionForm.type_pointage} 
                                     onValueChange={(value) => setCorrectionForm(prev => ({ ...prev, type_pointage: value }))}
                                   >
                                     <SelectTrigger>
                                       <SelectValue />
                                     </SelectTrigger>
                                     <SelectContent>
                                       <SelectItem value="entree">Entrée</SelectItem>
                                       <SelectItem value="sortie">Sortie</SelectItem>
                                       <SelectItem value="pause_debut">Début pause</SelectItem>
                                       <SelectItem value="pause_fin">Fin pause</SelectItem>
                                     </SelectContent>
                                   </Select>
                                 </div>
                                 
                                 <div>
                                   <Label htmlFor="datetime_correction">Date et heure</Label>
                                   <Input 
                                     id="datetime_correction"
                                     type="datetime-local" 
                                     value={correctionForm.timestamp_pointage}
                                     onChange={(e) => setCorrectionForm(prev => ({ ...prev, timestamp_pointage: e.target.value }))}
                                   />
                                 </div>
                                 
                                 <div>
                                   <Label htmlFor="localisation_correction">Localisation</Label>
                                   <Input 
                                     id="localisation_correction"
                                     value={correctionForm.localisation}
                                     onChange={(e) => setCorrectionForm(prev => ({ ...prev, localisation: e.target.value }))}
                                     placeholder="Lieu du pointage"
                                   />
                                 </div>
                                 
                                 <div>
                                   <Label htmlFor="notes_correction">Notes</Label>
                                   <Input 
                                     id="notes_correction"
                                     value={correctionForm.notes}
                                     onChange={(e) => setCorrectionForm(prev => ({ ...prev, notes: e.target.value }))}
                                     placeholder="Notes complémentaires"
                                   />
                                 </div>
                                 
                                 <div>
                                   <Label htmlFor="justification">Justification *</Label>
                                   <Textarea 
                                     id="justification" 
                                     value={correctionForm.justification}
                                     onChange={(e) => setCorrectionForm(prev => ({ ...prev, justification: e.target.value }))}
                                     placeholder="Expliquez la raison de la correction" 
                                     required
                                   />
                                 </div>
                               </div>
                               <DialogFooter>
                                 <Button variant="outline" onClick={() => setIsPointageDialogOpen(false)}>
                                   Annuler
                                 </Button>
                                 <Button 
                                   onClick={() => {
                                     if (!correctionForm.justification.trim()) {
                                       toast({
                                         title: "Erreur",
                                         description: "La justification est obligatoire",
                                         variant: "destructive"
                                       });
                                       return;
                                     }
                                     
                                     handleDemandeCorrection(selectedPointage?.id || '', {
                                       type_pointage: correctionForm.type_pointage,
                                       timestamp_pointage: correctionForm.timestamp_pointage,
                                       localisation: correctionForm.localisation,
                                       notes: correctionForm.notes,
                                       justification: correctionForm.justification
                                     });
                                   }}
                                   disabled={!correctionForm.justification.trim()}
                                 >
                                    {selectedPointage && isVirtualPointage(selectedPointage) 
                                      ? "Créer les pointages" 
                                      : "Demander la correction"}
                                 </Button>
                               </DialogFooter>
                             </DialogContent>
                          </Dialog>
                        </TableCell>
                      </TableRow>
                      );
                    })
                   )}
                 </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="demandes" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Suivi de mes Demandes</CardTitle>
              <CardDescription>Statut de vos demandes RH en cours avec possibilité de gestion</CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Type</TableHead>
                    <TableHead>Titre</TableHead>
                    <TableHead>Date demande</TableHead>
                    <TableHead>Statut</TableHead>
                    <TableHead>Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {demandes.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={5} className="text-center py-8 text-muted-foreground">
                        Aucune demande trouvée
                      </TableCell>
                    </TableRow>
                  ) : (
                    demandes.map((demande) => (
                      <TableRow key={demande.id}>
                        <TableCell>
                          <Badge variant="outline">
                            {getTypeLabel(demande.type_demande)}
                          </Badge>
                        </TableCell>
                        <TableCell className="font-medium">{demande.titre}</TableCell>
                        <TableCell>
                          {format(new Date(demande.created_at), "dd MMM yyyy", { locale: fr })}
                        </TableCell>
                        <TableCell>
                          <Badge className={getStatusColor(demande.statut)}>
                            {getStatusLabel(demande.statut)}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <div className="flex gap-2">
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => {
                                setSelectedDemandeDetail(demande);
                                setIsDemandeDetailOpen(true);
                              }}
                            >
                              <Eye className="h-4 w-4 mr-1" />
                              Voir détails
                            </Button>
                            {demande.statut === 'en_attente' && (
                              <Button
                                variant="destructive"
                                size="sm"
                                onClick={() => handleDeleteDemande(demande.id)}
                              >
                                <Trash2 className="h-4 w-4 mr-1" />
                                Supprimer
                              </Button>
                            )}
                          </div>
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="nouvelles" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <Dialog open={isDemandeDialogOpen} onOpenChange={setIsDemandeDialogOpen}>
              <DialogTrigger asChild>
                <Card className="cursor-pointer hover:shadow-md transition-shadow">
                  <CardContent className="p-6 text-center">
                    <CalendarIcon className="h-12 w-12 mx-auto mb-4 text-blue-600" />
                    <h3 className="font-semibold mb-2">Demande de Congé</h3>
                    <p className="text-sm text-muted-foreground">Congés payés, RTT, récupération</p>
                  </CardContent>
                </Card>
              </DialogTrigger>
              <DialogContent className="sm:max-w-lg">
                <DialogHeader>
                  <DialogTitle>Nouvelle Demande de Congé</DialogTitle>
                  <DialogDescription>
                    Formulaire de demande de congés
                  </DialogDescription>
                </DialogHeader>
                <div className="space-y-4">
                  <div>
                    <Label>Type de congé</Label>
                    <Select value={leaveType} onValueChange={setLeaveType}>
                      <SelectTrigger>
                        <SelectValue placeholder="Sélectionner le type" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="cp">Congés payés</SelectItem>
                        <SelectItem value="rtt">RTT</SelectItem>
                        <SelectItem value="recuperation">Récupération</SelectItem>
                        <SelectItem value="sans-solde">Sans solde</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <Label>Date de début</Label>
                      <Popover>
                        <PopoverTrigger asChild>
                          <Button
                            variant={"outline"}
                            className={cn(
                              "w-full justify-start text-left font-normal",
                              !selectedDate && "text-muted-foreground"
                            )}
                          >
                            <CalendarIcon className="mr-2 h-4 w-4" />
                            {selectedDate ? format(selectedDate, "dd/MM/yyyy", { locale: fr }) : "Sélectionner"}
                          </Button>
                        </PopoverTrigger>
                        <PopoverContent className="w-auto p-0">
                          <Calendar
                            mode="single"
                            selected={selectedDate}
                            onSelect={(date) => {
                              setSelectedDate(date);
                            }}
                            initialFocus
                            className={cn("p-3 pointer-events-auto")}
                          />
                          <div className="p-3 border-t">
                            <Button 
                              onClick={() => {
                                setSelectedDate(selectedDate);
                              }}
                              className="w-full"
                              size="sm"
                            >
                              OK
                            </Button>
                          </div>
                        </PopoverContent>
                      </Popover>
                    </div>
                    
                    <div>
                      <Label>Date de fin</Label>
                      <Popover>
                        <PopoverTrigger asChild>
                          <Button
                            variant={"outline"}
                            className={cn(
                              "w-full justify-start text-left font-normal",
                              !selectedEndDate && "text-muted-foreground"
                            )}
                          >
                            <CalendarIcon className="mr-2 h-4 w-4" />
                            {selectedEndDate ? format(selectedEndDate, "dd/MM/yyyy", { locale: fr }) : "Sélectionner"}
                          </Button>
                        </PopoverTrigger>
                        <PopoverContent className="w-auto p-0">
                          <Calendar
                            mode="single"
                            selected={selectedEndDate}
                            onSelect={(date) => {
                              setSelectedEndDate(date);
                            }}
                            disabled={(date) => selectedDate ? date < selectedDate : false}
                            initialFocus
                            className={cn("p-3 pointer-events-auto")}
                          />
                          <div className="p-3 border-t">
                            <Button 
                              onClick={() => {
                                setSelectedEndDate(selectedEndDate);
                              }}
                              className="w-full"
                              size="sm"
                            >
                              OK
                            </Button>
                          </div>
                        </PopoverContent>
                      </Popover>
                    </div>
                  </div>
                  
                  <div>
                    <Label htmlFor="motif">Motif (optionnel)</Label>
                    <Textarea 
                      id="motif" 
                      value={leaveReason}
                      onChange={(e) => setLeaveReason(e.target.value)}
                      placeholder="Précisez le motif de votre demande" 
                    />
                  </div>
                </div>
                <DialogFooter>
                  <Button variant="outline" onClick={() => setIsDemandeDialogOpen(false)}>
                    Annuler
                  </Button>
                  <Button onClick={handleLeaveRequest} disabled={!selectedDate || !selectedEndDate || !leaveType}>
                    Soumettre la demande
                  </Button>
                </DialogFooter>
              </DialogContent>
            </Dialog>

            <Card className="cursor-pointer hover:shadow-md transition-shadow">
              <CardContent className="p-6 text-center">
                <FileText className="h-12 w-12 mx-auto mb-4 text-green-600" />
                <h3 className="font-semibold mb-2">Demande de Formation</h3>
                <p className="text-sm text-muted-foreground">Formation professionnelle, séminaire</p>
              </CardContent>
            </Card>

            <Card className="cursor-pointer hover:shadow-md transition-shadow">
              <CardContent className="p-6 text-center">
                <User className="h-12 w-12 mx-auto mb-4 text-purple-600" />
                <h3 className="font-semibold mb-2">Demande Matériel</h3>
                <p className="text-sm text-muted-foreground">Équipement, fournitures</p>
              </CardContent>
            </Card>

            <Card className="cursor-pointer hover:shadow-md transition-shadow">
              <CardContent className="p-6 text-center">
                <Plus className="h-12 w-12 mx-auto mb-4 text-orange-600" />
                <h3 className="font-semibold mb-2">Autre Demande</h3>
                <p className="text-sm text-muted-foreground">Demande personnalisée</p>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
      
      {/* Modal de détails des demandes */}
      <ImprovedDemandeDetailModal
        demande={selectedDemandeDetail}
        open={isDemandeDetailOpen}
        onOpenChange={setIsDemandeDetailOpen}
        onDelete={handleDeleteDemande}
        showDeleteButton={true}
      />
      
      {/* Modals pour import/export */}
      <PointageImportModal
        isOpen={isImportModalOpen}
        onClose={() => setIsImportModalOpen(false)}
        onImport={handleImportPointages}
        profileId={profile?.id || ''}
      />

      <PointageExportModal
        isOpen={isExportModalOpen}
        onClose={() => setIsExportModalOpen(false)}
        pointages={filteredPointages}
        selectedYear={selectedYear}
        selectedMonth={selectedMonth}
      />
    </div>
  );
}