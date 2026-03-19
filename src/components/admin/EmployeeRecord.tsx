import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { supabase } from '@/integrations/supabase/client';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { ArrowLeft, Upload, Plus, Trash2, Edit, Eye, X, FileText, Download } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { Badge } from '@/components/ui/badge';
import { useNavigation } from '@/contexts/NavigationContext';
import { Breadcrumbs } from '@/components/Breadcrumbs';
import DocumentList from './DocumentList';
import { UserVilleAssignment } from './UserVilleAssignment';
import { UserCentreAssignment } from './UserCentreAssignment';
import { UserFormationAssignment } from './UserFormationAssignment';
import { EmployeePayrollSettings } from './EmployeePayrollSettings';

interface Profile {
  id: string;
  nom: string;
  prenom: string;
  email: string; // Email professionnel / de connexion
  poste?: string;
  photo_url?: string;
  date_naissance?: string;
  adresse_complete?: string;
  telephone_personnel?: string;
  email_personnel?: string; // Email personnel distinct
  cin_numero?: string;
  cin_scan_url?: string;
  cnss_numero?: string;
  cnss_scan_url?: string;
  rib_numero?: string;
  rib_scan_url?: string;
  type_contrat?: string;
  date_debut_contrat?: string;
  date_fin_contrat?: string;
  contrat_scan_url?: string;
  solde_conges_payes?: number;
  chef_hierarchique_id?: string;
  user_id?: string; // Pour la connexion avec auth.users
  salaire_horaire?: number;
}

interface ContractType {
  id: string;
  nom: string;
  is_active: boolean;
}

interface EmployeeDocument {
  id: string;
  profile_id: string;
  type_document: string;
  document_url: string;
  document_name: string;
  uploaded_at: string;
  description?: string;
}

interface AbsenceRetard {
  id: string;
  date_absence: string;
  type_absence: string;
  duree_heures: number;
  duree_jours: number;
  justificatif?: string;
  document_url?: string;
}

interface ActionDisciplinaire {
  id: string;
  date_action: string;
  type_action: string;
  motif: string;
  document_url?: string;
  created_by?: string;
}

const EmployeeRecord = () => {
  const { id } = useParams<{ id: string }>();
  const { goBack, setBreadcrumbs } = useNavigation();
  const { toast } = useToast();
  
  const [profile, setProfile] = useState<Profile | null>(null);
  const [contractTypes, setContractTypes] = useState<ContractType[]>([]);
  const [contractDocuments, setContractDocuments] = useState<EmployeeDocument[]>([]);
  const [disciplinaryDocuments, setDisciplinaryDocuments] = useState<EmployeeDocument[]>([]);
  const [absences, setAbsences] = useState<AbsenceRetard[]>([]);
  const [actions, setActions] = useState<ActionDisciplinaire[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('personal');
  
  // États pour les modales
  const [showAbsenceModal, setShowAbsenceModal] = useState(false);
  const [showActionModal, setShowActionModal] = useState(false);
  const [showContractTypeModal, setShowContractTypeModal] = useState(false);
  const [editingAbsence, setEditingAbsence] = useState<AbsenceRetard | null>(null);
  const [editingAction, setEditingAction] = useState<ActionDisciplinaire | null>(null);

  // États pour les formulaires
  const [profileForm, setProfileForm] = useState<Partial<Profile>>({});
  const [absenceForm, setAbsenceForm] = useState({
    date_absence: '',
    type_absence: '',
    duree_heures: 0,
    duree_jours: 0,
    justificatif: ''
  });
  const [actionForm, setActionForm] = useState({
    date_action: '',
    type_action: '',
    motif: ''
  });
  const [newContractType, setNewContractType] = useState('');

  // États pour les uploads
  const [uploading, setUploading] = useState(false);
  const [selectedActionDocuments, setSelectedActionDocuments] = useState<File[]>([]);
  const [selectedContractDocuments, setSelectedContractDocuments] = useState<File[]>([]);

  useEffect(() => {
    if (id) {
      fetchEmployeeData();
      fetchContractTypes();
    }
  }, [id]);

  useEffect(() => {
    if (profile) {
      setBreadcrumbs([
        { label: 'Administration', path: '/administration' },
        { label: `Fiche Employé - ${profile.nom}`, path: `/administration/employee/${id}` }
      ]);
    }
  }, [profile, id, setBreadcrumbs]);

  const fetchEmployeeData = async () => {
    try {
      // Récupérer le profil
      const { data: profileData, error: profileError } = await supabase
        .from('profiles')
        .select('*')
        .eq('id', id)
        .single();

      if (profileError) throw profileError;
      
      if (profileData) {
        // Régénérer les URLs signées pour tous les documents
        const updatedProfile = { ...profileData };
        const documentFields = ['photo_url', 'cin_scan_url', 'cnss_scan_url', 'rib_scan_url', 'contrat_scan_url'];
        
        for (const field of documentFields) {
          if (updatedProfile[field] && updatedProfile[field].includes('employee-documents')) {
            try {
              // Extraire le chemin du fichier
              let filePath = updatedProfile[field];
              
              // Si c'est une URL publique, extraire le chemin
              if (filePath.includes('/object/public/employee-documents/')) {
                filePath = filePath.split('/object/public/employee-documents/')[1];
              } 
              // Si c'est déjà une URL signée, extraire le chemin
              else if (filePath.includes('/object/sign/employee-documents/')) {
                filePath = filePath.split('/object/sign/employee-documents/')[1].split('?')[0];
              }
              
              // Générer une nouvelle URL signée
              const { data: signedUrlData, error: urlError } = await supabase.storage
                .from('employee-documents')
                .createSignedUrl(filePath, 3600 * 24 * 7); // 7 jours
              
              if (!urlError && signedUrlData) {
                updatedProfile[field] = signedUrlData.signedUrl;
              }
            } catch (error) {
              console.warn(`Erreur régénération URL pour ${field}:`, error);
            }
          }
        }
        
        setProfile(updatedProfile);
        setProfileForm(updatedProfile);
      }

      // Récupérer les absences
      const { data: absencesData, error: absencesError } = await supabase
        .from('absences_retards')
        .select('*')
        .eq('profile_id', id)
        .order('date_absence', { ascending: false });

      if (absencesError) throw absencesError;
      setAbsences(absencesData || []);

      // Récupérer les actions disciplinaires
      const { data: actionsData, error: actionsError } = await supabase
        .from('actions_disciplinaires')
        .select('*')
        .eq('profile_id', id)
        .order('date_action', { ascending: false });

      if (actionsError) throw actionsError;
      setActions(actionsData || []);

      // Récupérer les documents
      const { data: documentsData, error: documentsError } = await supabase
        .from('employee_documents')
        .select('*')
        .eq('profile_id', id)
        .order('uploaded_at', { ascending: false });

      if (documentsError) throw documentsError;
      
      setContractDocuments(documentsData?.filter(d => d.type_document === 'contrat') || []);
      setDisciplinaryDocuments(documentsData?.filter(d => d.type_document === 'disciplinaire') || []);

    } catch (error) {
      console.error('Erreur lors du chargement:', error);
      toast({
        title: "Erreur",
        description: "Impossible de charger les données de l'employé",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const fetchContractTypes = async () => {
    try {
      const { data, error } = await supabase
        .from('contract_types')
        .select('*')
        .eq('is_active', true)
        .order('nom');

      if (error) throw error;
      setContractTypes(data || []);
    } catch (error) {
      console.error('Erreur chargement types contrat:', error);
    }
  };

  const handleFileUpload = async (file: File, path: string) => {
    try {
      const fileExt = file.name.split('.').pop();
      const fileName = `${Date.now()}.${fileExt}`;
      const filePath = `${path}/${fileName}`;

      const { error: uploadError } = await supabase.storage
        .from('employee-documents')
        .upload(filePath, file);

      if (uploadError) throw uploadError;

      // Générer une URL signée car le bucket est privé
      const { data: signedUrlData, error: urlError } = await supabase.storage
        .from('employee-documents')
        .createSignedUrl(filePath, 3600 * 24 * 7); // Valide 7 jours

      if (urlError) throw urlError;

      return signedUrlData.signedUrl;
    } catch (error) {
      console.error('Erreur upload:', error);
      throw error;
    }
  };

  const handleSingleFileUpload = async (file: File, fieldName: string) => {
    if (!file || !id) return;

    setUploading(true);
    try {
      const url = await handleFileUpload(file, `${id}/${fieldName}`);
      
      // Mettre à jour le formulaire immédiatement pour l'affichage
      const updatedForm = {...profileForm, [fieldName]: url};
      setProfileForm(updatedForm);
      
      // Si c'est la photo, mettre à jour aussi le profil pour l'avatar en header
      if (fieldName === 'photo_url') {
        setProfile({...profile, photo_url: url} as Profile);
      }
      
      toast({
        title: "Succès",
        description: `${fieldName === 'photo_url' ? 'Photo' : 'Document'} uploadé avec succès`
      });
    } catch (error) {
      toast({
        title: "Erreur",
        description: "Erreur lors de l'upload du fichier",
        variant: "destructive"
      });
    } finally {
      setUploading(false);
    }
  };

  const handleMultipleDocumentsUpload = async (files: File[], type: string) => {
    if (!files.length || !id) return;

    setUploading(true);
    try {
      for (const file of files) {
        const url = await handleFileUpload(file, `${id}/${type}`);
        
        const { error } = await supabase
          .from('employee_documents')
          .insert({
            profile_id: id,
            type_document: type,
            document_url: url,
            document_name: file.name
          });

        if (error) throw error;
      }

      fetchEmployeeData();
      toast({
        title: "Succès",
        description: `${files.length} document(s) uploadé(s) avec succès`
      });
    } catch (error) {
      toast({
        title: "Erreur",
        description: "Erreur lors de l'upload des documents",
        variant: "destructive"
      });
    } finally {
      setUploading(false);
    }
  };

  const saveProfile = async () => {
    try {
      const { error } = await supabase
        .from('profiles')
        .update(profileForm)
        .eq('id', id);

      if (error) throw error;

      setProfile({ ...profile, ...profileForm } as Profile);
      toast({
        title: "Succès",
        description: "Profil mis à jour avec succès"
      });
    } catch (error) {
      console.error('Erreur sauvegarde:', error);
      toast({
        title: "Erreur",
        description: "Impossible de sauvegarder le profil",
        variant: "destructive"
      });
    }
  };

  const saveAbsence = async () => {
    try {
      if (editingAbsence) {
        const { error } = await supabase
          .from('absences_retards')
          .update(absenceForm)
          .eq('id', editingAbsence.id);
        if (error) throw error;
      } else {
        const { error } = await supabase
          .from('absences_retards')
          .insert({
            ...absenceForm,
            profile_id: id
          });
        if (error) throw error;
      }

      setShowAbsenceModal(false);
      setEditingAbsence(null);
      setAbsenceForm({
        date_absence: '',
        type_absence: '',
        duree_heures: 0,
        duree_jours: 0,
        justificatif: ''
      });
      fetchEmployeeData();
      
      toast({
        title: "Succès",
        description: editingAbsence ? "Absence mise à jour" : "Absence ajoutée"
      });
    } catch (error) {
      console.error('Erreur sauvegarde absence:', error);
      toast({
        title: "Erreur",
        description: "Impossible de sauvegarder l'absence",
        variant: "destructive"
      });
    }
  };

  const saveAction = async () => {
    try {
      let actionId = editingAction?.id;

      if (editingAction) {
        const { error } = await supabase
          .from('actions_disciplinaires')
          .update(actionForm)
          .eq('id', editingAction.id);
        if (error) throw error;
      } else {
        const { data, error } = await supabase
          .from('actions_disciplinaires')
          .insert({
            ...actionForm,
            profile_id: id
          })
          .select()
          .single();
        if (error) throw error;
        actionId = data.id;
      }

      // Upload des documents disciplinaires
      if (selectedActionDocuments.length > 0 && actionId) {
        await handleMultipleDocumentsUpload(selectedActionDocuments, 'disciplinaire');
        setSelectedActionDocuments([]);
      }

      setShowActionModal(false);
      setEditingAction(null);
      setActionForm({
        date_action: '',
        type_action: '',
        motif: ''
      });
      fetchEmployeeData();
      
      toast({
        title: "Succès",
        description: editingAction ? "Action mise à jour" : "Action ajoutée"
      });
    } catch (error) {
      console.error('Erreur sauvegarde action:', error);
      toast({
        title: "Erreur",
        description: "Impossible de sauvegarder l'action disciplinaire",
        variant: "destructive"
      });
    }
  };

  const addContractType = async () => {
    try {
      const { error } = await supabase
        .from('contract_types')
        .insert({ nom: newContractType });

      if (error) throw error;

      setNewContractType('');
      setShowContractTypeModal(false);
      fetchContractTypes();
      
      toast({
        title: "Succès",
        description: "Type de contrat ajouté"
      });
    } catch (error) {
      toast({
        title: "Erreur",
        description: "Impossible d'ajouter le type de contrat",
        variant: "destructive"
      });
    }
  };

  const deleteDocument = async (documentId: string) => {
    try {
      const { error } = await supabase
        .from('employee_documents')
        .delete()
        .eq('id', documentId);

      if (error) throw error;
      
      fetchEmployeeData();
      toast({
        title: "Succès",
        description: "Document supprimé"
      });
    } catch (error) {
      toast({
        title: "Erreur",
        description: "Impossible de supprimer le document",
        variant: "destructive"
      });
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    );
  }

  if (!profile) {
    return (
      <div className="p-6">
        <div className="text-center">
          <h1 className="text-2xl font-bold text-destructive">Employé introuvable</h1>
          <Button onClick={goBack} className="mt-4">
            <ArrowLeft className="h-4 w-4 mr-2" />
            Retour à l'administration
          </Button>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <Breadcrumbs />
      
      {/* En-tête */}
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-4">
          <Button
            variant="outline"
            onClick={goBack}
          >
            <ArrowLeft className="h-4 w-4 mr-2" />
            Retour
          </Button>
          <div className="flex items-center space-x-3">
            <Avatar className="h-16 w-16">
              <AvatarImage src={profileForm.photo_url || profile.photo_url} />
              <AvatarFallback>
                {profile.prenom?.charAt(0) || ''}{profile.nom?.charAt(0) || ''}
              </AvatarFallback>
            </Avatar>
            <div>
              <h1 className="text-2xl font-bold">{profile.prenom} {profile.nom}</h1>
              <p className="text-muted-foreground">{profile.poste || 'Aucun poste défini'}</p>
            </div>
          </div>
        </div>
      </div>

      {/* Onglets */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        <TabsList className="grid w-full grid-cols-6">
          <TabsTrigger value="personal">Informations Personnelles</TabsTrigger>
          <TabsTrigger value="contract">Contrat & Carrière</TabsTrigger>
          <TabsTrigger value="payroll">Paramètres de Paie</TabsTrigger>
          <TabsTrigger value="absences">Absences & Congés</TabsTrigger>
          <TabsTrigger value="disciplinary">Dossier Disciplinaire</TabsTrigger>
          <TabsTrigger value="assignments">Affectations</TabsTrigger>
        </TabsList>

        {/* Onglet Informations Personnelles */}
        <TabsContent value="personal" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Informations Personnelles & Administratives</CardTitle>
              <CardDescription>
                Données personnelles et documents administratifs de l'employé
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              {/* Photo de profil */}
              <div className="space-y-2">
                <Label>Photo de profil</Label>
                <div className="flex items-center space-x-4">
                  <Avatar className="h-20 w-20">
                    <AvatarImage 
                      src={profileForm.photo_url || profile.photo_url} 
                      key={profileForm.photo_url || profile.photo_url} // Force re-render when URL changes
                    />
                    <AvatarFallback>
                      {profile.prenom?.charAt(0) || ''}{profile.nom?.charAt(0) || ''}
                    </AvatarFallback>
                  </Avatar>
                  <div className="flex-1">
                    <Input
                      type="file"
                      accept="image/*"
                      onChange={(e) => {
                        const file = e.target.files?.[0];
                        if (file) {
                          // Preview immédiat de la nouvelle image
                          const previewUrl = URL.createObjectURL(file);
                          setProfileForm({...profileForm, photo_url: previewUrl});
                          // Upload réel
                          handleSingleFileUpload(file, 'photo_url');
                        }
                      }}
                      disabled={uploading}
                    />
                    <div className="flex items-center mt-2 space-x-2">
                      <div className={`h-2 w-2 rounded-full ${uploading ? 'bg-yellow-500 animate-pulse' : 'bg-green-500'}`}></div>
                      <p className="text-sm text-muted-foreground">
                        {uploading ? 'Upload en cours...' : 'Formats acceptés: JPG, PNG, GIF'}
                      </p>
                    </div>
                  </div>
                </div>
              </div>

              {/* Section Email et Contact */}
              <div className="space-y-4 border-t pt-4">
                <h3 className="font-semibold">Informations de Contact</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label htmlFor="email">Email professionnel (Identifiant de connexion)</Label>
                    <Input
                      id="email"
                      type="email"
                      value={profileForm.email || ''}
                      onChange={(e) => setProfileForm({...profileForm, email: e.target.value})}
                      className="bg-blue-50 border-blue-200"
                    />
                    <div className="p-2 bg-blue-50 border border-blue-200 rounded text-xs text-blue-700">
                      ⚠️ <strong>Important :</strong> Cet email sera utilisé comme identifiant de connexion unique pour l'employé. 
                      Il doit correspondre à l'email utilisé lors de la création du compte dans le système d'authentification.
                    </div>
                  </div>
                  <div>
                    <Label htmlFor="email_personnel">Email personnel (facultatif)</Label>
                    <Input
                      id="email_personnel"
                      type="email"
                      value={profileForm.email_personnel || ''}
                      onChange={(e) => setProfileForm({...profileForm, email_personnel: e.target.value})}
                      placeholder="Email personnel de l'employé"
                    />
                    <p className="text-xs text-muted-foreground mt-1">
                      Email personnel distinct de l'identifiant de connexion
                    </p>
                  </div>
                  <div>
                    <Label htmlFor="telephone_personnel">Téléphone personnel</Label>
                    <Input
                      id="telephone_personnel"
                      value={profileForm.telephone_personnel || ''}
                      onChange={(e) => setProfileForm({...profileForm, telephone_personnel: e.target.value})}
                    />
                  </div>
                  <div>
                    <Label htmlFor="date_naissance">Date de naissance</Label>
                    <Input
                      id="date_naissance"
                      type="date"
                      value={profileForm.date_naissance || ''}
                      onChange={(e) => setProfileForm({...profileForm, date_naissance: e.target.value})}
                    />
                  </div>
                </div>
                <div>
                  <Label htmlFor="adresse_complete">Adresse complète</Label>
                  <Textarea
                    id="adresse_complete"
                    value={profileForm.adresse_complete || ''}
                    onChange={(e) => setProfileForm({...profileForm, adresse_complete: e.target.value})}
                  />
                </div>
              </div>

              {/* Section CIN */}
              <div className="space-y-4 border-t pt-4">
                <h3 className="font-semibold">Carte Nationale d'Identité</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <Label htmlFor="cin_numero">Numéro CIN</Label>
                    <Input
                      id="cin_numero"
                      value={profileForm.cin_numero || ''}
                      onChange={(e) => setProfileForm({...profileForm, cin_numero: e.target.value})}
                    />
                  </div>
                  <div>
                    <Label>Scan CIN</Label>
                    <div className="space-y-2">
                      <Input
                        type="file"
                        accept="image/*,application/pdf"
                        onChange={(e) => {
                          const file = e.target.files?.[0];
                          if (file) handleSingleFileUpload(file, 'cin_scan_url');
                        }}
                        disabled={uploading}
                      />
                      {profileForm.cin_scan_url && (
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => window.open(profileForm.cin_scan_url, '_blank')}
                        >
                          <Eye className="h-4 w-4 mr-2" />
                          Voir le document
                        </Button>
                      )}
                    </div>
                  </div>
                </div>
              </div>

              {/* Section CNSS */}
              <div className="space-y-4 border-t pt-4">
                <h3 className="font-semibold">CNSS</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <Label htmlFor="cnss_numero">Numéro CNSS</Label>
                    <Input
                      id="cnss_numero"
                      value={profileForm.cnss_numero || ''}
                      onChange={(e) => setProfileForm({...profileForm, cnss_numero: e.target.value})}
                    />
                  </div>
                  <div>
                    <Label>Scan CNSS</Label>
                    <div className="space-y-2">
                      <Input
                        type="file"
                        accept="image/*,application/pdf"
                        onChange={(e) => {
                          const file = e.target.files?.[0];
                          if (file) handleSingleFileUpload(file, 'cnss_scan_url');
                        }}
                        disabled={uploading}
                      />
                      {profileForm.cnss_scan_url && (
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => window.open(profileForm.cnss_scan_url, '_blank')}
                        >
                          <Eye className="h-4 w-4 mr-2" />
                          Voir le document
                        </Button>
                      )}
                    </div>
                  </div>
                </div>
              </div>

              {/* Section RIB */}
              <div className="space-y-4 border-t pt-4">
                <h3 className="font-semibold">Relevé d'Identité Bancaire (RIB)</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <Label htmlFor="rib_numero">Numéro RIB</Label>
                    <Input
                      id="rib_numero"
                      value={profileForm.rib_numero || ''}
                      onChange={(e) => setProfileForm({...profileForm, rib_numero: e.target.value})}
                    />
                  </div>
                  <div>
                    <Label>Attestation RIB</Label>
                    <div className="space-y-2">
                      <Input
                        type="file"
                        accept="image/*,application/pdf"
                        onChange={(e) => {
                          const file = e.target.files?.[0];
                          if (file) handleSingleFileUpload(file, 'rib_scan_url');
                        }}
                        disabled={uploading}
                      />
                      {profileForm.rib_scan_url && (
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => window.open(profileForm.rib_scan_url, '_blank')}
                        >
                          <Eye className="h-4 w-4 mr-2" />
                          Voir le document
                        </Button>
                      )}
                    </div>
                  </div>
                </div>
              </div>

              <Button onClick={saveProfile} disabled={uploading}>
                {uploading ? 'Upload en cours...' : 'Sauvegarder les modifications'}
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Onglet Contrat & Carrière */}
        <TabsContent value="contract" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Contrat & Carrière</CardTitle>
              <CardDescription>
                Informations contractuelles et de carrière
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <Label htmlFor="type_contrat">Type de contrat</Label>
                  <div className="flex space-x-2">
                    <Select 
                      value={profileForm.type_contrat || ''} 
                      onValueChange={(value) => setProfileForm({...profileForm, type_contrat: value})}
                    >
                      <SelectTrigger className="flex-1">
                        <SelectValue placeholder="Sélectionner un type" />
                      </SelectTrigger>
                      <SelectContent>
                        {contractTypes.map((type) => (
                          <SelectItem key={type.id} value={type.nom}>
                            {type.nom}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <Dialog open={showContractTypeModal} onOpenChange={setShowContractTypeModal}>
                      <DialogTrigger asChild>
                        <Button variant="outline" size="icon">
                          <Plus className="h-4 w-4" />
                        </Button>
                      </DialogTrigger>
                      <DialogContent>
                        <DialogHeader>
                          <DialogTitle>Ajouter un type de contrat</DialogTitle>
                        </DialogHeader>
                        <div className="space-y-4">
                          <div>
                            <Label htmlFor="new_contract_type">Nom du type de contrat</Label>
                            <Input
                              id="new_contract_type"
                              value={newContractType}
                              onChange={(e) => setNewContractType(e.target.value)}
                              placeholder="Ex: Consultant externe"
                            />
                          </div>
                          <Button 
                            onClick={addContractType} 
                            disabled={!newContractType.trim()}
                            className="w-full"
                          >
                            Ajouter
                          </Button>
                        </div>
                      </DialogContent>
                    </Dialog>
                  </div>
                </div>
                <div>
                  <Label htmlFor="date_debut_contrat">Date de début</Label>
                  <Input
                    id="date_debut_contrat"
                    type="date"
                    value={profileForm.date_debut_contrat || ''}
                    onChange={(e) => setProfileForm({...profileForm, date_debut_contrat: e.target.value})}
                  />
                </div>
                <div>
                  <Label htmlFor="date_fin_contrat">Date de fin (optionnel)</Label>
                  <Input
                    id="date_fin_contrat"
                    type="date"
                    value={profileForm.date_fin_contrat || ''}
                    onChange={(e) => setProfileForm({...profileForm, date_fin_contrat: e.target.value})}
                  />
                </div>
                <div>
                  <Label htmlFor="solde_conges_payes">Solde congés payés (jours)</Label>
                  <Input
                    id="solde_conges_payes"
                    type="number"
                    step="0.5"
                    value={profileForm.solde_conges_payes || 0}
                    onChange={(e) => setProfileForm({...profileForm, solde_conges_payes: parseFloat(e.target.value)})}
                  />
                </div>
              </div>

              {/* Section Contrats avec Documents */}
              <div className="space-y-4 border-t pt-4">
                <div className="flex justify-between items-center">
                  <h3 className="font-semibold">Contrats de travail</h3>
                  <div>
                    <Input
                      type="file"
                      multiple
                      accept=".pdf,image/*"
                      onChange={(e) => {
                        const files = Array.from(e.target.files || []);
                        if (files.length > 0) {
                          setSelectedContractDocuments(files);
                          handleMultipleDocumentsUpload(files, 'contrat');
                        }
                      }}
                      className="hidden"
                      id="contract-upload"
                    />
                    <Label htmlFor="contract-upload" className="cursor-pointer">
                      <Button variant="outline" asChild>
                        <span>
                          <Upload className="h-4 w-4 mr-2" />
                          Ajouter des contrats
                        </span>
                      </Button>
                    </Label>
                  </div>
                </div>
                
                <DocumentList
                  title="Documents de contrat"
                  documents={contractDocuments}
                  onDelete={deleteDocument}
                  emptyMessage="Aucun contrat téléchargé"
                />
              </div>

              <Button onClick={saveProfile} disabled={uploading}>
                {uploading ? 'Upload en cours...' : 'Sauvegarder les modifications'}
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Onglet Paramètres de Paie */}
        <TabsContent value="payroll" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Paramètres de Paie</CardTitle>
              <CardDescription>
                Configuration des retenues et du salaire horaire pour les calculs de paie
              </CardDescription>
            </CardHeader>
            <CardContent>
              <EmployeePayrollSettings 
                profileId={id!} 
                profileName={`${profile.prenom} ${profile.nom}`}
                currentSalaireHoraire={profile.salaire_horaire}
              />
            </CardContent>
          </Card>
        </TabsContent>

        {/* Onglet Absences & Congés */}
        <TabsContent value="absences" className="space-y-6">
          <Card>
            <CardHeader>
              <div className="flex justify-between items-center">
                <div>
                  <CardTitle>Suivi des Absences & Congés</CardTitle>
                  <CardDescription>
                    Solde actuel: {profile.solde_conges_payes || 0} jours de congés payés
                  </CardDescription>
                </div>
                <Dialog open={showAbsenceModal} onOpenChange={setShowAbsenceModal}>
                  <DialogTrigger asChild>
                    <Button>
                      <Plus className="h-4 w-4 mr-2" />
                      Ajouter une absence
                    </Button>
                  </DialogTrigger>
                  <DialogContent>
                    <DialogHeader>
                      <DialogTitle>
                        {editingAbsence ? 'Modifier l\'absence' : 'Ajouter une absence'}
                      </DialogTitle>
                    </DialogHeader>
                    <div className="space-y-4">
                      <div>
                        <Label htmlFor="date_absence">Date</Label>
                        <Input
                          id="date_absence"
                          type="date"
                          value={absenceForm.date_absence}
                          onChange={(e) => setAbsenceForm({...absenceForm, date_absence: e.target.value})}
                        />
                      </div>
                      <div>
                        <Label htmlFor="type_absence">Type</Label>
                        <Select value={absenceForm.type_absence} onValueChange={(value) => setAbsenceForm({...absenceForm, type_absence: value})}>
                          <SelectTrigger>
                            <SelectValue placeholder="Sélectionner un type" />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="absence_justifiee">Absence Justifiée</SelectItem>
                            <SelectItem value="absence_non_justifiee">Absence Non Justifiée</SelectItem>
                            <SelectItem value="retard">Retard</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <Label htmlFor="duree_jours">Durée (jours)</Label>
                          <Input
                            id="duree_jours"
                            type="number"
                            step="0.5"
                            value={absenceForm.duree_jours}
                            onChange={(e) => setAbsenceForm({...absenceForm, duree_jours: parseFloat(e.target.value)})}
                          />
                        </div>
                        <div>
                          <Label htmlFor="duree_heures">Durée (heures)</Label>
                          <Input
                            id="duree_heures"
                            type="number"
                            step="0.25"
                            value={absenceForm.duree_heures}
                            onChange={(e) => setAbsenceForm({...absenceForm, duree_heures: parseFloat(e.target.value)})}
                          />
                        </div>
                      </div>
                      <div>
                        <Label htmlFor="justificatif">Justificatif</Label>
                        <Textarea
                          id="justificatif"
                          value={absenceForm.justificatif}
                          onChange={(e) => setAbsenceForm({...absenceForm, justificatif: e.target.value})}
                        />
                      </div>
                      <Button onClick={saveAbsence} className="w-full">
                        {editingAbsence ? 'Mettre à jour' : 'Ajouter'}
                      </Button>
                    </div>
                  </DialogContent>
                </Dialog>
              </div>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Date</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Durée</TableHead>
                    <TableHead>Justificatif</TableHead>
                    <TableHead>Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {absences.map((absence) => (
                    <TableRow key={absence.id}>
                      <TableCell>{new Date(absence.date_absence).toLocaleDateString()}</TableCell>
                      <TableCell>
                        {absence.type_absence === 'absence_justifiee' && 'Absence Justifiée'}
                        {absence.type_absence === 'absence_non_justifiee' && 'Absence Non Justifiée'}
                        {absence.type_absence === 'retard' && 'Retard'}
                      </TableCell>
                      <TableCell>
                        {absence.duree_jours > 0 && `${absence.duree_jours} j`}
                        {absence.duree_heures > 0 && ` ${absence.duree_heures} h`}
                      </TableCell>
                      <TableCell className="max-w-xs truncate">{absence.justificatif}</TableCell>
                      <TableCell>
                        <div className="flex space-x-2">
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => {
                              setEditingAbsence(absence);
                              setAbsenceForm({
                                date_absence: absence.date_absence,
                                type_absence: absence.type_absence,
                                duree_heures: absence.duree_heures,
                                duree_jours: absence.duree_jours,
                                justificatif: absence.justificatif || ''
                              });
                              setShowAbsenceModal(true);
                            }}
                          >
                            <Edit className="h-4 w-4" />
                          </Button>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={async () => {
                              try {
                                const { error } = await supabase
                                  .from('absences_retards')
                                  .delete()
                                  .eq('id', absence.id);

                                if (error) throw error;
                                
                                fetchEmployeeData();
                                toast({
                                  title: "Succès",
                                  description: "Absence supprimée"
                                });
                              } catch (error) {
                                toast({
                                  title: "Erreur",
                                  description: "Impossible de supprimer l'absence",
                                  variant: "destructive"
                                });
                              }
                            }}
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Onglet Dossier Disciplinaire */}
        <TabsContent value="disciplinary" className="space-y-6">
          <Card>
            <CardHeader>
              <div className="flex justify-between items-center">
                <div>
                  <CardTitle>Dossier Disciplinaire</CardTitle>
                  <CardDescription>
                    Historique des actions disciplinaires
                  </CardDescription>
                </div>
                <Dialog open={showActionModal} onOpenChange={setShowActionModal}>
                  <DialogTrigger asChild>
                    <Button>
                      <Plus className="h-4 w-4 mr-2" />
                      Ajouter une action
                    </Button>
                  </DialogTrigger>
                  <DialogContent className="max-w-2xl">
                    <DialogHeader>
                      <DialogTitle>
                        {editingAction ? 'Modifier l\'action' : 'Ajouter une action disciplinaire'}
                      </DialogTitle>
                    </DialogHeader>
                    <div className="space-y-4">
                      <div>
                        <Label htmlFor="date_action">Date</Label>
                        <Input
                          id="date_action"
                          type="date"
                          value={actionForm.date_action}
                          onChange={(e) => setActionForm({...actionForm, date_action: e.target.value})}
                        />
                      </div>
                      <div>
                        <Label htmlFor="type_action">Type d'action</Label>
                        <Select value={actionForm.type_action} onValueChange={(value) => setActionForm({...actionForm, type_action: value})}>
                          <SelectTrigger>
                            <SelectValue placeholder="Sélectionner un type" />
                          </SelectTrigger>
                          <SelectContent className="max-h-80 overflow-y-auto">
                            <SelectItem value="avertissement">
                              <div className="space-y-1">
                                <div className="font-medium">1. L'Avertissement</div>
                                <div className="text-xs text-muted-foreground">
                                  Document : Lettre d'avertissement. Sanction la plus légère pour une première faute simple.
                                </div>
                              </div>
                            </SelectItem>
                            <SelectItem value="blame">
                              <div className="space-y-1">
                                <div className="font-medium">2. Le Blâme</div>
                                <div className="text-xs text-muted-foreground">
                                  Document : Lettre de blâme. En cas de récidive ou faute de gravité intermédiaire.
                                </div>
                              </div>
                            </SelectItem>
                            <SelectItem value="deuxieme_blame">
                              <div className="space-y-1">
                                <div className="font-medium">3. Le Deuxième Blâme</div>
                                <div className="text-xs text-muted-foreground">
                                  Document : Lettre de deuxième blâme. Nouvelle faute après un premier blâme.
                                </div>
                              </div>
                            </SelectItem>
                            <SelectItem value="mise_a_pied_disciplinaire">
                              <div className="space-y-1">
                                <div className="font-medium">3. Mise à Pied Disciplinaire</div>
                                <div className="text-xs text-muted-foreground">
                                  Document : Lettre de mise à pied. Durée max 8 jours, contrat suspendu sans rémunération.
                                </div>
                              </div>
                            </SelectItem>
                            <SelectItem value="troisieme_blame">
                              <div className="space-y-1">
                                <div className="font-medium">4. Le Troisième Blâme</div>
                                <div className="text-xs text-muted-foreground">
                                  Document : Lettre de troisième blâme. Après deux blâmes antérieurs.
                                </div>
                              </div>
                            </SelectItem>
                            <SelectItem value="transfert_disciplinaire">
                              <div className="space-y-1">
                                <div className="font-medium">4. Transfert Disciplinaire</div>
                                <div className="text-xs text-muted-foreground">
                                  Document : Lettre de transfert. Vers un autre service ou établissement.
                                </div>
                              </div>
                            </SelectItem>
                            <SelectItem value="licenciement_cumul">
                              <div className="space-y-1">
                                <div className="font-medium">Licenciement pour Cumul de Sanctions</div>
                                <div className="text-xs text-muted-foreground">
                                  Document : Lettre de licenciement. Épuisement de l'échelle des sanctions sur une année.
                                </div>
                              </div>
                            </SelectItem>
                            <SelectItem value="convocation_entretien">
                              <div className="space-y-1">
                                <div className="font-medium">Convocation à l'Entretien Préalable</div>
                                <div className="text-xs text-muted-foreground">
                                  Document : Lettre de convocation. Avant licenciement pour faute grave.
                                </div>
                              </div>
                            </SelectItem>
                            <SelectItem value="pv_ecoute">
                              <div className="space-y-1">
                                <div className="font-medium">Procès-Verbal d'Écoute</div>
                                <div className="text-xs text-muted-foreground">
                                  Document : PV de l'entretien préalable. Signé par les deux parties.
                                </div>
                              </div>
                            </SelectItem>
                            <SelectItem value="licenciement_faute_grave">
                              <div className="space-y-1">
                                <div className="font-medium">Licenciement pour Faute Grave</div>
                                <div className="text-xs text-muted-foreground">
                                  Document : Lettre de licenciement. Sans préavis ni indemnité.
                                </div>
                              </div>
                            </SelectItem>
                            <SelectItem value="demission">
                              <div className="space-y-1">
                                <div className="font-medium">Démission</div>
                                <div className="text-xs text-muted-foreground">
                                  Document : Lettre de démission. Départ volontaire du salarié.
                                </div>
                              </div>
                            </SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                      <div>
                        <Label htmlFor="motif">Motif</Label>
                        <Textarea
                          id="motif"
                          value={actionForm.motif}
                          onChange={(e) => setActionForm({...actionForm, motif: e.target.value})}
                        />
                      </div>
                      
                      {/* Upload de documents disciplinaires */}
                      <div className="space-y-2">
                        <Label>Documents disciplinaires</Label>
                        <Input
                          type="file"
                          multiple
                          accept=".pdf,image/*"
                          onChange={(e) => {
                            const files = Array.from(e.target.files || []);
                            setSelectedActionDocuments(files);
                          }}
                        />
                        {selectedActionDocuments.length > 0 && (
                          <div className="space-y-1">
                            {selectedActionDocuments.map((file, index) => (
                              <div key={index} className="flex items-center justify-between text-sm p-2 bg-muted rounded">
                                <span>{file.name}</span>
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  onClick={() => {
                                    const newFiles = selectedActionDocuments.filter((_, i) => i !== index);
                                    setSelectedActionDocuments(newFiles);
                                  }}
                                >
                                  <X className="h-4 w-4" />
                                </Button>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>

                      <Button onClick={saveAction} className="w-full" disabled={uploading}>
                        {uploading ? 'Upload en cours...' : editingAction ? 'Mettre à jour' : 'Ajouter'}
                      </Button>
                    </div>
                  </DialogContent>
                </Dialog>
              </div>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Date</TableHead>
                    <TableHead>Type d'action</TableHead>
                    <TableHead>Motif</TableHead>
                    <TableHead>Documents</TableHead>
                    <TableHead>Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {actions.map((action) => (
                    <TableRow key={action.id}>
                      <TableCell>{new Date(action.date_action).toLocaleDateString()}</TableCell>
                      <TableCell>
                        {action.type_action === 'avertissement_oral' && 'Avertissement Oral'}
                        {action.type_action === 'avertissement_ecrit' && 'Avertissement Écrit'}
                        {action.type_action === 'mise_a_pied' && 'Mise à Pied'}
                        {action.type_action === 'autre' && 'Autre'}
                      </TableCell>
                      <TableCell className="max-w-xs truncate">{action.motif}</TableCell>
                      <TableCell>
                        {disciplinaryDocuments.filter(doc => doc.description === action.id).length > 0 ? (
                          <div className="space-y-1">
                            {disciplinaryDocuments
                              .filter(doc => doc.description === action.id)
                              .map((doc) => (
                                <Button
                                  key={doc.id}
                                  variant="outline"
                                  size="sm"
                                  onClick={() => window.open(doc.document_url, '_blank')}
                                >
                                  <FileText className="h-4 w-4 mr-1" />
                                  {doc.document_name}
                                </Button>
                              ))}
                          </div>
                        ) : (
                          <span className="text-muted-foreground text-sm">Aucun document</span>
                        )}
                      </TableCell>
                      <TableCell>
                        <div className="flex space-x-2">
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => {
                              setEditingAction(action);
                              setActionForm({
                                date_action: action.date_action,
                                type_action: action.type_action,
                                motif: action.motif
                              });
                              setShowActionModal(true);
                            }}
                          >
                            <Edit className="h-4 w-4" />
                          </Button>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={async () => {
                              try {
                                const { error } = await supabase
                                  .from('actions_disciplinaires')
                                  .delete()
                                  .eq('id', action.id);

                                if (error) throw error;
                                
                                fetchEmployeeData();
                                toast({
                                  title: "Succès",
                                  description: "Action disciplinaire supprimée"
                                });
                              } catch (error) {
                                toast({
                                  title: "Erreur",
                                  description: "Impossible de supprimer l'action disciplinaire",
                                  variant: "destructive"
                                });
                              }
                            }}
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
          
          {/* Section Documents Disciplinaires */}
          <Card>
            <CardHeader>
              <CardTitle>Documents Disciplinaires</CardTitle>
              <CardDescription>
                Tous les documents relatifs aux actions disciplinaires
              </CardDescription>
            </CardHeader>
            <CardContent>
              <DocumentList
                title="Documents disciplinaires"
                documents={disciplinaryDocuments}
                onDelete={deleteDocument}
                emptyMessage="Aucun document disciplinaire"
              />
            </CardContent>
          </Card>
        </TabsContent>

        {/* Onglet Affectations */}
        <TabsContent value="assignments" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Affectations de l'employé</CardTitle>
              <CardDescription>
                Gestion des affectations aux villes, centres et formations
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Tabs defaultValue="villes" className="w-full">
                <TabsList className="grid w-full grid-cols-3">
                  <TabsTrigger value="villes">Villes</TabsTrigger>
                  <TabsTrigger value="centres">Centres</TabsTrigger>
                  <TabsTrigger value="formations">Formations</TabsTrigger>
                </TabsList>
                
                <TabsContent value="villes" className="space-y-4">
                  {profile?.user_id && <UserVilleAssignment userId={profile.user_id} />}
                </TabsContent>
                
                <TabsContent value="centres" className="space-y-4">
                  {profile?.user_id && <UserCentreAssignment userId={profile.user_id} />}
                </TabsContent>
                
                <TabsContent value="formations" className="space-y-4">
                  {profile?.user_id && <UserFormationAssignment userId={profile.user_id} />}
                </TabsContent>
              </Tabs>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default EmployeeRecord;