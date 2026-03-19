import React, { useState, useEffect } from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { Separator } from '@/components/ui/separator';
import { Upload, X } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import LoadingSpinner from '@/components/LoadingSpinner';

import type { Student, Inscription } from '@/types/models';

interface Centre {
  id: string;
  nom: string;
  villes: { nom_ville: string };
}

interface Formation {
  id: string;
  titre: string;
  prix: number;
}

interface Classe {
  id: string;
  nom_classe: string;
  nombre_places: number;
  centre_id: string;
  formation_id: string;
}

interface EditStudentModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  student: Student;
  inscription: Inscription;
  onSuccess: () => void;
}

export function EditStudentModal({ open, onOpenChange, student, inscription, onSuccess }: EditStudentModalProps) {
  const [loading, setLoading] = useState(false);
  const [photoFile, setPhotoFile] = useState<File | null>(null);
  const [photoPreview, setPhotoPreview] = useState<string | null>(null);
  const [centres, setCentres] = useState<Centre[]>([]);
  const [formations, setFormations] = useState<Formation[]>([]);
  const [classes, setClasses] = useState<Classe[]>([]);
  const [currentClass, setCurrentClass] = useState<Classe | null>(null);
  const { toast } = useToast();
  const [initialized, setInitialized] = useState(false);

  const [formData, setFormData] = useState({
    // Student data
    nom: '',
    prenom: '',
    cin: '',
    email: '',
    telephone: '',
    whatsapp: '',
    date_naissance: '',
    lieu_naissance: '',
    adresse: '',
    
    // Inscription data
    centre_id: '',
    formation_id: '',
    classe_id: '',
    numero_bon: '',
    avance: '',
    statut_compte: ''
  });

  const [errors, setErrors] = useState<Record<string, string>>({});

  useEffect(() => {
    loadCentres();
    loadFormations();
  }, []);

  // Initialisation principale quand le modal s'ouvre avec les données
  useEffect(() => {
    if (open && student && inscription) {
      console.log('📝 EditStudentModal - Initializing with:', { student, inscription });
      
      // Initialiser immédiatement les données étudiant
      const initialData = {
        nom: student.nom || '',
        prenom: student.prenom || '',
        cin: student.cin || '',
        email: student.email || '',
        telephone: student.telephone || '',
        whatsapp: student.whatsapp || '',
        date_naissance: student.date_naissance ? student.date_naissance.split('T')[0] : '',
        lieu_naissance: student.lieu_naissance || '',
        adresse: student.adresse || '',
        formation_id: inscription.formation_id || '',
        classe_id: inscription.classe_id || '',
        numero_bon: inscription.numero_bon || '',
        avance: inscription.avance?.toString() || '',
        statut_compte: inscription.statut_compte || 'non_valide',
        centre_id: '' // Sera mis à jour par loadCurrentClass
      };
      
      console.log('📝 Setting initial form data:', initialData);
      setFormData(initialData);
      setPhotoPreview(student.photo_url || null);
      setErrors({}); // Réinitialiser les erreurs
      setInitialized(true);
      
      // Charger la classe actuelle pour récupérer centre_id
      if (inscription.classe_id) {
        loadCurrentClass(inscription.classe_id);
      }
    }
  }, [open, student, inscription, loadCurrentClass]);

  // Mettre à jour centre_id quand currentClass est chargée
  useEffect(() => {
    if (currentClass && open) {
      console.log('📚 Mise à jour formData avec currentClass:', currentClass);
      setFormData(prev => ({
        ...prev,
        centre_id: currentClass.centre_id
      }));
    }
  }, [currentClass, open]);

  // Charger les classes quand le centre change
  useEffect(() => {
    if (formData.centre_id && open) {
      loadClassesForCentre(formData.centre_id);
    }
  }, [formData.centre_id, open]);

  useEffect(() => {
    if (!open) {
      setInitialized(false);
      setPhotoFile(null);
    }
  }, [open]);

  const loadCentres = async () => {
    try {
      const { data, error } = await supabase
        .from('centres')
        .select('id, nom, villes:ville_id(nom_ville)')
        .eq('is_active', true)
        .order('nom');

      if (error) throw error;
      setCentres(data || []);
    } catch (error) {
      console.error('Error loading centres:', error);
    }
  };

  const loadFormations = async () => {
    try {
      const { data, error } = await supabase
        .from('formations')
        .select('id, titre, prix')
        .eq('is_active', true)
        .order('titre');

      if (error) throw error;
      setFormations(data || []);
    } catch (error) {
      console.error('Error loading formations:', error);
    }
  };

  const loadClassesForCentre = async (centreId: string) => {
    try {
      const { data, error } = await supabase
        .from('classes')
        .select('id, nom_classe, nombre_places, centre_id, formation_id')
        .eq('centre_id', centreId)
        .eq('is_active', true)
        .in('statut', ['programmee', 'en_cours'])
        .order('nom_classe');

      if (error) throw error;
      setClasses(data || []);
    } catch (error) {
      console.error('Error loading classes:', error);
    }
  };

  const loadCurrentClass = async (classeId: string) => {
    try {
      const { data, error } = await supabase
        .from('classes')
        .select('id, nom_classe, nombre_places, centre_id, formation_id')
        .eq('id', classeId)
        .single();

      if (error) throw error;
      return useCallback(async (classeId: string) => {
        try {
          const { data, error } = await supabase
            .from('classes')
            .select('id, nom_classe, nombre_places, centre_id, formation_id')
            .eq('id', classeId)
            .single();

          if (error) throw error;
          if (data) {
            console.log('📚 Classe actuelle chargée:', data);
            setCurrentClass(data);
            // Mettre à jour immédiatement le formData avec les bonnes valeurs
            setFormData(prev => ({
              ...prev,
              centre_id: data.centre_id
            }));
            // Charger les classes pour ce centre
            loadClassesForCentre(data.centre_id);
            return data; // Retourner les données pour les utiliser dans le useEffect
          }
        } catch (error) {
          console.error('Error loading current class:', error);
        }
        return null;
      }, [loadClassesForCentre]);
    if (!formData.nom.trim()) newErrors.nom = 'Ce champ est requis';
    if (!formData.prenom.trim()) newErrors.prenom = 'Ce champ est requis';
    if (!formData.cin.trim()) newErrors.cin = 'Ce champ est requis';
    if (!formData.telephone.trim()) newErrors.telephone = 'Ce champ est requis';
    if (!formData.date_naissance) newErrors.date_naissance = 'Ce champ est requis';
    if (!formData.lieu_naissance.trim()) newErrors.lieu_naissance = 'Ce champ est requis';
    if (!formData.adresse.trim()) newErrors.adresse = 'Ce champ est requis';
    
    // Champs obligatoires inscription
    if (!formData.centre_id) newErrors.centre_id = 'Ce champ est requis';
    if (!formData.classe_id) newErrors.classe_id = 'Ce champ est requis';
    if (!formData.formation_id) newErrors.formation_id = 'Ce champ est requis';
    if (!formData.numero_bon.trim()) newErrors.numero_bon = 'Ce champ est requis';


    // Validation email si fourni
    if (formData.email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email)) {
      newErrors.email = 'Adresse email invalide';
    }

    // Validation CIN
    if (formData.cin && !/^[A-Z]{1,2}[0-9]{1,6}$/.test(formData.cin.toUpperCase())) {
      newErrors.cin = 'Format CIN invalide (ex: AB123456)';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handlePhotoChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      if (file.size > 5 * 1024 * 1024) {
        toast({
          title: "Erreur",
          description: "La taille du fichier ne doit pas dépasser 5MB",
          variant: "destructive"
        });
        return;
      }

      setPhotoFile(file);
      const reader = new FileReader();
      reader.onload = (e) => {
        setPhotoPreview(e.target?.result as string);
      };
      reader.readAsDataURL(file);
    }
  };

  const removePhoto = () => {
    setPhotoFile(null);
    setPhotoPreview(student.photo_url || null);
  };

  const uploadPhoto = async (): Promise<string | null> => {
    if (!photoFile) return null;

    try {
      const fileExt = photoFile.name.split('.').pop();
      const fileName = `${Date.now()}-${Math.random().toString(36).substring(2)}.${fileExt}`;
      const filePath = `student-photos/${fileName}`;

      const { error: uploadError } = await supabase.storage
        .from('employee-documents')
        .upload(filePath, photoFile);

      if (uploadError) throw uploadError;

      const { data: { publicUrl } } = supabase.storage
        .from('employee-documents')
        .getPublicUrl(filePath);

      return publicUrl;
    } catch (error) {
      console.error('Error uploading photo:', error);
      toast({
        title: "Erreur",
        description: "Impossible d'uploader la photo",
        variant: "destructive"
      });
      return null;
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!validateForm()) {
      toast({
        title: "Erreur de validation",
        description: "Veuillez corriger les erreurs dans le formulaire",
        variant: "destructive"
      });
      return;
    }

    setLoading(true);

    try {
      // Upload new photo if provided
      let photoUrl = student.photo_url;
      if (photoFile) {
        const newPhotoUrl = await uploadPhoto();
        if (newPhotoUrl) photoUrl = newPhotoUrl;
      }

      // Update student data
      const studentUpdateData = {
        nom: formData.nom.trim(),
        prenom: formData.prenom.trim(),
        cin: formData.cin.toUpperCase().trim(),
        email: formData.email.trim() || null,
        telephone: formData.telephone.trim(),
        whatsapp: formData.whatsapp.trim() || null,
        date_naissance: formData.date_naissance,
        lieu_naissance: formData.lieu_naissance.trim(),
        adresse: formData.adresse.trim(),
        photo_url: photoUrl
      };

      const { error: studentError } = await supabase
        .from('etudiants')
        .update(studentUpdateData)
        .eq('id', student.id);

      if (studentError) throw studentError;

      // Update inscription data (including possible class change)
      const inscriptionUpdateData = {
        classe_id: formData.classe_id,
        formation_id: formData.formation_id,
        numero_bon: formData.numero_bon.trim(),
        avance: formData.avance ? parseFloat(formData.avance) : 0,
        statut_compte: formData.statut_compte
      };

      const { error: inscriptionError } = await supabase
        .from('inscriptions')
        .update(inscriptionUpdateData)
        .eq('id', inscription.id);

      if (inscriptionError) throw inscriptionError;

      toast({
        title: "Succès",
        description: "Les informations ont été mises à jour avec succès"
      });

      onSuccess();
      onOpenChange(false);
    } catch (error) {
      console.error('Error updating student:', error);
      toast({
        title: "Erreur",
        description: "Impossible de mettre à jour les informations",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Modifier les informations de l'étudiant</DialogTitle>
          <DialogDescription>Modifiez et enregistrez les informations de l'étudiant. Tous les champs requis sont marqués *</DialogDescription>
        </DialogHeader>

        {!initialized && (
          <div className="py-4 flex items-center gap-3">
            <LoadingSpinner size="sm" />
            <span className="text-muted-foreground">Chargement des données…</span>
          </div>
        )}

        {initialized && (
          <form onSubmit={handleSubmit} className="space-y-6">
          {/* Photo */}
          <div>
            <Label>Photo de profil</Label>
            <div className="mt-2">
              {photoPreview ? (
                <div className="relative inline-block">
                  <img
                    src={photoPreview}
                    alt="Aperçu"
                    className="w-32 h-32 object-cover rounded-lg border"
                  />
                  {photoFile && (
                    <Button
                      type="button"
                      variant="destructive"
                      size="sm"
                      className="absolute -top-2 -right-2"
                      onClick={removePhoto}
                    >
                      <X className="h-4 w-4" />
                    </Button>
                  )}
                </div>
              ) : (
                <div className="w-32 h-32 border-2 border-dashed border-muted-foreground/25 rounded-lg flex items-center justify-center">
                  <Upload className="h-8 w-8 text-muted-foreground" />
                </div>
              )}
              <div className="mt-2">
                <input
                  type="file"
                  accept="image/*"
                  onChange={handlePhotoChange}
                  className="hidden"
                  id="photo-upload-edit"
                  title="Photo de l'étudiant"
                  placeholder="Photo de l'étudiant"
                />
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => document.getElementById('photo-upload-edit')?.click()}
                >
                  Changer la photo
                </Button>
              </div>
            </div>
          </div>

          {/* Personal Information */}
          <div>
            <h3 className="text-lg font-semibold mb-4">Informations Personnelles</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <Label htmlFor="nom">Nom *</Label>
                <Input
                  id="nom"
                  value={formData.nom}
                  onChange={(e) => setFormData({ ...formData, nom: e.target.value })}
                  className={errors.nom ? 'border-destructive' : ''}
                />
                {errors.nom && <p className="text-sm text-destructive mt-1">{errors.nom}</p>}
              </div>

              <div>
                <Label htmlFor="prenom">Prénom *</Label>
                <Input
                  title="Nom de l'étudiant"
                  placeholder="Nom de l'étudiant"
                  id="prenom"
                  value={formData.prenom}
                  onChange={(e) => setFormData({ ...formData, prenom: e.target.value })}
                  className={errors.prenom ? 'border-destructive' : ''}
                />
                {errors.prenom && <p className="text-sm text-destructive mt-1">{errors.prenom}</p>}
              </div>

              <div>
                <Label htmlFor="cin">CIN *</Label>
                <Input
                  id="cin"
                  value={formData.cin}
                  onChange={(e) => setFormData({ ...formData, cin: e.target.value })}
                  className={errors.cin ? 'border-destructive' : ''}
                />
                {errors.cin && <p className="text-sm text-destructive mt-1">{errors.cin}</p>}
              </div>

              <div>
                <Label htmlFor="email">Email</Label>
                <Input
                  id="email"
                  type="email"
                  value={formData.email}
                  onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                  className={errors.email ? 'border-destructive' : ''}
                />
                {errors.email && <p className="text-sm text-destructive mt-1">{errors.email}</p>}
              </div>

              <div>
                <Label htmlFor="telephone">Téléphone *</Label>
                <Input
                  id="telephone"
                  value={formData.telephone}
                  onChange={(e) => setFormData({ ...formData, telephone: e.target.value })}
                  className={errors.telephone ? 'border-destructive' : ''}
                />
                {errors.telephone && <p className="text-sm text-destructive mt-1">{errors.telephone}</p>}
              </div>

              <div>
                <Label htmlFor="whatsapp">WhatsApp</Label>
                <Input
                  id="whatsapp"
                  value={formData.whatsapp}
                  onChange={(e) => setFormData({ ...formData, whatsapp: e.target.value })}
                />
              </div>

              <div>
                <Label htmlFor="date_naissance">Date de naissance *</Label>
                <Input
                  id="date_naissance"
                  type="date"
                  value={formData.date_naissance}
                  onChange={(e) => setFormData({ ...formData, date_naissance: e.target.value })}
                  className={errors.date_naissance ? 'border-destructive' : ''}
                />
                {errors.date_naissance && <p className="text-sm text-destructive mt-1">{errors.date_naissance}</p>}
              </div>

              <div>
                <Label htmlFor="lieu_naissance">Lieu de naissance *</Label>
                <Input
                  id="lieu_naissance"
                  value={formData.lieu_naissance}
                  onChange={(e) => setFormData({ ...formData, lieu_naissance: e.target.value })}
                  className={errors.lieu_naissance ? 'border-destructive' : ''}
                />
                {errors.lieu_naissance && <p className="text-sm text-destructive mt-1">{errors.lieu_naissance}</p>}
              </div>
            </div>

            <div className="mt-4">
              <Label htmlFor="adresse">Adresse *</Label>
              <Textarea
                id="adresse"
                value={formData.adresse}
                onChange={(e) => setFormData({ ...formData, adresse: e.target.value })}
                className={errors.adresse ? 'border-destructive' : ''}
                rows={3}
              />
              {errors.adresse && <p className="text-sm text-destructive mt-1">{errors.adresse}</p>}
            </div>
          </div>

          <Separator />

          {/* Formation Information */}
          <div>
            <h3 className="text-lg font-semibold mb-4">Informations sur l'inscription</h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <Label htmlFor="centre_id">Centre de formation *</Label>
                <Select
                  value={formData.centre_id}
                  onValueChange={(value) => {
                    setFormData({ 
                      ...formData, 
                      centre_id: value,
                      classe_id: '' // Reset classe when centre changes
                    });
                  }}
                >
                  <SelectTrigger className={errors.centre_id ? 'border-destructive' : ''}>
                    <SelectValue placeholder="Sélectionner un centre" />
                  </SelectTrigger>
                  <SelectContent>
                    {centres.map((centre) => (
                      <SelectItem key={centre.id} value={centre.id}>
                        {centre.nom} - {centre.villes?.nom_ville}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {errors.centre_id && <p className="text-sm text-destructive mt-1">{errors.centre_id}</p>}
              </div>

              <div>
                <Label htmlFor="classe_id">Classe *</Label>
                <Select
                  value={formData.classe_id}
                  onValueChange={(value) => {
                    setFormData({ 
                      ...formData, 
                      classe_id: value
                    });
                  }}
                  disabled={!formData.centre_id}
                >
                  <SelectTrigger className={errors.classe_id ? 'border-destructive' : ''}>
                    <SelectValue placeholder="Sélectionner une classe" />
                  </SelectTrigger>
                  <SelectContent>
                    {classes.map((classe) => (
                      <SelectItem key={classe.id} value={classe.id}>
                        {classe.nom_classe}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {errors.classe_id && <p className="text-sm text-destructive mt-1">{errors.classe_id}</p>}
              </div>

              <div>
                <Label htmlFor="formation_id">Formation *</Label>
                <Select
                  value={formData.formation_id}
                  onValueChange={(value) => setFormData({ ...formData, formation_id: value, classe_id: '' })}
                >
                  <SelectTrigger className={errors.formation_id ? 'border-destructive' : ''}>
                    <SelectValue placeholder="Sélectionner une formation" />
                  </SelectTrigger>
                  <SelectContent>
                    {formations.map((formation) => (
                      <SelectItem key={formation.id} value={formation.id}>
                        {formation.titre} - {formation.prix} DH
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {errors.formation_id && <p className="text-sm text-destructive mt-1">{errors.formation_id}</p>}
              </div>
            </div>
          </div>

          <Separator />

          {/* Administrative Information */}
          <div>
            <h3 className="text-lg font-semibold mb-4">Informations Administratives</h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <Label htmlFor="numero_bon">Numéro de bon *</Label>
                <Input
                  id="numero_bon"
                  value={formData.numero_bon}
                  onChange={(e) => setFormData({ ...formData, numero_bon: e.target.value })}
                  className={errors.numero_bon ? 'border-destructive' : ''}
                />
                {errors.numero_bon && <p className="text-sm text-destructive mt-1">{errors.numero_bon}</p>}
              </div>

              <div>
                <Label htmlFor="avance">Avance (DH)</Label>
                <Input
                  id="avance"
                  type="number"
                  min="0"
                  step="0.01"
                  value={formData.avance}
                  onChange={(e) => setFormData({ ...formData, avance: e.target.value })}
                />
              </div>

              <div>
                <Label htmlFor="statut_compte">Statut de compte *</Label>
                <Select
                  value={formData.statut_compte}
                  onValueChange={(value) => setFormData({ ...formData, statut_compte: value })}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="valide">Valide</SelectItem>
                    <SelectItem value="non_valide">Non valide</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
          </div>

          {/* Actions */}
          <div className="flex justify-end space-x-2">
            <Button
              type="button"
              variant="outline"
              onClick={() => onOpenChange(false)}
              disabled={loading}
            >
              Annuler
            </Button>
            <Button type="submit" disabled={loading}>
              {loading ? 'Sauvegarde...' : 'Sauvegarder'}
            </Button>
          </div>
        </form>)}
      </DialogContent>
    </Dialog>
  );
}

export default EditStudentModal;