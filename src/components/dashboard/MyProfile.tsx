import React, { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { useToast } from '@/hooks/use-toast';
import { User, Mail, Phone, MapPin, Calendar, Award, Eye, EyeOff, Camera, Save } from 'lucide-react';

export const MyProfile = () => {
  const { toast } = useToast();
  const [isEditing, setIsEditing] = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  const [profile, setProfile] = useState({
    prenom: "Jean",
    nom: "Dupont",
    email: "jean.dupont@email.com",
    telephone: "+33 6 12 34 56 78",
    adresse: "123 Rue de la Paix",
    ville: "Paris",
    codePostal: "75001",
    pays: "France",
    dateNaissance: "1990-05-15",
    profession: "Chef de projet",
    entreprise: "TechCorp",
    linkedin: "linkedin.com/in/jeandupont",
    bio: "Chef de projet passionné par l'innovation et le management d'équipe. 10 ans d'expérience dans le secteur technologique.",
    avatar: "/api/placeholder/150/150"
  });

  const competences = [
    { nom: "Project Management", niveau: "Expert", couleur: "bg-green-500" },
    { nom: "Data Analysis", niveau: "Avancé", couleur: "bg-blue-500" },
    { nom: "Leadership", niveau: "Expert", couleur: "bg-green-500" },
    { nom: "Digital Marketing", niveau: "Intermédiaire", couleur: "bg-yellow-500" },
    { nom: "Lean Management", niveau: "Débutant", couleur: "bg-red-500" }
  ];

  const certifications = [
    {
      nom: "Project Management Professional (PMP)",
      organisme: "PMI",
      dateObtention: "2024-01-15",
      valide: true,
      expiration: "2027-01-15"
    },
    {
      nom: "Digital Marketing Strategy",
      organisme: "PROLEAN Formation",
      dateObtention: "2024-01-20",
      valide: true,
      expiration: null
    },
    {
      nom: "Leadership & Communication",
      organisme: "PROLEAN Formation",
      dateObtention: "2023-12-30",
      valide: true,
      expiration: null
    }
  ];

  const handleSave = () => {
    setIsEditing(false);
    toast({
      title: "Profil mis à jour",
      description: "Vos informations ont été sauvegardées avec succès.",
    });
  };

  const handleCancel = () => {
    setIsEditing(false);
    // Reset changes logic here
  };

  return (
    <div className="space-y-6">
      <Tabs defaultValue="informations" className="w-full">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="informations">Informations</TabsTrigger>
          <TabsTrigger value="competences">Compétences</TabsTrigger>
          <TabsTrigger value="certifications">Certifications</TabsTrigger>
          <TabsTrigger value="securite">Sécurité</TabsTrigger>
        </TabsList>

        <TabsContent value="informations" className="mt-6">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Photo de profil */}
            <Card>
              <CardHeader>
                <CardTitle>Photo de profil</CardTitle>
              </CardHeader>
              <CardContent className="text-center space-y-4">
                <Avatar className="w-32 h-32 mx-auto">
                  <AvatarImage src={profile.avatar} alt="Profile" />
                  <AvatarFallback className="text-2xl">
                    {profile.prenom[0]}{profile.nom[0]}
                  </AvatarFallback>
                </Avatar>
                <Button variant="outline" size="sm">
                  <Camera className="h-4 w-4 mr-2" />
                  Changer la photo
                </Button>
              </CardContent>
            </Card>

            {/* Informations personnelles */}
            <Card className="lg:col-span-2">
              <CardHeader className="flex flex-row items-center justify-between">
                <CardTitle>Informations personnelles</CardTitle>
                <Button
                  variant={isEditing ? "destructive" : "outline"}
                  size="sm"
                  onClick={isEditing ? handleCancel : () => setIsEditing(true)}
                >
                  {isEditing ? "Annuler" : "Modifier"}
                </Button>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label htmlFor="prenom">Prénom</Label>
                    <Input
                      id="prenom"
                      value={profile.prenom}
                      disabled={!isEditing}
                      onChange={(e) => setProfile({...profile, prenom: e.target.value})}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="nom">Nom</Label>
                    <Input
                      id="nom"
                      value={profile.nom}
                      disabled={!isEditing}
                      onChange={(e) => setProfile({...profile, nom: e.target.value})}
                    />
                  </div>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="email">Email</Label>
                  <Input
                    id="email"
                    type="email"
                    value={profile.email}
                    disabled={!isEditing}
                    onChange={(e) => setProfile({...profile, email: e.target.value})}
                  />
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label htmlFor="telephone">Téléphone</Label>
                    <Input
                      id="telephone"
                      value={profile.telephone}
                      disabled={!isEditing}
                      onChange={(e) => setProfile({...profile, telephone: e.target.value})}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="dateNaissance">Date de naissance</Label>
                    <Input
                      id="dateNaissance"
                      type="date"
                      value={profile.dateNaissance}
                      disabled={!isEditing}
                      onChange={(e) => setProfile({...profile, dateNaissance: e.target.value})}
                    />
                  </div>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="adresse">Adresse</Label>
                  <Input
                    id="adresse"
                    value={profile.adresse}
                    disabled={!isEditing}
                    onChange={(e) => setProfile({...profile, adresse: e.target.value})}
                  />
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="space-y-2">
                    <Label htmlFor="ville">Ville</Label>
                    <Input
                      id="ville"
                      value={profile.ville}
                      disabled={!isEditing}
                      onChange={(e) => setProfile({...profile, ville: e.target.value})}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="codePostal">Code postal</Label>
                    <Input
                      id="codePostal"
                      value={profile.codePostal}
                      disabled={!isEditing}
                      onChange={(e) => setProfile({...profile, codePostal: e.target.value})}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="pays">Pays</Label>
                    <Select disabled={!isEditing} value={profile.pays}>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="France">France</SelectItem>
                        <SelectItem value="Belgique">Belgique</SelectItem>
                        <SelectItem value="Suisse">Suisse</SelectItem>
                        <SelectItem value="Canada">Canada</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label htmlFor="profession">Profession</Label>
                    <Input
                      id="profession"
                      value={profile.profession}
                      disabled={!isEditing}
                      onChange={(e) => setProfile({...profile, profession: e.target.value})}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="entreprise">Entreprise</Label>
                    <Input
                      id="entreprise"
                      value={profile.entreprise}
                      disabled={!isEditing}
                      onChange={(e) => setProfile({...profile, entreprise: e.target.value})}
                    />
                  </div>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="linkedin">LinkedIn</Label>
                  <Input
                    id="linkedin"
                    value={profile.linkedin}
                    disabled={!isEditing}
                    onChange={(e) => setProfile({...profile, linkedin: e.target.value})}
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="bio">Biographie</Label>
                  <Textarea
                    id="bio"
                    value={profile.bio}
                    disabled={!isEditing}
                    onChange={(e) => setProfile({...profile, bio: e.target.value})}
                    rows={4}
                  />
                </div>

                {isEditing && (
                  <div className="flex justify-end">
                    <Button onClick={handleSave}>
                      <Save className="h-4 w-4 mr-2" />
                      Sauvegarder
                    </Button>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="competences" className="mt-6">
          <Card>
            <CardHeader>
              <CardTitle>Mes compétences</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {competences.map((competence, index) => (
                  <div key={index} className="flex items-center justify-between p-4 border rounded-lg">
                    <div className="flex items-center gap-3">
                      <div className={`w-3 h-3 rounded-full ${competence.couleur}`} />
                      <span className="font-medium">{competence.nom}</span>
                    </div>
                    <Badge variant="outline">{competence.niveau}</Badge>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="certifications" className="mt-6">
          <Card>
            <CardHeader>
              <CardTitle>Mes certifications</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {certifications.map((cert, index) => (
                <div key={index} className="flex items-center justify-between p-4 border rounded-lg">
                  <div className="space-y-1">
                    <div className="flex items-center gap-3">
                      <Award className="h-5 w-5 text-yellow-500" />
                      <h4 className="font-semibold">{cert.nom}</h4>
                      {cert.valide && <Badge variant="default">Valide</Badge>}
                    </div>
                    <p className="text-sm text-muted-foreground">{cert.organisme}</p>
                    <div className="text-xs text-muted-foreground">
                      Obtenu le {new Date(cert.dateObtention).toLocaleDateString('fr-FR')}
                      {cert.expiration && (
                        <span> • Expire le {new Date(cert.expiration).toLocaleDateString('fr-FR')}</span>
                      )}
                    </div>
                  </div>
                  <Button variant="outline" size="sm">
                    Télécharger
                  </Button>
                </div>
              ))}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="securite" className="mt-6">
          <Card>
            <CardHeader>
              <CardTitle>Sécurité et confidentialité</CardTitle>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-4">
                <h4 className="font-medium">Changer le mot de passe</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label htmlFor="currentPassword">Mot de passe actuel</Label>
                    <div className="relative">
                      <Input
                        id="currentPassword"
                        type={showPassword ? "text" : "password"}
                        placeholder="••••••••"
                      />
                      <Button
                        type="button"
                        variant="ghost"
                        size="icon"
                        className="absolute right-2 top-1/2 -translate-y-1/2"
                        onClick={() => setShowPassword(!showPassword)}
                      >
                        {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                      </Button>
                    </div>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="newPassword">Nouveau mot de passe</Label>
                    <Input
                      id="newPassword"
                      type="password"
                      placeholder="••••••••"
                    />
                  </div>
                </div>
                <Button>Mettre à jour le mot de passe</Button>
              </div>

              <div className="border-t pt-6">
                <h4 className="font-medium mb-4">Préférences de confidentialité</h4>
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span>Profil visible par les autres apprenants</span>
                    <input type="checkbox" defaultChecked className="rounded" />
                  </div>
                  <div className="flex items-center justify-between">
                    <span>Recevoir des notifications par email</span>
                    <input type="checkbox" defaultChecked className="rounded" />
                  </div>
                  <div className="flex items-center justify-between">
                    <span>Partager ma progression avec mon entreprise</span>
                    <input type="checkbox" className="rounded" />
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};