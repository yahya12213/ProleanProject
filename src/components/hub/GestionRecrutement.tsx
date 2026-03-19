import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import { 
  Plus, 
  User, 
  FileText, 
  Calendar, 
  Phone,
  Mail,
  Download,
  Eye,
  Edit,
  Trash2,
  MoreHorizontal,
  UserCheck,
  Clock
} from "lucide-react";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";

interface Candidat {
  id: string;
  nom: string;
  prenom: string;
  email: string;
  telephone: string;
  poste_souhaite: string;
  statut: "candidature" | "preselection" | "entretien" | "decision" | "embauche" | "refus";
  experience: string;
  formation: string;
  competences: string[];
  cv_url?: string;
  date_candidature: Date;
  date_derniere_maj: Date;
  notes: string;
  recruteur: string;
}

interface Entretien {
  id: string;
  candidat_id: string;
  date: Date;
  type: "technique" | "rh" | "manager";
  intervieweur: string;
  template_id?: string;
  notes?: string;
  evaluation?: number;
}

export function GestionRecrutement() {
  const [isCandidatDialogOpen, setIsCandidatDialogOpen] = useState(false);
  const [isEntretienDialogOpen, setIsEntretienDialogOpen] = useState(false);
  const [selectedCandidat, setSelectedCandidat] = useState<Candidat | null>(null);
  const [filterStatus, setFilterStatus] = useState("all");
  const [filterPoste, setFilterPoste] = useState("all");

  // Mock data
  const candidats: Candidat[] = [
    {
      id: "1",
      nom: "Dupuis",
      prenom: "Alice",
      email: "alice.dupuis@email.com",
      telephone: "06 12 34 56 78",
      poste_souhaite: "Formateur Digital",
      statut: "entretien",
      experience: "5 ans",
      formation: "Master Marketing Digital",
      competences: ["Marketing Digital", "Formation", "Adobe Suite"],
      cv_url: "/cv/alice-dupuis.pdf",
      date_candidature: new Date("2024-01-15"),
      date_derniere_maj: new Date("2024-01-20"),
      notes: "Profil très intéressant, expérience pertinente",
      recruteur: "Marie Martin"
    },
    {
      id: "2",
      nom: "Moreau",
      prenom: "Thomas",
      email: "thomas.moreau@email.com",
      telephone: "06 98 76 54 32",
      poste_souhaite: "Commercial Formation",
      statut: "preselection",
      experience: "3 ans",
      formation: "École de Commerce",
      competences: ["Vente", "Négociation", "CRM"],
      date_candidature: new Date("2024-01-18"),
      date_derniere_maj: new Date("2024-01-22"),
      notes: "Bon commercial, à creuser en entretien",
      recruteur: "Jean Dupont"
    },
    {
      id: "3",
      nom: "Rousseau",
      prenom: "Amélie",
      email: "amelie.rousseau@email.com",
      telephone: "06 11 22 33 44",
      poste_souhaite: "Assistante Pédagogique",
      statut: "decision",
      experience: "2 ans",
      formation: "BTS Assistant Manager",
      competences: ["Organisation", "Communication", "Bureautique"],
      date_candidature: new Date("2024-01-10"),
      date_derniere_maj: new Date("2024-01-25"),
      notes: "Excellents entretiens, recommandée pour embauche",
      recruteur: "Sophie Leroy"
    }
  ];

  const entretiens: Entretien[] = [
    {
      id: "1",
      candidat_id: "1",
      date: new Date("2024-01-22T14:00:00"),
      type: "technique",
      intervieweur: "Pierre Bernard",
      evaluation: 4,
      notes: "Très bon niveau technique"
    },
    {
      id: "2", 
      candidat_id: "3",
      date: new Date("2024-01-25T10:00:00"),
      type: "rh",
      intervieweur: "Marie Martin",
      evaluation: 5,
      notes: "Parfait fit culturel"
    }
  ];

  const templates_entretien = [
    { id: "1", nom: "Entretien Technique Formateur", type: "technique" },
    { id: "2", nom: "Entretien RH Standard", type: "rh" },
    { id: "3", nom: "Entretien Manager Commercial", type: "manager" }
  ];

  const postes_disponibles = [
    "Formateur Digital",
    "Commercial Formation", 
    "Assistante Pédagogique",
    "Responsable Pédagogique",
    "Développeur Web"
  ];

  const getStatusColor = (statut: string) => {
    switch (statut) {
      case "candidature": return "bg-gray-100 text-gray-800";
      case "preselection": return "bg-blue-100 text-blue-800";
      case "entretien": return "bg-yellow-100 text-yellow-800";
      case "decision": return "bg-orange-100 text-orange-800";
      case "embauche": return "bg-green-100 text-green-800";
      case "refus": return "bg-red-100 text-red-800";
      default: return "bg-gray-100 text-gray-800";
    }
  };

  const getStatusLabel = (statut: string) => {
    switch (statut) {
      case "candidature": return "Candidature";
      case "preselection": return "Présélection";
      case "entretien": return "Entretien";
      case "decision": return "Décision";
      case "embauche": return "Embauche";
      case "refus": return "Refus";
      default: return statut;
    }
  };

  const filteredCandidats = candidats.filter(candidat => {
    const matchesStatus = filterStatus === "all" || candidat.statut === filterStatus;
    const matchesPoste = filterPoste === "all" || candidat.poste_souhaite === filterPoste;
    return matchesStatus && matchesPoste;
  });

  const statistiques = {
    total: candidats.length,
    en_cours: candidats.filter(c => ["preselection", "entretien", "decision"].includes(c.statut)).length,
    embauches: candidats.filter(c => c.statut === "embauche").length,
    taux_reussite: Math.round((candidats.filter(c => c.statut === "embauche").length / candidats.length) * 100)
  };

  return (
    <div className="space-y-6">
      {/* Statistiques */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Total Candidatures</p>
                <p className="text-2xl font-bold">{statistiques.total}</p>
              </div>
              <User className="h-8 w-8 text-blue-600" />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">En Cours</p>
                <p className="text-2xl font-bold">{statistiques.en_cours}</p>
              </div>
              <Clock className="h-8 w-8 text-orange-600" />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Embauches</p>
                <p className="text-2xl font-bold">{statistiques.embauches}</p>
              </div>
              <UserCheck className="h-8 w-8 text-green-600" />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Taux Réussite</p>
                <p className="text-2xl font-bold">{statistiques.taux_reussite}%</p>
              </div>
              <Calendar className="h-8 w-8 text-purple-600" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Filtres et actions */}
      <div className="flex flex-col sm:flex-row gap-4 items-center justify-between">
        <div className="flex gap-4">
          <Select value={filterStatus} onValueChange={setFilterStatus}>
            <SelectTrigger className="w-40">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">Tous les statuts</SelectItem>
              <SelectItem value="candidature">Candidature</SelectItem>
              <SelectItem value="preselection">Présélection</SelectItem>
              <SelectItem value="entretien">Entretien</SelectItem>
              <SelectItem value="decision">Décision</SelectItem>
              <SelectItem value="embauche">Embauche</SelectItem>
              <SelectItem value="refus">Refus</SelectItem>
            </SelectContent>
          </Select>

          <Select value={filterPoste} onValueChange={setFilterPoste}>
            <SelectTrigger className="w-40">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">Tous les postes</SelectItem>
              {postes_disponibles.map((poste) => (
                <SelectItem key={poste} value={poste}>{poste}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <div className="flex gap-2">
          <Dialog open={isEntretienDialogOpen} onOpenChange={setIsEntretienDialogOpen}>
            <DialogTrigger asChild>
              <Button variant="outline">
                <Calendar className="h-4 w-4 mr-2" />
                Planifier Entretien
              </Button>
            </DialogTrigger>
            <DialogContent className="sm:max-w-lg">
              <DialogHeader>
                <DialogTitle>Planifier un entretien</DialogTitle>
                <DialogDescription>
                  Programmer un entretien avec un candidat
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-4">
                <div>
                  <Label>Candidat</Label>
                  <Select>
                    <SelectTrigger>
                      <SelectValue placeholder="Sélectionner un candidat" />
                    </SelectTrigger>
                    <SelectContent>
                      {candidats.map((candidat) => (
                        <SelectItem key={candidat.id} value={candidat.id}>
                          {candidat.prenom} {candidat.nom} - {candidat.poste_souhaite}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label>Type d'entretien</Label>
                    <Select>
                      <SelectTrigger>
                        <SelectValue placeholder="Type" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="technique">Technique</SelectItem>
                        <SelectItem value="rh">RH</SelectItem>
                        <SelectItem value="manager">Manager</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  
                  <div>
                    <Label>Template</Label>
                    <Select>
                      <SelectTrigger>
                        <SelectValue placeholder="Sélectionner" />
                      </SelectTrigger>
                      <SelectContent>
                        {templates_entretien.map((template) => (
                          <SelectItem key={template.id} value={template.id}>
                            {template.nom}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </div>
                
                <div>
                  <Label>Intervieweur</Label>
                  <Select>
                    <SelectTrigger>
                      <SelectValue placeholder="Sélectionner l'intervieweur" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="marie">Marie Martin</SelectItem>
                      <SelectItem value="jean">Jean Dupont</SelectItem>
                      <SelectItem value="sophie">Sophie Leroy</SelectItem>
                      <SelectItem value="pierre">Pierre Bernard</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label htmlFor="date">Date</Label>
                    <Input id="date" type="date" />
                  </div>
                  <div>
                    <Label htmlFor="heure">Heure</Label>
                    <Input id="heure" type="time" />
                  </div>
                </div>
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => setIsEntretienDialogOpen(false)}>
                  Annuler
                </Button>
                <Button onClick={() => setIsEntretienDialogOpen(false)}>
                  Planifier
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>

          <Dialog open={isCandidatDialogOpen} onOpenChange={setIsCandidatDialogOpen}>
            <DialogTrigger asChild>
              <Button>
                <Plus className="h-4 w-4 mr-2" />
                Nouveau Candidat
              </Button>
            </DialogTrigger>
            <DialogContent className="sm:max-w-lg">
              <DialogHeader>
                <DialogTitle>Ajouter un candidat</DialogTitle>
                <DialogDescription>
                  Créer une nouvelle fiche candidat
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label htmlFor="prenom">Prénom</Label>
                    <Input id="prenom" placeholder="Prénom" />
                  </div>
                  <div>
                    <Label htmlFor="nom">Nom</Label>
                    <Input id="nom" placeholder="Nom" />
                  </div>
                </div>
                
                <div>
                  <Label htmlFor="email">Email</Label>
                  <Input id="email" type="email" placeholder="Email" />
                </div>
                
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label htmlFor="telephone">Téléphone</Label>
                    <Input id="telephone" placeholder="06 12 34 56 78" />
                  </div>
                  <div>
                    <Label>Poste souhaité</Label>
                    <Select>
                      <SelectTrigger>
                        <SelectValue placeholder="Sélectionner" />
                      </SelectTrigger>
                      <SelectContent>
                        {postes_disponibles.map((poste) => (
                          <SelectItem key={poste} value={poste}>{poste}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </div>
                
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label htmlFor="experience">Expérience</Label>
                    <Input id="experience" placeholder="Ex: 3 ans" />
                  </div>
                  <div>
                    <Label htmlFor="formation">Formation</Label>
                    <Input id="formation" placeholder="Diplôme principal" />
                  </div>
                </div>
                
                <div>
                  <Label htmlFor="competences">Compétences</Label>
                  <Input id="competences" placeholder="Séparées par des virgules" />
                </div>
                
                <div>
                  <Label htmlFor="notes">Notes</Label>
                  <Textarea id="notes" placeholder="Notes sur le candidat" />
                </div>
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => setIsCandidatDialogOpen(false)}>
                  Annuler
                </Button>
                <Button onClick={() => setIsCandidatDialogOpen(false)}>
                  Créer le candidat
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </div>
      </div>

      {/* Tableau des candidats */}
      <Card>
        <CardHeader>
          <CardTitle>Pipeline de Recrutement</CardTitle>
          <CardDescription>
            Gestion et suivi des candidatures ({filteredCandidats.length} affichés)
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Candidat</TableHead>
                <TableHead>Poste</TableHead>
                <TableHead>Expérience</TableHead>
                <TableHead>Statut</TableHead>
                <TableHead>Recruteur</TableHead>
                <TableHead>Candidature</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredCandidats.map((candidat) => (
                <TableRow key={candidat.id}>
                  <TableCell>
                    <div>
                      <div className="font-medium">{candidat.prenom} {candidat.nom}</div>
                      <div className="text-sm text-muted-foreground">{candidat.email}</div>
                      <div className="text-sm text-muted-foreground">{candidat.telephone}</div>
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="font-medium">{candidat.poste_souhaite}</div>
                    <div className="text-sm text-muted-foreground">{candidat.formation}</div>
                  </TableCell>
                  <TableCell>{candidat.experience}</TableCell>
                  <TableCell>
                    <Badge className={getStatusColor(candidat.statut)}>
                      {getStatusLabel(candidat.statut)}
                    </Badge>
                  </TableCell>
                  <TableCell>{candidat.recruteur}</TableCell>
                  <TableCell>
                    {candidat.date_candidature.toLocaleDateString('fr-FR')}
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <Button variant="ghost" size="sm">
                        <Eye className="h-4 w-4" />
                      </Button>
                      {candidat.cv_url && (
                        <Button variant="ghost" size="sm">
                          <Download className="h-4 w-4" />
                        </Button>
                      )}
                      <Button variant="ghost" size="sm">
                        <Phone className="h-4 w-4" />
                      </Button>
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="ghost" size="sm">
                            <MoreHorizontal className="h-4 w-4" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <DropdownMenuItem>
                            <Edit className="h-4 w-4 mr-2" />
                            Modifier
                          </DropdownMenuItem>
                          <DropdownMenuItem>
                            <Calendar className="h-4 w-4 mr-2" />
                            Planifier entretien
                          </DropdownMenuItem>
                          <DropdownMenuItem>
                            <UserCheck className="h-4 w-4 mr-2" />
                            Proposer embauche
                          </DropdownMenuItem>
                          <DropdownMenuItem className="text-red-600">
                            <Trash2 className="h-4 w-4 mr-2" />
                            Refuser
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}