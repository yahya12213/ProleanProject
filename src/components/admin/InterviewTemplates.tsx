import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger } from "@/components/ui/alert-dialog";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useToast } from "@/hooks/use-toast";
import { FileText, Plus, Edit, Trash2, List, Move, X } from "lucide-react";

interface Question {
  id: string;
  texte: string;
  type: 'texte' | 'choix_multiple' | 'notation' | 'oui_non';
  options?: string[];
  obligatoire: boolean;
}

interface Section {
  id: string;
  titre: string;
  description?: string;
  ordre: number;
  questions: Question[];
}

interface FicheEntretienModele {
  id: string;
  nom: string;
  description?: string;
  type_poste: string;
  sections: Section[];
  created_at: string;
}

const InterviewTemplates = () => {
  const [templates, setTemplates] = useState<FicheEntretienModele[]>([]);
  const [loading, setLoading] = useState(true);
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [editingTemplate, setEditingTemplate] = useState<FicheEntretienModele | null>(null);
  const { toast } = useToast();

  // Form state
  const [formData, setFormData] = useState({
    nom: "",
    description: "",
    type_poste: "",
    sections: [] as Section[]
  });

  const typesPoste = [
    "Commercial",
    "Manager",
    "Développeur",
    "RH",
    "Comptable",
    "Marketing",
    "Consultant",
    "Stagiaire"
  ];

  const typesQuestion = [
    { value: "texte", label: "Texte libre" },
    { value: "choix_multiple", label: "Choix multiple" },
    { value: "notation", label: "Notation (1-5)" },
    { value: "oui_non", label: "Oui/Non" }
  ];

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      
      // Mock templates data
      const mockTemplates: FicheEntretienModele[] = [
        {
          id: "1",
          nom: "Entretien Commercial - Junior",
          description: "Fiche d'entretien pour les postes commerciaux débutants",
          type_poste: "Commercial",
          sections: [
            {
              id: "1",
              titre: "Expérience professionnelle",
              description: "Évaluation du parcours professionnel",
              ordre: 1,
              questions: [
                {
                  id: "1",
                  texte: "Décrivez votre expérience commerciale précédente",
                  type: "texte",
                  obligatoire: true
                },
                {
                  id: "2",
                  texte: "Quelle est votre approche pour convaincre un client réticent ?",
                  type: "texte",
                  obligatoire: true
                }
              ]
            },
            {
              id: "2",
              titre: "Compétences techniques",
              ordre: 2,
              questions: [
                {
                  id: "3",
                  texte: "Maîtrise des outils CRM",
                  type: "notation",
                  obligatoire: false
                },
                {
                  id: "4",
                  texte: "A-t-il de l'expérience en prospection téléphonique ?",
                  type: "oui_non",
                  obligatoire: true
                }
              ]
            }
          ],
          created_at: new Date().toISOString()
        },
        {
          id: "2",
          nom: "Entretien Manager - Senior",
          description: "Évaluation pour les postes de management",
          type_poste: "Manager",
          sections: [
            {
              id: "3",
              titre: "Leadership",
              ordre: 1,
              questions: [
                {
                  id: "5",
                  texte: "Comment gérez-vous les conflits dans votre équipe ?",
                  type: "texte",
                  obligatoire: true
                },
                {
                  id: "6",
                  texte: "Style de management préféré",
                  type: "choix_multiple",
                  options: ["Directif", "Participatif", "Délégatif", "Transformationnel"],
                  obligatoire: true
                }
              ]
            }
          ],
          created_at: new Date().toISOString()
        }
      ];

      setTemplates(mockTemplates);

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

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    try {
      if (editingTemplate) {
        setTemplates(templates.map(template => 
          template.id === editingTemplate.id 
            ? {
                ...template,
                nom: formData.nom,
                description: formData.description,
                type_poste: formData.type_poste,
                sections: formData.sections
              }
            : template
        ));
        toast({ title: "Succès", description: "Modèle modifié avec succès" });
      } else {
        const newTemplate: FicheEntretienModele = {
          id: Date.now().toString(),
          nom: formData.nom,
          description: formData.description,
          type_poste: formData.type_poste,
          sections: formData.sections,
          created_at: new Date().toISOString()
        };
        setTemplates([...templates, newTemplate]);
        toast({ title: "Succès", description: "Modèle créé avec succès" });
      }

      setIsDialogOpen(false);
      resetForm();
    } catch (error) {
      toast({ title: "Erreur", description: "Impossible de sauvegarder le modèle", variant: "destructive" });
    }
  };

  const handleDelete = async (templateId: string) => {
    try {
      setTemplates(templates.filter(template => template.id !== templateId));
      toast({ title: "Succès", description: "Modèle supprimé avec succès" });
    } catch (error) {
      toast({ title: "Erreur", description: "Impossible de supprimer le modèle", variant: "destructive" });
    }
  };

  const resetForm = () => {
    setFormData({
      nom: "",
      description: "",
      type_poste: "",
      sections: []
    });
    setEditingTemplate(null);
  };

  const openEditDialog = (template: FicheEntretienModele) => {
    setEditingTemplate(template);
    setFormData({
      nom: template.nom,
      description: template.description || "",
      type_poste: template.type_poste,
      sections: template.sections
    });
    setIsDialogOpen(true);
  };

  const addSection = () => {
    const newSection: Section = {
      id: Date.now().toString(),
      titre: "",
      description: "",
      ordre: formData.sections.length + 1,
      questions: []
    };
    setFormData({
      ...formData,
      sections: [...formData.sections, newSection]
    });
  };

  const updateSection = (sectionIndex: number, field: keyof Section, value: any) => {
    const updatedSections = formData.sections.map((section, i) => 
      i === sectionIndex ? { ...section, [field]: value } : section
    );
    setFormData({ ...formData, sections: updatedSections });
  };

  const removeSection = (sectionIndex: number) => {
    const updatedSections = formData.sections
      .filter((_, i) => i !== sectionIndex)
      .map((section, i) => ({ ...section, ordre: i + 1 }));
    setFormData({ ...formData, sections: updatedSections });
  };

  const addQuestion = (sectionIndex: number) => {
    const newQuestion: Question = {
      id: Date.now().toString(),
      texte: "",
      type: "texte",
      obligatoire: false
    };
    
    const updatedSections = formData.sections.map((section, i) => 
      i === sectionIndex 
        ? { ...section, questions: [...section.questions, newQuestion] }
        : section
    );
    setFormData({ ...formData, sections: updatedSections });
  };

  const updateQuestion = (sectionIndex: number, questionIndex: number, field: keyof Question, value: any) => {
    const updatedSections = formData.sections.map((section, i) => 
      i === sectionIndex 
        ? {
            ...section,
            questions: section.questions.map((question, j) => 
              j === questionIndex ? { ...question, [field]: value } : question
            )
          }
        : section
    );
    setFormData({ ...formData, sections: updatedSections });
  };

  const removeQuestion = (sectionIndex: number, questionIndex: number) => {
    const updatedSections = formData.sections.map((section, i) => 
      i === sectionIndex 
        ? {
            ...section,
            questions: section.questions.filter((_, j) => j !== questionIndex)
          }
        : section
    );
    setFormData({ ...formData, sections: updatedSections });
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="text-center">
          <FileText className="h-12 w-12 mx-auto mb-4 text-muted-foreground animate-pulse" />
          <p className="text-muted-foreground">Chargement des modèles...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h3 className="text-lg font-semibold">Fiches d'Entretien</h3>
          <p className="text-sm text-muted-foreground">
            Standardisez les processus de recrutement avec des modèles d'entretien
          </p>
        </div>
        
        <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
          <DialogTrigger asChild>
            <Button onClick={resetForm} className="gap-2">
              <Plus className="h-4 w-4" />
              Créer un modèle
            </Button>
          </DialogTrigger>
          
          <DialogContent className="max-w-4xl max-h-[80vh] overflow-y-auto">
            <form onSubmit={handleSubmit}>
              <DialogHeader>
                <DialogTitle>
                  {editingTemplate ? "Modifier le modèle" : "Nouveau modèle d'entretien"}
                </DialogTitle>
                <DialogDescription>
                  Créez des modèles réutilisables pour vos entretiens de recrutement
                </DialogDescription>
              </DialogHeader>

              <div className="grid gap-6 py-4">
                {/* Basic Info */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <Label htmlFor="nom">Nom du modèle *</Label>
                    <Input
                      id="nom"
                      value={formData.nom}
                      onChange={(e) => setFormData({...formData, nom: e.target.value})}
                      required
                    />
                  </div>
                  <div>
                    <Label htmlFor="type_poste">Type de poste *</Label>
                    <Select value={formData.type_poste} onValueChange={(value) => setFormData({...formData, type_poste: value})}>
                      <SelectTrigger>
                        <SelectValue placeholder="Sélectionner un type" />
                      </SelectTrigger>
                      <SelectContent>
                        {typesPoste.map((type) => (
                          <SelectItem key={type} value={type}>
                            {type}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </div>

                <div>
                  <Label htmlFor="description">Description</Label>
                  <Textarea
                    id="description"
                    value={formData.description}
                    onChange={(e) => setFormData({...formData, description: e.target.value})}
                    rows={2}
                  />
                </div>

                {/* Sections */}
                <Card>
                  <CardHeader>
                    <div className="flex items-center justify-between">
                      <CardTitle className="text-base">Sections d'entretien</CardTitle>
                      <Button type="button" onClick={addSection} size="sm" className="gap-2">
                        <Plus className="h-4 w-4" />
                        Ajouter une section
                      </Button>
                    </div>
                  </CardHeader>
                  <CardContent>
                    {formData.sections.length === 0 ? (
                      <div className="text-center py-8 text-muted-foreground">
                        <List className="h-8 w-8 mx-auto mb-2" />
                        <p>Aucune section définie. Ajoutez une première section.</p>
                      </div>
                    ) : (
                      <div className="space-y-4">
                        {formData.sections.map((section, sectionIndex) => (
                          <Card key={section.id}>
                            <CardHeader className="pb-3">
                              <div className="flex items-center justify-between">
                                <div className="flex-1 grid grid-cols-2 gap-4">
                                  <Input
                                    placeholder="Titre de la section *"
                                    value={section.titre}
                                    onChange={(e) => updateSection(sectionIndex, 'titre', e.target.value)}
                                  />
                                  <Input
                                    placeholder="Description (optionnel)"
                                    value={section.description || ""}
                                    onChange={(e) => updateSection(sectionIndex, 'description', e.target.value)}
                                  />
                                </div>
                                <Button
                                  type="button"
                                  variant="outline"
                                  size="sm"
                                  onClick={() => removeSection(sectionIndex)}
                                  className="ml-2"
                                >
                                  <X className="h-4 w-4" />
                                </Button>
                              </div>
                            </CardHeader>
                            <CardContent>
                              <div className="space-y-3">
                                <div className="flex items-center justify-between">
                                  <Label className="text-sm font-medium">Questions</Label>
                                  <Button
                                    type="button"
                                    onClick={() => addQuestion(sectionIndex)}
                                    size="sm"
                                    variant="outline"
                                    className="gap-1"
                                  >
                                    <Plus className="h-3 w-3" />
                                    Question
                                  </Button>
                                </div>
                                
                                {section.questions.map((question, questionIndex) => (
                                  <div key={question.id} className="p-3 border rounded-lg space-y-2">
                                    <div className="flex items-center justify-between">
                                      <Input
                                        placeholder="Texte de la question *"
                                        value={question.texte}
                                        onChange={(e) => updateQuestion(sectionIndex, questionIndex, 'texte', e.target.value)}
                                        className="flex-1"
                                      />
                                      <Button
                                        type="button"
                                        variant="outline"
                                        size="sm"
                                        onClick={() => removeQuestion(sectionIndex, questionIndex)}
                                        className="ml-2"
                                      >
                                        <X className="h-4 w-4" />
                                      </Button>
                                    </div>
                                    
                                    <div className="grid grid-cols-2 gap-2">
                                      <Select 
                                        value={question.type} 
                                        onValueChange={(value) => updateQuestion(sectionIndex, questionIndex, 'type', value)}
                                      >
                                        <SelectTrigger className="h-8">
                                          <SelectValue />
                                        </SelectTrigger>
                                        <SelectContent>
                                          {typesQuestion.map((type) => (
                                            <SelectItem key={type.value} value={type.value}>
                                              {type.label}
                                            </SelectItem>
                                          ))}
                                        </SelectContent>
                                      </Select>
                                      
                                      <div className="flex items-center space-x-2">
                                        <input
                                          type="checkbox"
                                          id={`obligatoire-${question.id}`}
                                          checked={question.obligatoire}
                                          onChange={(e) => updateQuestion(sectionIndex, questionIndex, 'obligatoire', e.target.checked)}
                                          className="rounded"
                                        />
                                        <Label htmlFor={`obligatoire-${question.id}`} className="text-xs">
                                          Obligatoire
                                        </Label>
                                      </div>
                                    </div>
                                    
                                    {question.type === 'choix_multiple' && (
                                      <Textarea
                                        placeholder="Options (une par ligne)"
                                        value={question.options?.join('\n') || ""}
                                        onChange={(e) => updateQuestion(sectionIndex, questionIndex, 'options', e.target.value.split('\n').filter(o => o.trim()))}
                                        rows={3}
                                        className="text-sm"
                                      />
                                    )}
                                  </div>
                                ))}
                                
                                {section.questions.length === 0 && (
                                  <div className="text-center py-4 text-muted-foreground text-sm">
                                    Aucune question dans cette section
                                  </div>
                                )}
                              </div>
                            </CardContent>
                          </Card>
                        ))}
                      </div>
                    )}
                  </CardContent>
                </Card>
              </div>

              <DialogFooter>
                <Button type="button" variant="outline" onClick={() => setIsDialogOpen(false)}>
                  Annuler
                </Button>
                <Button type="submit">
                  {editingTemplate ? "Modifier" : "Créer"}
                </Button>
              </DialogFooter>
            </form>
          </DialogContent>
        </Dialog>
      </div>

      {/* Templates Table */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FileText className="h-5 w-5" />
            Modèles d'entretien ({templates.length})
          </CardTitle>
          <CardDescription>
            Liste de tous les modèles de fiches d'entretien
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Modèle</TableHead>
                <TableHead>Type de poste</TableHead>
                <TableHead>Sections</TableHead>
                <TableHead>Questions</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {templates.map((template) => {
                const totalQuestions = template.sections.reduce((total, section) => total + section.questions.length, 0);
                
                return (
                  <TableRow key={template.id}>
                    <TableCell>
                      <div className="flex items-center gap-3">
                        <div className="p-2 bg-primary/10 rounded-lg">
                          <FileText className="h-4 w-4 text-primary" />
                        </div>
                        <div>
                          <div className="font-medium">{template.nom}</div>
                          {template.description && (
                            <div className="text-sm text-muted-foreground max-w-xs truncate">
                              {template.description}
                            </div>
                          )}
                        </div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="secondary">{template.type_poste}</Badge>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline">{template.sections.length} section(s)</Badge>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline">{totalQuestions} question(s)</Badge>
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex gap-2 justify-end">
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => openEditDialog(template)}
                        >
                          <Edit className="h-4 w-4" />
                        </Button>
                        
                        <AlertDialog>
                          <AlertDialogTrigger asChild>
                            <Button variant="outline" size="sm">
                              <Trash2 className="h-4 w-4" />
                            </Button>
                          </AlertDialogTrigger>
                          <AlertDialogContent>
                            <AlertDialogHeader>
                              <AlertDialogTitle>Confirmer la suppression</AlertDialogTitle>
                              <AlertDialogDescription>
                                Êtes-vous sûr de vouloir supprimer le modèle "{template.nom}" ? 
                                Cette action est irréversible.
                              </AlertDialogDescription>
                            </AlertDialogHeader>
                            <AlertDialogFooter>
                              <AlertDialogCancel>Annuler</AlertDialogCancel>
                              <AlertDialogAction 
                                onClick={() => handleDelete(template.id)}
                                className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                              >
                                Supprimer
                              </AlertDialogAction>
                            </AlertDialogFooter>
                          </AlertDialogContent>
                        </AlertDialog>
                      </div>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
};

export default InterviewTemplates;