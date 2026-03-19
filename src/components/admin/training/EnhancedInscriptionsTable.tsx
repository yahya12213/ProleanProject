import React from 'react';
import { EnhancedCard } from '@/components/ui/enhanced-card';
import { EnhancedButton, ActionButton } from '@/components/ui/enhanced-button';
import { Badge } from '@/components/ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Checkbox } from '@/components/ui/checkbox';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { 
  MoreVertical, 
  Edit, 
  CreditCard, 
  FileText, 
  Phone, 
  Mail,
  Calendar,
  Award 
} from 'lucide-react';

interface Inscription {
  id: string;
  etudiant_id: string;
  date_inscription: string;
  statut_inscription: string;
  numero_bon?: string;
  avance?: number;
  statut_compte?: string;
  student_id_unique?: string;
  formation_id?: string;
  formations?: {
    id?: string;
    titre: string;
    prix: number;
  };
  etudiants: {
    id: string;
    nom: string;
    prenom: string;
    cin?: string;
    telephone?: string;
    email?: string;
    photo_url?: string;
    date_naissance?: string;
    lieu_naissance?: string;
    adresse?: string;
    whatsapp?: string;
  };
  paiements?: Array<{
    id: string;
    montant: number;
  }>;
}

interface EnhancedInscriptionsTableProps {
  inscriptions: Inscription[];
  selectedStudents: Set<string>;
  selectAll: boolean;
  onSelectAll: (checked: boolean) => void;
  onSelectStudent: (studentId: string, checked: boolean) => void;
  onEditStudent: (inscription: Inscription) => void;
  onAddPayment: (inscription: Inscription) => void;
  onViewPaymentHistory: (inscription: Inscription) => void;
  onGenerateDocuments: (inscriptions: Inscription[]) => void;
  onViewPhoto: (inscription: Inscription) => void;
  loading?: boolean;
}

const EnhancedInscriptionsTable: React.FC<EnhancedInscriptionsTableProps> = ({
  inscriptions,
  selectedStudents,
  selectAll,
  onSelectAll,
  onSelectStudent,
  onEditStudent,
  onAddPayment,
  onViewPaymentHistory,
  onGenerateDocuments,
  onViewPhoto,
  loading = false
}) => {
  
  const getStatusBadge = (status: string) => {
    const variants = {
      'en_attente': 'destructive',
      'confirmee': 'secondary',
      'validee': 'default',
      'annulee': 'outline',
      'terminee': 'outline'
    } as const;
    
    const labels = {
      'en_attente': 'En attente',
      'confirmee': 'Confirmée',
      'validee': 'Validée',
      'annulee': 'Annulée',
      'terminee': 'Terminée'
    };

    return (
      <Badge variant={variants[status as keyof typeof variants] || 'outline'}>
        {labels[status as keyof typeof labels] || status}
      </Badge>
    );
  };

  const getAccountStatusBadge = (status?: string) => {
    if (!status) return null;
    
    const variants = {
      'valide': 'default',
      'non_valide': 'destructive', 
      'en_cours': 'secondary',
      'suspendu': 'outline'
    } as const;
    
    const labels = {
      'valide': 'Validé',
      'non_valide': 'Non validé',
      'en_cours': 'En cours',
      'suspendu': 'Suspendu'
    };

    return (
      <Badge variant={variants[status as keyof typeof variants] || 'outline'} className="ml-2">
        {labels[status as keyof typeof labels] || status}
      </Badge>
    );
  };

  const getTotalPaiements = (paiements?: Array<{montant: number}>) => {
    return paiements?.reduce((sum, p) => sum + p.montant, 0) || 0;
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('fr-FR');
  };

  const getInitials = (nom: string, prenom: string) => {
    return `${nom.charAt(0)}${prenom.charAt(0)}`.toUpperCase();
  };

  if (loading) {
    return (
      <EnhancedCard variant="premium">
        <div className="p-6">
          <div className="animate-pulse space-y-4">
            {Array.from({ length: 5 }).map((_, i) => (
              <div key={i} className="flex items-center space-x-4">
                <div className="h-10 w-10 bg-muted rounded-full" />
                <div className="flex-1 space-y-2">
                  <div className="h-4 bg-muted rounded w-1/4" />
                  <div className="h-3 bg-muted rounded w-1/2" />
                </div>
                <div className="h-8 w-20 bg-muted rounded" />
              </div>
            ))}
          </div>
        </div>
      </EnhancedCard>
    );
  }

  if (inscriptions.length === 0) {
    return (
      <EnhancedCard variant="premium">
        <div className="p-12 text-center">
          <div className="mx-auto h-12 w-12 text-muted-foreground mb-4">
            <Award className="h-full w-full" />
          </div>
          <h3 className="text-lg font-semibold mb-2">Aucune inscription</h3>
          <p className="text-muted-foreground mb-6">
            Commencez par ajouter des étudiants à cette classe.
          </p>
          <EnhancedButton variant="premium">
            Ajouter un étudiant
          </EnhancedButton>
        </div>
      </EnhancedCard>
    );
  }

  return (
    <EnhancedCard variant="premium" className="overflow-hidden">
      <Table>
        <TableHeader>
          <TableRow className="border-b">
            <TableHead className="w-12">
              <Checkbox
                checked={selectAll}
                onCheckedChange={onSelectAll}
                aria-label="Sélectionner tout"
              />
            </TableHead>
            <TableHead>Étudiant</TableHead>
            <TableHead>Contact</TableHead>
            <TableHead>Formation</TableHead>
            <TableHead>Statut</TableHead>
            <TableHead>Paiements</TableHead>
            <TableHead>Date d'inscription</TableHead>
            <TableHead className="w-12">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {inscriptions.map((inscription) => {
            const etudiant = inscription.etudiants;
            const isSelected = selectedStudents.has(inscription.id);
            const totalPaiements = getTotalPaiements(inscription.paiements);
            const prixFormation = inscription.formations?.prix || 0;
            const avance = inscription.avance || 0;
            const resteDu = prixFormation - totalPaiements - avance;
            
            return (
              <TableRow 
                key={inscription.id}
                className={`hover:bg-muted/50 transition-colors ${isSelected ? 'bg-primary/5' : ''}`}
              >
                <TableCell>
                  <Checkbox
                    checked={isSelected}
                    onCheckedChange={(checked) => onSelectStudent(inscription.id, checked as boolean)}
                    aria-label={`Sélectionner ${etudiant.nom} ${etudiant.prenom}`}
                  />
                </TableCell>
                
                <TableCell>
                  <div className="flex items-center space-x-3">
                    <Avatar 
                      className="h-10 w-10 cursor-pointer hover:scale-105 transition-transform"
                      onClick={() => onViewPhoto(inscription)}
                    >
                      <AvatarImage src={etudiant.photo_url} alt={`${etudiant.nom} ${etudiant.prenom}`} />
                      <AvatarFallback className="bg-primary/10 text-primary font-semibold">
                        {getInitials(etudiant.nom, etudiant.prenom)}
                      </AvatarFallback>
                    </Avatar>
                    <div>
                      <div className="font-semibold text-foreground">
                        {etudiant.nom} {etudiant.prenom}
                      </div>
                      <div className="text-sm text-muted-foreground">
                        {inscription.student_id_unique || 'ID non généré'}
                      </div>
                      {etudiant.cin && (
                        <div className="text-xs text-muted-foreground">
                          CIN: {etudiant.cin}
                        </div>
                      )}
                    </div>
                  </div>
                </TableCell>
                
                <TableCell>
                  <div className="space-y-1">
                    {etudiant.telephone && (
                      <div className="flex items-center text-sm text-muted-foreground">
                        <Phone className="h-3 w-3 mr-2" />
                        {etudiant.telephone}
                      </div>
                    )}
                    {etudiant.email && (
                      <div className="flex items-center text-sm text-muted-foreground">
                        <Mail className="h-3 w-3 mr-2" />
                        {etudiant.email}
                      </div>
                    )}
                  </div>
                </TableCell>
                
                <TableCell>
                  <div>
                    <div className="font-medium text-sm">
                      {inscription.formations?.titre || 'Formation non définie'}
                    </div>
                    <div className="text-sm text-muted-foreground">
                      {prixFormation.toLocaleString()} DH
                    </div>
                  </div>
                </TableCell>
                
                <TableCell>
                  <div className="space-y-1">
                    {getStatusBadge(inscription.statut_inscription)}
                    {getAccountStatusBadge(inscription.statut_compte)}
                  </div>
                </TableCell>
                
                <TableCell>
                  <div className="space-y-1">
                    <div className="text-sm">
                      <span className="font-medium">{totalPaiements.toLocaleString()} DH</span>
                      <span className="text-muted-foreground"> / {prixFormation.toLocaleString()} DH</span>
                    </div>
                    {avance > 0 && (
                      <div className="text-xs text-muted-foreground">
                        Avance: {avance.toLocaleString()} DH
                      </div>
                    )}
                    {resteDu > 0 && (
                      <div className="text-xs text-orange-600">
                        Reste: {resteDu.toLocaleString()} DH
                      </div>
                    )}
                  </div>
                </TableCell>
                
                <TableCell>
                  <div className="flex items-center text-sm text-muted-foreground">
                    <Calendar className="h-3 w-3 mr-2" />
                    {formatDate(inscription.date_inscription)}
                  </div>
                </TableCell>
                
                <TableCell>
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <EnhancedButton variant="ghost" size="icon-sm">
                        <MoreVertical className="h-4 w-4" />
                      </EnhancedButton>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end" className="w-48">
                      <DropdownMenuItem onClick={() => onEditStudent(inscription)}>
                        <Edit className="h-4 w-4 mr-2" />
                        Modifier
                      </DropdownMenuItem>
                      <DropdownMenuItem onClick={() => onAddPayment(inscription)}>
                        <CreditCard className="h-4 w-4 mr-2" />
                        Ajouter paiement
                      </DropdownMenuItem>
                      <DropdownMenuItem onClick={() => onViewPaymentHistory(inscription)}>
                        <FileText className="h-4 w-4 mr-2" />
                        Historique paiements
                      </DropdownMenuItem>
                      <DropdownMenuItem onClick={() => onGenerateDocuments([inscription])}>
                        <Award className="h-4 w-4 mr-2" />
                        Générer documents
                      </DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                </TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
    </EnhancedCard>
  );
};

export default EnhancedInscriptionsTable;