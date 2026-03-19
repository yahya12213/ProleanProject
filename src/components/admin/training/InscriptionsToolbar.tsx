import React from 'react';
import { EnhancedButton, ActionButton } from '@/components/ui/enhanced-button';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Plus, Search, Filter, Download, Upload } from 'lucide-react';

interface InscriptionsToolbarProps {
  searchTerm: string;
  onSearchChange: (value: string) => void;
  statusFilter: string;
  onStatusFilterChange: (value: string) => void;
  accountStatusFilter: string;
  onAccountStatusFilterChange: (value: string) => void;
  onAddStudent: () => void;
  onExport?: () => void;
  onImport?: () => void;
  className?: string;
}

const InscriptionsToolbar: React.FC<InscriptionsToolbarProps> = ({
  searchTerm,
  onSearchChange,
  statusFilter, 
  onStatusFilterChange,
  accountStatusFilter,
  onAccountStatusFilterChange,
  onAddStudent,
  onExport,
  onImport,
  className
}) => {
  return (
    <div className={`bg-white rounded-lg border p-4 space-y-4 ${className}`}>
      {/* Ligne principale avec recherche et actions */}
      <div className="flex flex-col sm:flex-row gap-4 items-start sm:items-center justify-between">
        {/* Barre de recherche */}
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-muted-foreground h-4 w-4" />
          <Input
            placeholder="Rechercher par nom, CIN, email..."
            value={searchTerm}
            onChange={(e) => onSearchChange(e.target.value)}
            className="pl-10"
          />
        </div>

        {/* Actions principales */}
        <div className="flex gap-2">
          {onImport && (
            <EnhancedButton 
              variant="outline" 
              size="sm"
              leftIcon={<Upload className="h-4 w-4" />}
              onClick={onImport}
            >
              Importer
            </EnhancedButton>
          )}
          
          {onExport && (
            <EnhancedButton 
              variant="outline" 
              size="sm"
              leftIcon={<Download className="h-4 w-4" />}
              onClick={onExport}
            >
              Exporter
            </EnhancedButton>
          )}
          
          <EnhancedButton
            variant="premium"
            size="sm"
            leftIcon={<Plus className="h-4 w-4" />}
            onClick={onAddStudent}
          >
            Nouvel Étudiant
          </EnhancedButton>
        </div>
      </div>

      {/* Filtres */}
      <div className="flex flex-col sm:flex-row gap-4">
        <div className="flex items-center gap-2">
          <Filter className="h-4 w-4 text-muted-foreground" />
          <span className="text-sm font-medium text-muted-foreground">Filtres:</span>
        </div>
        
        <div className="flex gap-4 flex-1">
          <Select value={statusFilter} onValueChange={onStatusFilterChange}>
            <SelectTrigger className="w-48">
              <SelectValue placeholder="Statut inscription" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="tous">Tous les statuts</SelectItem>
              <SelectItem value="en_attente">En attente</SelectItem>
              <SelectItem value="confirmee">Confirmée</SelectItem>
              <SelectItem value="validee">Validée</SelectItem>
              <SelectItem value="annulee">Annulée</SelectItem>
              <SelectItem value="terminee">Terminée</SelectItem>
            </SelectContent>
          </Select>

          <Select value={accountStatusFilter} onValueChange={onAccountStatusFilterChange}>
            <SelectTrigger className="w-48">
              <SelectValue placeholder="Statut compte" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="tous">Tous les comptes</SelectItem>
              <SelectItem value="valide">Validé</SelectItem>
              <SelectItem value="non_valide">Non validé</SelectItem>
              <SelectItem value="en_cours">En cours</SelectItem>
              <SelectItem value="suspendu">Suspendu</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>
    </div>
  );
};

export default InscriptionsToolbar;