import { useState } from "react";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Checkbox } from "@/components/ui/checkbox";
import { useToast } from "@/hooks/use-toast";
import { Download, FileSpreadsheet, FileText } from "lucide-react";
import * as XLSX from 'xlsx';
import { format } from "date-fns";
import fr from "date-fns/locale/fr";

interface Pointage {
  id: string;
  type_pointage: string;
  timestamp_pointage: string;
  localisation?: string;
  notes?: string;
  ecart_minutes?: number;
  heures_reelles?: number;
  heures_configurees?: number;
  heure_configuree_entree?: string;
  heure_configuree_sortie?: string;
}

interface ExportOptions {
  format: 'excel' | 'csv';
  includeNotes: boolean;
  includeLocalisation: boolean;
  dateFormat: 'fr' | 'iso';
}

interface PointageExportModalProps {
  isOpen: boolean;
  onClose: () => void;
  pointages: Pointage[];
  selectedYear: string;
  selectedMonth: string;
}

export function PointageExportModal({ 
  isOpen, 
  onClose, 
  pointages, 
  selectedYear, 
  selectedMonth 
}: PointageExportModalProps) {
  const [exportOptions, setExportOptions] = useState<ExportOptions>({
    format: 'excel',
    includeNotes: true,
    includeLocalisation: true,
    dateFormat: 'fr'
  });
  const { toast } = useToast();

  const formatPointageForExport = (pointage: Pointage) => {
    const date = new Date(pointage.timestamp_pointage);
    const formattedDate = exportOptions.dateFormat === 'fr' 
      ? format(date, "dd/MM/yyyy", { locale: fr })
      : format(date, "yyyy-MM-dd");
    
    // Pour les pointages virtuels (week-end, jours fériés), utiliser 00:00:00
    // au lieu de l'heure UTC convertie en heure locale
    let formattedTime = format(date, "HH:mm:ss");
    if (pointage.notes?.includes('Week-end') || pointage.notes?.includes('Jour férié') || pointage.notes?.includes('Aucun pointage')) {
      formattedTime = "00:00:00";
    }

    const typeLabels: Record<string, string> = {
      entree: "Entrée",
      sortie: "Sortie", 
      pause_debut: "Début pause",
      pause_fin: "Fin pause"
    };

    const exportData: any = {
      Date: formattedDate,
      Heure: formattedTime,
      Type: typeLabels[pointage.type_pointage] || pointage.type_pointage,
      "Jour de la semaine": format(date, "EEEE", { locale: fr }),
      "Heure Configurée": pointage.type_pointage === 'entree' ? pointage.heure_configuree_entree || '' : pointage.heure_configuree_sortie || '',
      "Écart (min)": pointage.ecart_minutes || 0,
      "Heures Configurées": pointage.heures_configurees || '',
      "Heures Réelles": pointage.heures_reelles || '',
    };

    if (exportOptions.includeLocalisation) {
      exportData.Localisation = pointage.localisation || "Non spécifié";
    }

    if (exportOptions.includeNotes) {
      exportData.Notes = pointage.notes || "";
    }

    return exportData;
  };

  const generateFileName = () => {
    const now = new Date();
    const timestamp = format(now, "yyyyMMdd_HHmm");
    let period = "";
    
    if (selectedYear !== "all" && selectedMonth !== "all") {
      const monthNames = [
        "janvier", "février", "mars", "avril", "mai", "juin",
        "juillet", "août", "septembre", "octobre", "novembre", "décembre"
      ];
      period = `_${monthNames[parseInt(selectedMonth) - 1]}_${selectedYear}`;
    } else if (selectedYear !== "all") {
      period = `_${selectedYear}`;
    }

    return `pointages${period}_${timestamp}`;
  };

  const handleExport = () => {
    if (pointages.length === 0) {
      toast({
        title: "Aucune donnée",
        description: "Aucun pointage à exporter",
        variant: "destructive"
      });
      return;
    }

    try {
      const exportData = pointages.map(formatPointageForExport);
      const fileName = generateFileName();

      if (exportOptions.format === 'excel') {
        const ws = XLSX.utils.json_to_sheet(exportData);
        
        // Auto-size columns
        const colWidths = Object.keys(exportData[0] || {}).map(key => ({
          wch: Math.max(key.length, 12)
        }));
        ws['!cols'] = colWidths;

        const wb = XLSX.utils.book_new();
        XLSX.utils.book_append_sheet(wb, ws, "Pointages");
        XLSX.writeFile(wb, `${fileName}.xlsx`);
      } else {
        // CSV export
        const ws = XLSX.utils.json_to_sheet(exportData);
        const csv = XLSX.utils.sheet_to_csv(ws);
        
        const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
        const link = document.createElement('a');
        const url = URL.createObjectURL(blob);
        link.setAttribute('href', url);
        link.setAttribute('download', `${fileName}.csv`);
        link.style.visibility = 'hidden';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
      }

      toast({
        title: "Export réussi",
        description: `${pointages.length} pointages exportés en ${exportOptions.format.toUpperCase()}`
      });

      onClose();
    } catch (error) {
      console.error('Export error:', error);
      toast({
        title: "Erreur d'export",
        description: "Impossible d'exporter les données",
        variant: "destructive"
      });
    }
  };

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Exporter les pointages</DialogTitle>
          <DialogDescription>
            Configurez les options d'export pour {pointages.length} pointage(s)
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div>
            <Label>Format d'export</Label>
            <Select 
              value={exportOptions.format} 
              onValueChange={(value: 'excel' | 'csv') => 
                setExportOptions(prev => ({ ...prev, format: value }))
              }
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="excel">
                  <div className="flex items-center gap-2">
                    <FileSpreadsheet className="h-4 w-4" />
                    Excel (.xlsx)
                  </div>
                </SelectItem>
                <SelectItem value="csv">
                  <div className="flex items-center gap-2">
                    <FileText className="h-4 w-4" />
                    CSV (.csv)
                  </div>
                </SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div>
            <Label>Format de date</Label>
            <Select 
              value={exportOptions.dateFormat} 
              onValueChange={(value: 'fr' | 'iso') => 
                setExportOptions(prev => ({ ...prev, dateFormat: value }))
              }
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="fr">Français (DD/MM/YYYY)</SelectItem>
                <SelectItem value="iso">ISO (YYYY-MM-DD)</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-3">
            <Label>Colonnes à inclure</Label>
            
            <div className="flex items-center space-x-2">
              <Checkbox
                id="include-localisation"
                checked={exportOptions.includeLocalisation}
                onCheckedChange={(checked) => 
                  setExportOptions(prev => ({ ...prev, includeLocalisation: !!checked }))
                }
              />
              <Label htmlFor="include-localisation" className="text-sm">
                Localisation
              </Label>
            </div>

            <div className="flex items-center space-x-2">
              <Checkbox
                id="include-notes"
                checked={exportOptions.includeNotes}
                onCheckedChange={(checked) => 
                  setExportOptions(prev => ({ ...prev, includeNotes: !!checked }))
                }
              />
              <Label htmlFor="include-notes" className="text-sm">
                Notes
              </Label>
            </div>
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            Annuler
          </Button>
          <Button onClick={handleExport} disabled={pointages.length === 0}>
            <Download className="h-4 w-4 mr-2" />
            Exporter
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}