import React from "react";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { AlertCircle, CheckCircle, FileText, Clock } from "lucide-react";
import { type ImportResult } from "@/lib/pointage-import-engine";

interface PointageImportResultsModalProps {
  isOpen: boolean;
  onClose: () => void;
  result: ImportResult | null;
}

export function PointageImportResultsModal({ 
  isOpen, 
  onClose, 
  result 
}: PointageImportResultsModalProps) {
  if (!result) return null;

  const { validEntries, invalidEntries, warnings, errors, metadata } = result;
  const totalEntries = validEntries.length + invalidEntries.length;
  const successRate = totalEntries > 0 ? (validEntries.length / totalEntries) * 100 : 0;

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="max-w-2xl max-h-[80vh] overflow-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <FileText className="h-5 w-5" />
            Résultats de l'importation
          </DialogTitle>
          <DialogDescription>
            Analyse détaillée du processus d'importation des pointages
          </DialogDescription>
        </DialogHeader>

        {/* Statistiques générales */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm flex items-center gap-2">
                <CheckCircle className="h-4 w-4 text-green-600" />
                Entrées valides
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-green-600">
                {validEntries.length}
              </div>
              <div className="text-xs text-muted-foreground">
                {successRate.toFixed(1)}% de réussite
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm flex items-center gap-2">
                <AlertCircle className="h-4 w-4 text-red-600" />
                Entrées invalides
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-red-600">
                {invalidEntries.length}
              </div>
              <div className="text-xs text-muted-foreground">
                Nécessitent correction
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm flex items-center gap-2">
                <Clock className="h-4 w-4 text-blue-600" />
                Temps de traitement
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-blue-600">
                {metadata.processingTime}ms
              </div>
              <div className="text-xs text-muted-foreground">
                {(metadata.processingTime / totalEntries).toFixed(1)}ms/ligne
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Avertissements */}
        {warnings.length > 0 && (
          <Card>
            <CardHeader>
              <CardTitle className="text-sm text-orange-600 flex items-center gap-2">
                <AlertCircle className="h-4 w-4" />
                Avertissements ({warnings.length})
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-1">
                {warnings.slice(0, 5).map((warning, index) => (
                  <div key={index} className="text-sm text-orange-700 bg-orange-50 p-2 rounded">
                    {warning}
                  </div>
                ))}
                {warnings.length > 5 && (
                  <div className="text-xs text-muted-foreground">
                    ... et {warnings.length - 5} autres avertissements
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        )}

        {/* Erreurs */}
        {errors.length > 0 && (
          <Card>
            <CardHeader>
              <CardTitle className="text-sm text-red-600 flex items-center gap-2">
                <AlertCircle className="h-4 w-4" />
                Erreurs ({errors.length})
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-1">
                {errors.slice(0, 5).map((error, index) => (
                  <div key={index} className="text-sm text-red-700 bg-red-50 p-2 rounded">
                    {error}
                  </div>
                ))}
                {errors.length > 5 && (
                  <div className="text-xs text-muted-foreground">
                    ... et {errors.length - 5} autres erreurs
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        )}

        {/* Détails des entrées invalides */}
        {invalidEntries.length > 0 && (
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Détails des entrées invalides</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2 max-h-40 overflow-y-auto">
                {invalidEntries.slice(0, 10).map((entry, index) => (
                  <div key={index} className="text-sm border-l-2 border-red-200 pl-3">
                    <div className="font-medium text-red-700">
                      Ligne {entry.originalIndex + 1}: {entry.date} {entry.heure} {entry.type}
                    </div>
                    <div className="text-red-600 text-xs">
                      {entry.errors.join(', ')}
                    </div>
                  </div>
                ))}
                {invalidEntries.length > 10 && (
                  <div className="text-xs text-muted-foreground">
                    ... et {invalidEntries.length - 10} autres entrées invalides
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        )}

        {/* Résumé par jour de la semaine */}
        {validEntries.length > 0 && (
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Répartition par jour</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                {Object.entries(
                  validEntries.reduce((acc, entry) => {
                    if (entry.date) {
                      try {
                        const date = new Date(entry.date);
                        if (!isNaN(date.getTime())) {
                          const dayName = date.toLocaleDateString('fr-FR', { weekday: 'long' });
                          acc[dayName] = (acc[dayName] || 0) + 1;
                        }
                      } catch {
                        // Ignore les erreurs de parsing de date
                      }
                    }
                    return acc;
                  }, {} as Record<string, number>)
                ).map(([day, count]) => (
                  <div key={day} className="flex justify-between items-center text-sm">
                    <span className="capitalize">{day}</span>
                    <Badge variant="outline">{count} entrées</Badge>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}

        <div className="flex justify-end">
          <Button onClick={onClose}>
            Fermer
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}