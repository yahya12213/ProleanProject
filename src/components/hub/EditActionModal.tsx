import React, { useState } from "react";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useToast } from "@/hooks/use-toast";
import { Action, ActionStatus, ACTION_STATUS_OPTIONS, updateActionStatus, updateActionComment } from "@/lib/project-utils";

interface EditActionModalProps {
  action: Action | null;
  isOpen: boolean;
  onClose: () => void;
  onActionUpdated: () => void;
}

export function EditActionModal({ action, isOpen, onClose, onActionUpdated }: EditActionModalProps) {
  const [commentaire, setCommentaire] = useState(action?.commentaire || "");
  const [statut, setStatut] = useState<ActionStatus>(action?.statut || "todo");
  const [isLoading, setIsLoading] = useState(false);
  const { toast } = useToast();

  // Réinitialiser les états quand l'action change
  React.useEffect(() => {
    if (action) {
      setCommentaire(action.commentaire || "");
      setStatut(action.statut);
    }
  }, [action]);

  const handleSave = async () => {
    if (!action) return;

    setIsLoading(true);
    try {
      // Mettre à jour le statut si changé
      if (statut !== action.statut) {
        await updateActionStatus(action.id, statut);
      }

      // Mettre à jour le commentaire si changé
      if (commentaire !== action.commentaire) {
        await updateActionComment(action.id, commentaire);
      }

      toast({
        title: "Succès",
        description: "Action mise à jour avec succès"
      });

      onActionUpdated();
      onClose();
    } catch (error) {
      toast({
        title: "Erreur",
        description: "Impossible de mettre à jour l'action",
        variant: "destructive"
      });
    } finally {
      setIsLoading(false);
    }
  };

  if (!action) return null;

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Modifier l'action</DialogTitle>
          <DialogDescription>
            Mettez à jour le statut et le commentaire de cette action
          </DialogDescription>
        </DialogHeader>
        
        <div className="space-y-4">
          {/* Titre de l'action (lecture seule) */}
          <div>
            <Label className="text-sm font-medium text-muted-foreground">Action</Label>
            <div className="p-3 bg-muted rounded-md">
              <div className="font-medium text-foreground">{action.titre}</div>
              {action.description && (
                <div className="text-sm text-muted-foreground mt-1">{action.description}</div>
              )}
            </div>
          </div>

          {/* Pilote (lecture seule) */}
          <div>
            <Label className="text-sm font-medium text-muted-foreground">Pilote</Label>
            <div className="p-3 bg-muted rounded-md text-foreground">
              {action.assigned_to_name || "Non assigné"}
            </div>
          </div>

          {/* Statut */}
          <div>
            <Label htmlFor="statut">État d'avancement</Label>
            <Select value={statut} onValueChange={(value) => setStatut(value as ActionStatus)}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {ACTION_STATUS_OPTIONS.map((option) => (
                  <SelectItem key={option.value} value={option.value}>
                    {option.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {/* Commentaire */}
          <div>
            <Label htmlFor="commentaire">Commentaire / Notes de progression</Label>
            <Textarea
              id="commentaire"
              value={commentaire}
              onChange={(e) => setCommentaire(e.target.value)}
              placeholder="Ajoutez vos notes de progression, obstacles rencontrés, prochaines étapes..."
              rows={4}
            />
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={isLoading}>
            Annuler
          </Button>
          <Button onClick={handleSave} disabled={isLoading}>
            {isLoading ? "Mise à jour..." : "Enregistrer"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}