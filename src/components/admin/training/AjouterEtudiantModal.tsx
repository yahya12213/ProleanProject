import React from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import AjouterEtudiant from './AjouterEtudiant';


interface AjouterEtudiantModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  classe?: any;
  onSuccess: () => void;
}

export const AjouterEtudiantModal: React.FC<AjouterEtudiantModalProps> = ({
  open,
  onOpenChange,
  classe,
  onSuccess
}) => {
  const handleSuccess = () => {
    onSuccess();
    onOpenChange(false);
  };

  const handleCancel = () => {
    onOpenChange(false);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Ajouter un nouvel étudiant</DialogTitle>
        </DialogHeader>
        <AjouterEtudiant
          classe={classe}
          onSuccess={handleSuccess}
          onCancel={handleCancel}
        />
      </DialogContent>
    </Dialog>
  );
};