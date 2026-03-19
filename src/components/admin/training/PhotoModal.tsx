import React from 'react';
import { Dialog, DialogContent } from "@/components/ui/dialog";
import { X } from 'lucide-react';

interface PhotoModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  student: {
    nom: string;
    prenom: string;
    photo_url?: string;
  };
}

export const PhotoModal: React.FC<PhotoModalProps> = ({
  open,
  onOpenChange,
  student
}) => {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md p-0 overflow-hidden">
        <div className="relative">
          <button
            onClick={() => onOpenChange(false)}
            className="absolute top-2 right-2 z-10 p-1 bg-black/50 hover:bg-black/70 rounded-full text-white transition-colors"
          >
            <X className="h-4 w-4" />
          </button>
          
          <div className="p-6 text-center">
            <div className="relative mx-auto mb-4">
              {student.photo_url ? (
                <img
                  src={student.photo_url}
                  alt={`Photo de ${student.prenom} ${student.nom}`}
                  className="w-64 h-64 object-cover rounded-lg mx-auto shadow-lg"
                />
              ) : (
                <div className="w-64 h-64 bg-gray-200 rounded-lg mx-auto flex items-center justify-center shadow-lg">
                  <span className="text-4xl font-bold text-gray-400">
                    {student.prenom.charAt(0)}{student.nom.charAt(0)}
                  </span>
                </div>
              )}
            </div>
            
            <h3 className="text-lg font-semibold">
              {student.prenom} {student.nom}
            </h3>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
};