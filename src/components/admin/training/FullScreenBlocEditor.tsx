import React, { useRef, useEffect, useState, useCallback } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Plus, Check, X } from 'lucide-react';
import { toast } from 'sonner';
import { supabase } from '@/integrations/supabase/client';

interface DocumentBloc {
  id: string;
  nom_bloc: string;
  type_contenu: string;
  face: string;
  position_x: number;
  position_y: number;
  largeur: number;
  hauteur: number;
  styles_css: any;
  ordre_affichage: number;
}

interface FullScreenBlocEditorProps {
  isOpen: boolean;
  onClose: () => void;
  imageUrl: string;
  face: 'recto' | 'verso';
  blocs: DocumentBloc[];
  modeleId: string;
  onBlocsUpdate: (blocs: DocumentBloc[]) => void;
}

const CONTENT_TYPES = [
  { value: 'cin', label: 'CIN' },
  { value: 'nom', label: 'Nom' },
  { value: 'prenom', label: 'Prénom' },
  { value: 'texte_libre', label: 'Texte Personnalisé' }
];

const FullScreenBlocEditor: React.FC<FullScreenBlocEditorProps> = ({
  isOpen,
  onClose,
  imageUrl,
  face,
  blocs,
  modeleId,
  onBlocsUpdate
}) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [isPlacingMode, setIsPlacingMode] = useState(false);
  const [placementPosition, setPlacementPosition] = useState<{ x: number; y: number } | null>(null);
  const [showConfirmButton, setShowConfirmButton] = useState(false);
  const [showConfigPopup, setShowConfigPopup] = useState(false);
  const [imageLoaded, setImageLoaded] = useState(false);
  const [scale, setScale] = useState(1);
  const [canvasSize, setCanvasSize] = useState({ width: 800, height: 600 });
  
  const [blocConfig, setBlocConfig] = useState({
    type_contenu: 'nom',
    fontSize: 14,
    fontWeight: 'normal',
    fontStyle: 'normal',
    color: '#000000'
  });

  const image = useRef(new Image());

  useEffect(() => {
    if (!isOpen) return;
    
    // Mode plein écran
    document.body.style.overflow = 'hidden';
    
    return () => {
      document.body.style.overflow = 'auto';
    };
  }, [isOpen]);

  useEffect(() => {
    if (!imageUrl || !isOpen) {
      setImageLoaded(false);
      return;
    }
    
    image.current.onload = () => {
      setImageLoaded(true);
      calculateCanvasSize();
    };
    image.current.onerror = () => {
      setImageLoaded(false);
      toast.error('Erreur lors du chargement de l\'image');
    };
    image.current.src = imageUrl;
  }, [imageUrl, isOpen]);

  useEffect(() => {
    if (imageLoaded && isOpen) {
      drawCanvas();
    }
  }, [imageLoaded, isOpen, blocs, placementPosition, showConfirmButton]);

  const calculateCanvasSize = () => {
    if (!image.current.complete) return;

    const maxWidth = window.innerWidth - 100;
    const maxHeight = window.innerHeight - 200;
    
    const imgAspectRatio = image.current.naturalWidth / image.current.naturalHeight;
    
    let width, height;
    
    if (imgAspectRatio > maxWidth / maxHeight) {
      width = maxWidth;
      height = width / imgAspectRatio;
    } else {
      height = maxHeight;
      width = height * imgAspectRatio;
    }
    
    setScale(width / image.current.naturalWidth);
    setCanvasSize({ width: Math.floor(width), height: Math.floor(height) });
  };

  const drawCanvas = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas || !imageLoaded) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    // Clear canvas
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // Draw background image
    ctx.drawImage(image.current, 0, 0, canvas.width, canvas.height);

    // Draw existing blocs
    const facesBlocs = blocs.filter(bloc => bloc.face === face);
    
    facesBlocs.forEach(bloc => {
      const x = bloc.position_x * scale;
      const y = bloc.position_y * scale;
      const width = bloc.largeur * scale;
      const height = bloc.hauteur * scale;
      
      // Draw bloc background
      ctx.fillStyle = 'rgba(59, 130, 246, 0.2)';
      ctx.fillRect(x, y, width, height);
      
      // Draw bloc border
      ctx.strokeStyle = '#3b82f6';
      ctx.lineWidth = 2;
      ctx.strokeRect(x, y, width, height);
      
      // Draw text sample
      const styles = typeof bloc.styles_css === 'string' ? JSON.parse(bloc.styles_css) : bloc.styles_css;
      ctx.fillStyle = styles?.color || '#000000';
      ctx.font = `${styles?.fontStyle || 'normal'} ${styles?.fontWeight || 'normal'} ${(styles?.fontSize || 14) * scale}px ${styles?.fontFamily || 'Arial'}`;
      ctx.fillText(bloc.nom_bloc, x + 5, y + (styles?.fontSize || 14) * scale + 5);
      
      // Draw label above
      ctx.fillStyle = '#3b82f6';
      ctx.font = `normal normal ${12 * scale}px Arial`;
      ctx.fillText(bloc.nom_bloc, x, y - 5);
    });

    // Draw placement indicator if in placing mode
    if (placementPosition && showConfirmButton) {
      const x = placementPosition.x * scale;
      const y = placementPosition.y * scale;
      
      ctx.fillStyle = 'rgba(34, 197, 94, 0.3)';
      ctx.fillRect(x - 75, y - 15, 150, 30);
      
      ctx.strokeStyle = '#22c55e';
      ctx.lineWidth = 2;
      ctx.strokeRect(x - 75, y - 15, 150, 30);
      
      ctx.fillStyle = '#22c55e';
      ctx.font = `normal normal ${12 * scale}px Arial`;
      ctx.fillText('Nouvel emplacement', x - 70, y + 5);
    }
  }, [blocs, face, imageLoaded, placementPosition, showConfirmButton, scale]);

  const getCanvasPosition = useCallback((e: React.MouseEvent) => {
    const canvas = canvasRef.current;
    if (!canvas) return { x: 0, y: 0 };

    // Cache the bounding rect to avoid forced reflows
    const rect = canvas.getBoundingClientRect();
    const x = (e.clientX - rect.left) / scale;
    const y = (e.clientY - rect.top) / scale;
    
    return { x: Math.max(0, x), y: Math.max(0, y) };
  }, [scale]);

  const handleCanvasClick = (e: React.MouseEvent) => {
    if (!isPlacingMode) return;

    const pos = getCanvasPosition(e);
    setPlacementPosition(pos);
    setShowConfirmButton(true);
  };

  const handleAddBloc = () => {
    setIsPlacingMode(true);
    setPlacementPosition(null);
    setShowConfirmButton(false);
    setShowConfigPopup(false);
    
    // Change cursor to crosshair
    const canvas = canvasRef.current;
    if (canvas) {
      canvas.style.cursor = 'crosshair';
    }
  };

  const handleConfirmPosition = () => {
    if (!placementPosition) return;
    
    setShowConfirmButton(false);
    setShowConfigPopup(true);
  };

  const handleCancelPlacement = () => {
    setIsPlacingMode(false);
    setPlacementPosition(null);
    setShowConfirmButton(false);
    setShowConfigPopup(false);
    
    const canvas = canvasRef.current;
    if (canvas) {
      canvas.style.cursor = 'default';
    }
  };

  const handleValidateBloc = async () => {
    if (!placementPosition || !modeleId) return;

    try {
      const { data, error } = await supabase
        .from('document_blocs')
        .insert({
          modele_id: modeleId,
          nom_bloc: `${blocConfig.type_contenu}_${Date.now()}`,
          type_contenu: blocConfig.type_contenu,
          face: face,
          position_x: Math.round(placementPosition.x),
          position_y: Math.round(placementPosition.y),
          largeur: 150,
          hauteur: 30,
          styles_css: JSON.stringify({
            fontSize: blocConfig.fontSize,
            fontFamily: 'Arial',
            fontWeight: blocConfig.fontWeight,
            fontStyle: blocConfig.fontStyle,
            color: blocConfig.color,
            textAlign: 'left',
            backgroundColor: 'transparent'
          }),
          ordre_affichage: blocs.length + 1,
          actif: true
        })
        .select()
        .single();

      if (error) throw error;

      // Update blocs list
      onBlocsUpdate([...blocs, data]);
      
      toast.success('Bloc créé avec succès');
      
      // Reset state
      handleCancelPlacement();
      
    } catch (error) {
      console.error('Error creating bloc:', error);
      toast.error('Erreur lors de la création du bloc');
    }
  };

  const handleSaveAndExit = async () => {
    toast.success('Modifications sauvegardées');
    onClose();
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-background z-50 flex flex-col">
      {/* Toolbar simplifié */}
      <div className="h-16 bg-background border-b flex items-center justify-between px-6">
        <div className="flex items-center space-x-4">
          <Button
            onClick={handleAddBloc}
            disabled={isPlacingMode}
            className="bg-blue-600 hover:bg-blue-700"
          >
            <Plus className="h-4 w-4 mr-2" />
            {isPlacingMode ? 'Mode placement actif...' : '+ Ajouter un Bloc'}
          </Button>
        </div>
        
        <Button
          onClick={handleSaveAndExit}
          className="bg-green-600 hover:bg-green-700"
        >
          <Check className="h-4 w-4 mr-2" />
          ✅ Enregistrer et Quitter
        </Button>
      </div>

      {/* Canvas plein écran */}
      <div className="flex-1 flex items-center justify-center bg-gray-50 relative">
        {!imageUrl ? (
          <div className="text-center text-gray-500">
            <p className="text-xl">Aucune image disponible</p>
            <p className="text-sm mt-2">Veuillez d'abord uploader une image</p>
          </div>
        ) : (
          <canvas
            ref={canvasRef}
            width={canvasSize.width}
            height={canvasSize.height}
            className={`border border-gray-300 bg-white ${isPlacingMode ? 'cursor-crosshair' : 'cursor-default'}`}
            onClick={handleCanvasClick}
          />
        )}

        {/* Bouton "Confirmer ici" */}
        {showConfirmButton && placementPosition && (
          <div
            className="absolute bg-green-600 text-white px-3 py-1 rounded shadow-lg cursor-pointer hover:bg-green-700 transition-colors"
            style={{
              left: `${placementPosition.x * scale + (window.innerWidth - canvasSize.width) / 2}px`,
              top: `${placementPosition.y * scale + (window.innerHeight - canvasSize.height) / 2 + 80}px`,
              transform: 'translate(-50%, -50%)'
            }}
            onClick={handleConfirmPosition}
          >
            Confirmer ici
          </div>
        )}

        {/* Instructions */}
        {isPlacingMode && !showConfirmButton && (
          <div className="absolute top-4 left-1/2 transform -translate-x-1/2 bg-blue-100 text-blue-800 px-4 py-2 rounded-lg border border-blue-200">
            Cliquez sur l'image pour choisir l'emplacement du nouveau bloc
          </div>
        )}
      </div>

      {/* Pop-up de configuration */}
      {showConfigPopup && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 w-80 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-medium">Configuration du bloc</h3>
              <Button variant="ghost" size="sm" onClick={handleCancelPlacement}>
                <X className="h-4 w-4" />
              </Button>
            </div>

            <div className="space-y-3">
              <div>
                <Label>Type de contenu</Label>
                <Select 
                  value={blocConfig.type_contenu} 
                  onValueChange={(value) => setBlocConfig(prev => ({ ...prev, type_contenu: value }))}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {CONTENT_TYPES.map(type => (
                      <SelectItem key={type.value} value={type.value}>
                        {type.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="grid grid-cols-2 gap-2">
                <div>
                  <Label>Taille</Label>
                  <Input
                    type="number"
                    value={blocConfig.fontSize}
                    onChange={(e) => setBlocConfig(prev => ({ ...prev, fontSize: parseInt(e.target.value) || 14 }))}
                  />
                </div>
                <div>
                  <Label>Couleur</Label>
                  <Input
                    type="color"
                    value={blocConfig.color}
                    onChange={(e) => setBlocConfig(prev => ({ ...prev, color: e.target.value }))}
                  />
                </div>
              </div>

              <div className="flex space-x-2">
                <Button
                  variant={blocConfig.fontWeight === 'bold' ? 'default' : 'outline'}
                  size="sm"
                  onClick={() => setBlocConfig(prev => ({ 
                    ...prev, 
                    fontWeight: prev.fontWeight === 'bold' ? 'normal' : 'bold' 
                  }))}
                >
                  Gras
                </Button>
                <Button
                  variant={blocConfig.fontStyle === 'italic' ? 'default' : 'outline'}
                  size="sm"
                  onClick={() => setBlocConfig(prev => ({ 
                    ...prev, 
                    fontStyle: prev.fontStyle === 'italic' ? 'normal' : 'italic' 
                  }))}
                >
                  Italique
                </Button>
              </div>

              <Button
                onClick={handleValidateBloc}
                className="w-full bg-blue-600 hover:bg-blue-700"
              >
                Valider le Bloc
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default FullScreenBlocEditor;