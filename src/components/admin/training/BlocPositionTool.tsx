import React, { useRef, useEffect, useState, useCallback } from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Separator } from '@/components/ui/separator';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { ZoomIn, ZoomOut, RotateCcw, Eye, EyeOff, Check, X, Type, Palette, Grid, Save, Plus } from 'lucide-react';
import { toast } from 'sonner';
import axios from 'axios';
import { generateCanvasCSS, normalizeCSSStyles } from '@/lib/pdf-font-utils';

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

interface BlocPositionToolProps {
  isOpen: boolean;
  onClose: () => void;
  imageUrl: string;
  face: 'recto' | 'verso';
  blocs: DocumentBloc[];
  onPositionSelected?: (x: number, y: number) => void;
  onBlocUpdate?: (bloc: DocumentBloc) => void;
  onBlocCreate?: (bloc: Partial<DocumentBloc>) => void;
  placingMode?: boolean;
  modeleId?: string;
}

// Formats de documents prédéfinis (en mm convertis en pixels à 300 DPI)
const DOCUMENT_FORMATS = {
  'A4': { width: 2480, height: 3508, name: 'A4 (210×297mm)' },
  'A5': { width: 1748, height: 2480, name: 'A5 (148×210mm)' },
  'CARTE_BANCAIRE': { width: 1012, height: 638, name: 'Carte bancaire (85.6×53.98mm)' },
  'CARTE_VISITE': { width: 1004, height: 650, name: 'Carte de visite (85×55mm)' },
  'CARTE_IDENTITE': { width: 1012, height: 638, name: 'Carte d\'identité (85.6×53.98mm)' }
} as const;

type DocumentFormat = keyof typeof DOCUMENT_FORMATS;

const FONT_FAMILIES = [
  'Arial', 'Times New Roman', 'Helvetica', 'Georgia', 'Verdana', 'Courier New', 'Impact', 'Comic Sans MS'
];

const CONTENT_TYPES = [
  { value: 'nom', label: 'Nom' },
  { value: 'prenom', label: 'Prénom' },
  { value: 'cin', label: 'CIN' },
  { value: 'date_naissance', label: 'Date de naissance' },
  { value: 'adresse', label: 'Adresse' },
  { value: 'telephone', label: 'Téléphone' },
  { value: 'email', label: 'Email' },
  { value: 'formation', label: 'Formation' },
  { value: 'date_formation', label: 'Date de formation' },
  { value: 'date_emission', label: 'Date d\'émission' },
  { value: 'numero_certificat', label: 'Numéro de certificat' },
  { value: 'texte_libre', label: 'Texte libre' }
];

const BlocPositionTool: React.FC<BlocPositionToolProps> = ({
  isOpen,
  onClose,
  imageUrl,
  face,
  blocs,
  onPositionSelected,
  onBlocUpdate,
  onBlocCreate,
  placingMode = false,
  modeleId
}) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [scale, setScale] = useState(0.5);
  const [offset, setOffset] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  const [selectedBloc, setSelectedBloc] = useState<DocumentBloc | null>(null);
  const [isResizing, setIsResizing] = useState(false);
  const [resizeHandle, setResizeHandle] = useState<string>('');
  const [showBlocs, setShowBlocs] = useState(true);
  const [showGrid, setShowGrid] = useState(false);
  const [imageLoaded, setImageLoaded] = useState(false);
  const [documentFormat, setDocumentFormat] = useState<DocumentFormat>('A4');
  const [canvasSize, setCanvasSize] = useState({ width: 800, height: 600 });
  
  // Style properties for selected bloc
  const [blocStyles, setBlocStyles] = useState({
    fontSize: 14, // En points, pas en string
    fontFamily: 'Arial',
    color: '#000000',
    backgroundColor: 'transparent',
    fontWeight: 'normal',
    fontStyle: 'normal',
    textAlign: 'left',
    verticalAlign: 'middle'
  });

  // New bloc creation popup
  const [showCreatePopup, setShowCreatePopup] = useState(false);
  const [newBlocPosition, setNewBlocPosition] = useState({ x: 0, y: 0 });
  const [newBlocData, setNewBlocData] = useState({
    nom_bloc: '',
    type_contenu: 'nom',
    largeur: 150,
    hauteur: 30
  });

  const image = useRef(new Image());

  useEffect(() => {
    if (!imageUrl) {
      setImageLoaded(false);
      return;
    }
    
    image.current.onload = () => {
      setImageLoaded(true);
      calculateCanvasSize();
      centerImage();
    };
    image.current.onerror = () => {
      console.error('Error loading image:', imageUrl);
      setImageLoaded(false);
      toast.error('Erreur lors du chargement de l\'image');
    };
    image.current.src = imageUrl;
  }, [imageUrl]);

  useEffect(() => {
    if (selectedBloc) {
      const styles = parseStylesFromCSS(selectedBloc.styles_css);
      setBlocStyles(styles);
    }
  }, [selectedBloc]);

  useEffect(() => {
    if (imageLoaded) {
      drawCanvas();
    }
  }, [imageLoaded, blocs, selectedBloc, showBlocs, showGrid, scale, offset, blocStyles]);

  const parseStylesFromCSS = (cssString: string) => {
    if (!cssString) return normalizeCSSStyles({});

    try {
      const styles = typeof cssString === 'string' ? JSON.parse(cssString) : cssString;
      return normalizeCSSStyles(styles); // Utiliser la normalisation commune
    } catch {
      return normalizeCSSStyles({});
    }
  };

  const calculateCanvasSize = () => {
    if (!image.current.complete) return;

    // Calculer les dimensions en fonction du format de document sélectionné
    const format = DOCUMENT_FORMATS[documentFormat];
    const imgAspectRatio = image.current.naturalWidth / image.current.naturalHeight;
    const formatAspectRatio = format.width / format.height;
    
    const maxWidth = 900;
    const maxHeight = 700;

    let width, height;
    
    // Utiliser l'aspect ratio de l'image mais limiter par les dimensions max
    if (imgAspectRatio > 1) {
      width = Math.min(maxWidth, image.current.naturalWidth * 0.4);
      height = width / imgAspectRatio;
    } else {
      height = Math.min(maxHeight, image.current.naturalHeight * 0.4);
      width = height * imgAspectRatio;
    }

    setCanvasSize({ width: Math.floor(width), height: Math.floor(height) });
  };

  const centerImage = () => {
    if (!image.current.complete) return;
    
    const canvas = canvasRef.current;
    if (!canvas) return;

    const centerX = (canvas.width - image.current.naturalWidth * scale) / 2 / scale;
    const centerY = (canvas.height - image.current.naturalHeight * scale) / 2 / scale;
    
    setOffset({ x: centerX, y: centerY });
  };

  const drawCanvas = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    // Clear canvas
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // Apply transformations
    ctx.save();
    ctx.scale(scale, scale);
    ctx.translate(offset.x, offset.y);

    // Draw background image
    if (imageLoaded && image.current.complete) {
      ctx.drawImage(image.current, 0, 0, image.current.naturalWidth, image.current.naturalHeight);
    } else if (!imageLoaded) {
      // Draw placeholder when no image
      ctx.fillStyle = '#f3f4f6';
      ctx.fillRect(0, 0, canvas.width / scale, canvas.height / scale);
      ctx.fillStyle = '#6b7280';
      ctx.font = '24px Arial';
      ctx.textAlign = 'center';
      ctx.fillText('Aucune image', (canvas.width / scale) / 2, (canvas.height / scale) / 2);
    }

    // Draw grid if enabled
    if (showGrid && imageLoaded) {
      ctx.strokeStyle = 'rgba(0, 0, 0, 0.1)';
      ctx.lineWidth = 1;
      const gridSize = 20;
      
      for (let x = 0; x < image.current.naturalWidth; x += gridSize) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, image.current.naturalHeight);
        ctx.stroke();
      }
      
      for (let y = 0; y < image.current.naturalHeight; y += gridSize) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(image.current.naturalWidth, y);
        ctx.stroke();
      }
    }

    // Draw blocs if visible
    if (showBlocs) {
      const facesBlocs = blocs.filter(bloc => bloc.face === face);
      
      facesBlocs.forEach(bloc => {
        const isSelected = selectedBloc?.id === bloc.id;
        
        // Parse bloc styles
        const styles = parseStylesFromCSS(bloc.styles_css);
        
        // Draw bloc background
        if (styles.backgroundColor !== 'transparent') {
          ctx.fillStyle = styles.backgroundColor;
          ctx.fillRect(bloc.position_x, bloc.position_y, bloc.largeur, bloc.hauteur);
        }
        
        // Draw bloc border
        ctx.strokeStyle = isSelected ? '#3b82f6' : '#10b981';
        ctx.fillStyle = isSelected ? 'rgba(59, 130, 246, 0.1)' : 'rgba(16, 185, 129, 0.1)';
        ctx.lineWidth = isSelected ? 3 : 2;
        
        if (styles.backgroundColor === 'transparent') {
          ctx.fillRect(bloc.position_x, bloc.position_y, bloc.largeur, bloc.hauteur);
        }
        ctx.strokeRect(bloc.position_x, bloc.position_y, bloc.largeur, bloc.hauteur);

        // Draw sample text with styles - utiliser la conversion jsPDF
        const canvasStyles = generateCanvasCSS(styles, 'A4', scale); // Utiliser le format approprié
        ctx.fillStyle = canvasStyles.color;
        ctx.font = `${canvasStyles.fontStyle} ${canvasStyles.fontWeight} ${canvasStyles.fontSize} ${canvasStyles.fontFamily}`;
        ctx.textAlign = canvasStyles.textAlign as CanvasTextAlign;
        
        let textX = bloc.position_x + 5;
        if (canvasStyles.textAlign === 'center') {
          textX = bloc.position_x + bloc.largeur / 2;
        } else if (canvasStyles.textAlign === 'right') {
          textX = bloc.position_x + bloc.largeur - 5;
        }
        
        ctx.fillText(
          bloc.nom_bloc,
          textX,
          bloc.position_y + parseFloat(canvasStyles.fontSize) + 5
        );

        // Draw bloc label above
        ctx.fillStyle = isSelected ? '#3b82f6' : '#10b981';
        ctx.font = '12px Arial';
        ctx.textAlign = 'left';
        ctx.fillText(bloc.nom_bloc, bloc.position_x, bloc.position_y - 5);

        // Draw resize handles for selected bloc
        if (isSelected) {
          const handleSize = 8;
          ctx.fillStyle = '#3b82f6';
          
          // Corner handles
          const handles = [
            { x: bloc.position_x - handleSize/2, y: bloc.position_y - handleSize/2 },
            { x: bloc.position_x + bloc.largeur - handleSize/2, y: bloc.position_y - handleSize/2 },
            { x: bloc.position_x - handleSize/2, y: bloc.position_y + bloc.hauteur - handleSize/2 },
            { x: bloc.position_x + bloc.largeur - handleSize/2, y: bloc.position_y + bloc.hauteur - handleSize/2 }
          ];

          handles.forEach(handle => {
            ctx.fillRect(handle.x, handle.y, handleSize, handleSize);
          });
        }
      });
    }

    ctx.restore();
  }, [blocs, selectedBloc, showBlocs, showGrid, scale, offset, face, imageLoaded, blocStyles]);

  const getCanvasPosition = useCallback((e: React.MouseEvent) => {
    const canvas = canvasRef.current;
    if (!canvas) return { x: 0, y: 0 };

    // Cache the bounding rect to avoid forced reflows
    const rect = canvas.getBoundingClientRect();
    const x = ((e.clientX - rect.left) / scale) - offset.x;
    const y = ((e.clientY - rect.top) / scale) - offset.y;
    
    return { x: Math.max(0, x), y: Math.max(0, y) };
  }, [scale, offset]);

  const handleCanvasClick = (e: React.MouseEvent) => {
    if (isResizing || isDragging) return;

    const pos = getCanvasPosition(e);
    
    if (placingMode && onPositionSelected) {
      onPositionSelected(Math.round(pos.x), Math.round(pos.y));
      return;
    }

    // Check if clicking on a bloc
    const facesBlocs = blocs.filter(bloc => bloc.face === face);
    const clickedBloc = facesBlocs.find(bloc => 
      pos.x >= bloc.position_x && 
      pos.x <= bloc.position_x + bloc.largeur &&
      pos.y >= bloc.position_y && 
      pos.y <= bloc.position_y + bloc.hauteur
    );

    if (clickedBloc) {
      setSelectedBloc(clickedBloc);
    } else {
      // Si on ne clique pas sur un bloc, proposer de créer un nouveau bloc
      setSelectedBloc(null);
      setNewBlocPosition({ x: Math.round(pos.x), y: Math.round(pos.y) });
      setShowCreatePopup(true);
    }
  };

  const handleMouseDown = (e: React.MouseEvent) => {
    const pos = getCanvasPosition(e);
    
    if (selectedBloc) {
      // Check if clicking on resize handle
      const handleSize = 8;
      const handles = [
        { x: selectedBloc.position_x - handleSize/2, y: selectedBloc.position_y - handleSize/2, type: 'nw' },
        { x: selectedBloc.position_x + selectedBloc.largeur - handleSize/2, y: selectedBloc.position_y - handleSize/2, type: 'ne' },
        { x: selectedBloc.position_x - handleSize/2, y: selectedBloc.position_y + selectedBloc.hauteur - handleSize/2, type: 'sw' },
        { x: selectedBloc.position_x + selectedBloc.largeur - handleSize/2, y: selectedBloc.position_y + selectedBloc.hauteur - handleSize/2, type: 'se' }
      ];

      const handle = handles.find(h => 
        pos.x >= h.x && pos.x <= h.x + handleSize &&
        pos.y >= h.y && pos.y <= h.y + handleSize
      );

      if (handle) {
        setIsResizing(true);
        setResizeHandle(handle.type);
        return;
      }
    }

    setIsDragging(true);
    setDragStart(pos);
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    const pos = getCanvasPosition(e);

    if (isResizing && selectedBloc && onBlocUpdate) {
      const updatedBloc = { ...selectedBloc };
      
      switch (resizeHandle) {
        case 'se':
          updatedBloc.largeur = Math.max(20, pos.x - selectedBloc.position_x);
          updatedBloc.hauteur = Math.max(20, pos.y - selectedBloc.position_y);
          break;
        case 'sw':
          const newWidth = selectedBloc.position_x + selectedBloc.largeur - pos.x;
          if (newWidth > 20) {
            updatedBloc.position_x = pos.x;
            updatedBloc.largeur = newWidth;
          }
          updatedBloc.hauteur = Math.max(20, pos.y - selectedBloc.position_y);
          break;
        case 'ne':
          updatedBloc.largeur = Math.max(20, pos.x - selectedBloc.position_x);
          const newHeight = selectedBloc.position_y + selectedBloc.hauteur - pos.y;
          if (newHeight > 20) {
            updatedBloc.position_y = pos.y;
            updatedBloc.hauteur = newHeight;
          }
          break;
        case 'nw': {
          const newWidth = selectedBloc.position_x + selectedBloc.largeur - pos.x;
          const newHeight = selectedBloc.position_y + selectedBloc.hauteur - pos.y;
          if (newWidth > 20) {
            updatedBloc.position_x = pos.x;
            updatedBloc.largeur = newWidth;
          }
          if (newHeight > 20) {
            updatedBloc.position_y = pos.y;
            updatedBloc.hauteur = newHeight;
          }
          break;
        }
      }
      
      setSelectedBloc(updatedBloc);
    } else if (isDragging && selectedBloc && onBlocUpdate) {
      const deltaX = pos.x - dragStart.x;
      const deltaY = pos.y - dragStart.y;
      
      const updatedBloc = {
        ...selectedBloc,
        position_x: Math.max(0, selectedBloc.position_x + deltaX),
        position_y: Math.max(0, selectedBloc.position_y + deltaY)
      };
      
      setSelectedBloc(updatedBloc);
      setDragStart(pos);
    }
  };

  const handleMouseUp = () => {
    if (selectedBloc && onBlocUpdate && (isDragging || isResizing)) {
      onBlocUpdate(selectedBloc);
    }
    setIsDragging(false);
    setIsResizing(false);
    setResizeHandle('');
  };

  const handleZoom = (factor: number) => {
    setScale(prev => Math.max(0.1, Math.min(3, prev * factor)));
  };

  const resetView = () => {
    setScale(0.5);
    centerImage();
  };

  const handleStyleChange = (property: string, value: string) => {
    setBlocStyles(prev => ({
      ...prev,
      [property]: value
    }));
  };

  const applyStylesToBloc = async () => {
    if (!selectedBloc || !onBlocUpdate) return;

    const updatedBloc = {
      ...selectedBloc,
      styles_css: JSON.stringify(normalizeCSSStyles(blocStyles)) // Normaliser avant de sauvegarder
    };

    // Save to database
    try {
      await axios.put(`/api/blocs/${selectedBloc.id}`, {
        styles_css: JSON.stringify(normalizeCSSStyles(blocStyles))
      });

      onBlocUpdate(updatedBloc);
      toast.success('Styles appliqués et sauvegardés');
    } catch (error) {
      console.error('Error updating bloc styles:', error);
      toast.error('Erreur lors de la sauvegarde des styles');
    }
  };

  const fetchBlocs = async (modeleId: string) => {
    try {
      const response = await axios.get(`/api/blocs?modeleId=${modeleId}`);
      return response.data;
    } catch (error) {
      console.error('Error fetching blocs:', error);
      toast.error('Erreur lors du chargement des blocs');
      return [];
    }
  };

  const handleCreateBloc = async () => {
    if (!newBlocData.nom_bloc || !modeleId) {
      toast.error('Veuillez remplir tous les champs obligatoires');
      return;
    }

    try {
      const { data } = await axios.post('/api/blocs', {
        modele_id: modeleId,
        nom_bloc: newBlocData.nom_bloc,
        type_contenu: newBlocData.type_contenu,
        face: face,
        position_x: newBlocPosition.x,
        position_y: newBlocPosition.y,
        largeur: newBlocData.largeur,
        hauteur: newBlocData.hauteur,
        styles_css: JSON.stringify(blocStyles),
        ordre_affichage: blocs.length + 1,
        actif: true
      });

      if (onBlocCreate) {
        onBlocCreate(data);
      }

      // Reset form
      setNewBlocData({
        nom_bloc: '',
        type_contenu: 'nom',
        largeur: 150,
        hauteur: 30
      });
      setShowCreatePopup(false);
      toast.success('Bloc créé avec succès');

    } catch (error) {
      console.error('Error creating bloc:', error);
      toast.error('Erreur lors de la création du bloc');
    }
  };

  const validateAndClose = () => {
    if (selectedBloc && onBlocUpdate) {
      onBlocUpdate(selectedBloc);
    }
    toast.success('Modifications sauvegardées');
    onClose();
  };

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="max-w-[95vw] max-h-[95vh] overflow-hidden">
        <DialogHeader>
          <DialogTitle className="flex items-center justify-between">
            <span>Éditeur Visuel - {face === 'recto' ? 'Recto' : 'Verso'}</span>
            <div className="flex gap-2">
              <Select value={documentFormat} onValueChange={(value: DocumentFormat) => setDocumentFormat(value)}>
                <SelectTrigger className="w-48">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {Object.entries(DOCUMENT_FORMATS).map(([key, format]) => (
                    <SelectItem key={key} value={key}>{format.name}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Button onClick={validateAndClose} className="bg-green-600 hover:bg-green-700">
                <Save className="h-4 w-4 mr-2" />
                Valider et Fermer
              </Button>
            </div>
          </DialogTitle>
        </DialogHeader>

        <div className="flex h-[80vh] gap-4">
          {/* Left Panel - Canvas */}
          <div className="flex-1 flex flex-col space-y-4">
            {/* Toolbar */}
            <div className="flex justify-between items-center bg-gray-50 p-3 rounded-lg">
              <div className="flex space-x-2">
                <Button variant="outline" size="sm" onClick={() => handleZoom(1.2)}>
                  <ZoomIn className="h-4 w-4" />
                </Button>
                <Button variant="outline" size="sm" onClick={() => handleZoom(0.8)}>
                  <ZoomOut className="h-4 w-4" />
                </Button>
                <Button variant="outline" size="sm" onClick={resetView}>
                  <RotateCcw className="h-4 w-4" />
                </Button>
                <Button 
                  variant={showBlocs ? "default" : "outline"} 
                  size="sm" 
                  onClick={() => setShowBlocs(!showBlocs)}
                >
                  {showBlocs ? <Eye className="h-4 w-4" /> : <EyeOff className="h-4 w-4" />}
                  Blocs
                </Button>
                <Button 
                  variant={showGrid ? "default" : "outline"} 
                  size="sm" 
                  onClick={() => setShowGrid(!showGrid)}
                >
                  <Grid className="h-4 w-4" />
                  Grille
                </Button>
              </div>

              {selectedBloc && (
                <Badge variant="outline" className="text-blue-600">
                  {selectedBloc.nom_bloc} - {Math.round(selectedBloc.position_x)},{Math.round(selectedBloc.position_y)} 
                  ({Math.round(selectedBloc.largeur)}×{Math.round(selectedBloc.hauteur)})
                </Badge>
              )}
            </div>

            {/* Canvas Container */}
            <div 
              ref={containerRef}
              className="flex-1 border rounded-lg overflow-auto bg-gray-50 flex items-center justify-center relative"
            >
              {!imageUrl ? (
                <div className="text-center text-gray-500 p-8">
                  <Type className="h-16 w-16 mx-auto mb-4 text-gray-300" />
                  <p className="text-lg font-medium">Aucune image disponible</p>
                  <p className="text-sm">Veuillez d'abord uploader une image dans l'onglet "Images"</p>
                </div>
              ) : (
                <canvas
                  ref={canvasRef}
                  width={canvasSize.width}
                  height={canvasSize.height}
                  className="cursor-crosshair border border-gray-300 bg-white"
                  onClick={handleCanvasClick}
                  onMouseDown={handleMouseDown}
                  onMouseMove={handleMouseMove}
                  onMouseUp={handleMouseUp}
                  onMouseLeave={handleMouseUp}
                />
              )}

              {/* Create Bloc Popup */}
              <Popover open={showCreatePopup} onOpenChange={setShowCreatePopup}>
                <PopoverTrigger asChild>
                  <div className="hidden-element" />
                </PopoverTrigger>
                <PopoverContent className="w-80 absolute" style={{ 
                  position: 'fixed', 
                  left: '50%', 
                  top: '50%', 
                  transform: 'translate(-50%, -50%)',
                  zIndex: 1000
                }}>
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <h4 className="font-medium">Créer un nouveau bloc</h4>
                      <Button variant="ghost" size="sm" onClick={() => setShowCreatePopup(false)}>
                        <X className="h-4 w-4" />
                      </Button>
                    </div>

                    <div className="text-sm text-gray-600">
                      Position: {newBlocPosition.x}, {newBlocPosition.y}
                    </div>

                    <div className="space-y-3">
                      <div>
                        <Label htmlFor="blocName">Nom du bloc</Label>
                        <Input
                          id="blocName"
                          placeholder="Ex: Nom de l'étudiant"
                          value={newBlocData.nom_bloc}
                          onChange={(e) => setNewBlocData(prev => ({ ...prev, nom_bloc: e.target.value }))}
                        />
                      </div>

                      <div>
                        <Label htmlFor="contentType">Type de contenu</Label>
                        <Select 
                          value={newBlocData.type_contenu} 
                          onValueChange={(value) => setNewBlocData(prev => ({ ...prev, type_contenu: value }))}
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
                          <Label htmlFor="width">Largeur</Label>
                          <Input
                            id="width"
                            type="number"
                            value={newBlocData.largeur}
                            onChange={(e) => setNewBlocData(prev => ({ ...prev, largeur: parseInt(e.target.value) || 150 }))}
                          />
                        </div>
                        <div>
                          <Label htmlFor="height">Hauteur</Label>
                          <Input
                            id="height"
                            type="number"
                            value={newBlocData.hauteur}
                            onChange={(e) => setNewBlocData(prev => ({ ...prev, hauteur: parseInt(e.target.value) || 30 }))}
                          />
                        </div>
                      </div>

                      <div className="flex gap-2">
                        <Button 
                          onClick={handleCreateBloc}
                          className="flex-1 bg-blue-600 hover:bg-blue-700"
                        >
                          <Plus className="h-4 w-4 mr-2" />
                          Créer le bloc
                        </Button>
                        <Button 
                          variant="outline" 
                          onClick={() => setShowCreatePopup(false)}
                        >
                          Annuler
                        </Button>
                      </div>
                    </div>
                  </div>
                </PopoverContent>
              </Popover>
            </div>

            {placingMode && (
              <div className="text-center text-blue-600 bg-blue-50 p-3 rounded-lg border border-blue-200">
                📍 Mode placement actif - Cliquez sur l'image pour positionner le nouveau bloc
              </div>
            )}

            {!placingMode && (
              <div className="text-center text-green-600 bg-green-50 p-3 rounded-lg border border-green-200">
                ✨ Cliquez sur l'image pour créer un nouveau bloc ou sélectionnez un bloc existant
              </div>
            )}
          </div>

          {/* Right Panel - Style Properties */}
          <div className="w-80 flex flex-col space-y-4">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <Palette className="h-5 w-5 mr-2" />
                  Propriétés du Bloc
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {selectedBloc ? (
                  <>
                    <div className="bg-blue-50 p-3 rounded-lg border border-blue-200">
                      <h4 className="font-medium text-blue-800">{selectedBloc.nom_bloc}</h4>
                      <p className="text-sm text-blue-600">Type: {selectedBloc.type_contenu}</p>
                    </div>

                    <Separator />

                    <div className="space-y-3">
                      <div>
                        <Label htmlFor="fontSize">Taille de police</Label>
                        <Input
                          id="fontSize"
                          type="number"
                          value={blocStyles.fontSize}
                          onChange={(e) => handleStyleChange('fontSize', e.target.value)}
                          className="mt-1"
                        />
                      </div>

                      <div>
                        <Label htmlFor="fontFamily">Police</Label>
                        <Select value={blocStyles.fontFamily} onValueChange={(value) => handleStyleChange('fontFamily', value)}>
                          <SelectTrigger className="mt-1">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            {FONT_FAMILIES.map(font => (
                              <SelectItem key={font} value={font}>{font}</SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      </div>

                      <div>
                        <Label htmlFor="color">Couleur du texte</Label>
                        <div className="flex gap-2 mt-1">
                          <Input
                            id="color"
                            type="color"
                            value={blocStyles.color}
                            onChange={(e) => handleStyleChange('color', e.target.value)}
                            className="w-16 h-10 p-1"
                          />
                          <Input
                            value={blocStyles.color}
                            onChange={(e) => handleStyleChange('color', e.target.value)}
                            className="flex-1"
                          />
                        </div>
                      </div>

                      <div>
                        <Label htmlFor="backgroundColor">Couleur de fond</Label>
                        <div className="flex gap-2 mt-1">
                          <Input
                            id="backgroundColor"
                            type="color"
                            value={blocStyles.backgroundColor === 'transparent' ? '#ffffff' : blocStyles.backgroundColor}
                            onChange={(e) => handleStyleChange('backgroundColor', e.target.value)}
                            className="w-16 h-10 p-1"
                          />
                          <Select value={blocStyles.backgroundColor} onValueChange={(value) => handleStyleChange('backgroundColor', value)}>
                            <SelectTrigger className="flex-1">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="transparent">Transparent</SelectItem>
                              <SelectItem value="#ffffff">Blanc</SelectItem>
                              <SelectItem value="#000000">Noir</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                      </div>

                      <div>
                        <Label htmlFor="fontWeight">Style</Label>
                        <div className="flex gap-2 mt-1">
                          <Select value={blocStyles.fontWeight} onValueChange={(value) => handleStyleChange('fontWeight', value)}>
                            <SelectTrigger className="flex-1">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="normal">Normal</SelectItem>
                              <SelectItem value="bold">Gras</SelectItem>
                            </SelectContent>
                          </Select>
                          <Select value={blocStyles.fontStyle} onValueChange={(value) => handleStyleChange('fontStyle', value)}>
                            <SelectTrigger className="flex-1">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="normal">Normal</SelectItem>
                              <SelectItem value="italic">Italique</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                      </div>

                      <div>
                        <Label htmlFor="textAlign">Alignement</Label>
                        <Select value={blocStyles.textAlign} onValueChange={(value) => handleStyleChange('textAlign', value)}>
                          <SelectTrigger className="mt-1">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="left">Gauche</SelectItem>
                            <SelectItem value="center">Centre</SelectItem>
                            <SelectItem value="right">Droite</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>

                      <Button 
                        onClick={applyStylesToBloc}
                        className="w-full bg-blue-600 hover:bg-blue-700"
                      >
                        <Check className="h-4 w-4 mr-2" />
                        Appliquer et sauvegarder
                      </Button>
                    </div>
                  </>
                ) : (
                  <div className="text-center text-gray-500 py-8">
                    <Type className="h-12 w-12 mx-auto mb-3 text-gray-300" />
                    <p>Sélectionnez un bloc pour modifier ses propriétés</p>
                    <p className="text-xs mt-2">ou cliquez sur l'image pour créer un nouveau bloc</p>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Instructions */}
            <Card>
              <CardHeader>
                <CardTitle className="text-sm">Instructions</CardTitle>
              </CardHeader>
              <CardContent className="text-xs space-y-2">
                <p>• <strong>Clic vide</strong> : Créer un nouveau bloc</p>
                <p>• <strong>Clic sur bloc</strong> : Sélectionner</p>
                <p>• <strong>Glisser</strong> : Déplacer un bloc</p>
                <p>• <strong>Coins bleus</strong> : Redimensionner</p>
                <p>• <strong>Molette</strong> : Zoomer</p>
                <p>• <strong>Panneau droit</strong> : Modifier l'apparence</p>
              </CardContent>
            </Card>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
};

export default BlocPositionTool;