import React, { useState, useRef, useEffect, useCallback } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Plus, Edit, Trash2, Check, X, Camera } from 'lucide-react';
import { toast } from 'sonner';
import { supabase } from '@/integrations/supabase/client';
import { generateCanvasCSS, calculateEditorScale, debugFontConversion } from '@/lib/pdf-font-utils';

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

interface UnifiedBlocEditorProps {
  modeleId: string;
  blocs: DocumentBloc[];
  onBlocsChange: (blocs: DocumentBloc[]) => void;
  imageRectoUrl?: string;
  imageVersoUrl?: string;
  formatPage?: string;
  isNewModel: boolean;
}

const CONTENT_TYPES = [
  { value: 'cin', label: 'CIN' },
  { value: 'nom', label: 'Nom' },
  { value: 'prenom', label: 'Prénom' },
  { value: 'email', label: 'Email' },
  { value: 'telephone', label: 'Téléphone' },
  { value: 'whatsapp', label: 'WhatsApp' },
  { value: 'date_naissance', label: 'Date de Naissance' },
  { value: 'lieu_naissance', label: 'Lieu de Naissance' },
  { value: 'adresse', label: 'Adresse' },
  { value: 'date_delivrance', label: 'Date de Délivrance' },
  { value: 'lieu_delivrance', label: 'Lieu de Délivrance' },
  { value: 'serie', label: 'Série' },
  { value: 'id_etudiant', label: 'ID Étudiant' },
  { value: 'photo_candidat', label: 'Photo du Candidat' },
  { value: 'texte_libre', label: 'Texte Personnalisé' }
];

const FONT_FAMILIES = [
  { value: 'Arial', label: 'Arial' },
  { value: 'Helvetica', label: 'Helvetica' },
  { value: 'Times New Roman', label: 'Times New Roman' },
  { value: 'Georgia', label: 'Georgia' },
  { value: 'Verdana', label: 'Verdana' },
  { value: 'Tahoma', label: 'Tahoma' },
  { value: 'Courier New', label: 'Courier New' },
  { value: 'Monaco', label: 'Monaco' },
  { value: 'Roboto', label: 'Roboto' },
  { value: 'Open Sans', label: 'Open Sans' },
  { value: 'Montserrat', label: 'Montserrat' },
  { value: 'Lato', label: 'Lato' },
  { value: 'Poppins', label: 'Poppins' },
  { value: 'Inter', label: 'Inter' },
  { value: 'Source Sans Pro', label: 'Source Sans Pro' },
  { value: 'Raleway', label: 'Raleway' },
  { value: 'Nunito', label: 'Nunito' },
  { value: 'PT Sans', label: 'PT Sans' },
  { value: 'Ubuntu', label: 'Ubuntu' },
  { value: 'Playfair Display', label: 'Playfair Display' },
  { value: 'Merriweather', label: 'Merriweather' },
  { value: 'Oswald', label: 'Oswald' },
  { value: 'Source Code Pro', label: 'Source Code Pro' },
  { value: 'Fira Sans', label: 'Fira Sans' },
  { value: 'Work Sans', label: 'Work Sans' }
];

const UnifiedBlocEditor: React.FC<UnifiedBlocEditorProps> = ({
  modeleId,
  blocs,
  onBlocsChange,
  imageRectoUrl,
  imageVersoUrl,
  formatPage = 'A4',
  isNewModel
}) => {
  // Fonction pour obtenir les dimensions selon le format
  const getCanvasDimensions = (format: string) => {
    switch (format) {
      case 'A4':
        return { width: 600, height: 849 }; // Ratio 0.707
      case 'carte':
        return { width: 600, height: 378 }; // Ratio 1.586  
      case 'A5':
        return { width: 600, height: 425 }; // Ratio 1.414
      default:
        return { width: 600, height: 849 }; // Default A4
    }
  };
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [selectedFace, setSelectedFace] = useState<'recto' | 'verso'>('recto');
  const [isPlacingMode, setIsPlacingMode] = useState(false);
  const [isDrawingPhotoFrame, setIsDrawingPhotoFrame] = useState(false);
  const [isResizingPhotoFrame, setIsResizingPhotoFrame] = useState(false);
  const [resizeHandle, setResizeHandle] = useState<'tl' | 'tr' | 'bl' | 'br' | null>(null);
  const [photoFrameStart, setPhotoFrameStart] = useState<{ x: number; y: number } | null>(null);
  const [photoFrameEnd, setPhotoFrameEnd] = useState<{ x: number; y: number } | null>(null);
  const [mousePosition, setMousePosition] = useState<{ x: number; y: number } | null>(null);
  const [showCrosshair, setShowCrosshair] = useState(false);
  const [placementPosition, setPlacementPosition] = useState<{ x: number; y: number } | null>(null);
  const [showConfirmButton, setShowConfirmButton] = useState(false);
  const [showConfigPopup, setShowConfigPopup] = useState(false);
  const [imageLoaded, setImageLoaded] = useState(false);
  const [scale, setScale] = useState(1);
  const [canvasSize, setCanvasSize] = useState({ width: 600, height: 400 });
  const [editingBloc, setEditingBloc] = useState<DocumentBloc | null>(null);
  const [draggingBloc, setDraggingBloc] = useState<DocumentBloc | null>(null);
  const [dragOffset, setDragOffset] = useState({ x: 0, y: 0 });
  const [tempPositions, setTempPositions] = useState<Record<string, {x: number, y: number}>>({});
  const [tempSizes, setTempSizes] = useState<Record<string, {width: number, height: number}>>({});
  const [originalPositions, setOriginalPositions] = useState<Record<string, {x: number, y: number}>>({});
  const [showGrid, setShowGrid] = useState(false);
  const [isDraggingPopup, setIsDraggingPopup] = useState(false);
  const [popupPosition, setPopupPosition] = useState({ x: 0, y: 0 });
  const [dragStartPosition, setDragStartPosition] = useState({ x: 0, y: 0 });
  
  const [blocConfig, setBlocConfig] = useState({
    type_contenu: 'nom',
    fontSize: 14,
    fontWeight: 'normal',
    fontStyle: 'normal',
    fontFamily: 'Arial',
    color: '#000000',
    textAlign: 'left',
    verticalAlign: 'top',
    styles: {} as any
  });

  const image = useRef(new Image());
  const currentImageUrl = selectedFace === 'recto' ? imageRectoUrl : imageVersoUrl;

  useEffect(() => {
    if (!currentImageUrl) {
      setImageLoaded(false);
      return;
    }
    
    console.log('Chargement de l\'image:', currentImageUrl);
    image.current.onload = () => {
      console.log('Image chargée avec succès, dimensions:', image.current.naturalWidth, 'x', image.current.naturalHeight);
      setImageLoaded(true);
      calculateCanvasSize();
    };
    image.current.onerror = (err) => {
      console.error('Erreur lors du chargement de l\'image:', err);
      setImageLoaded(false);
      toast.error('Erreur lors du chargement de l\'image');
    };
    image.current.crossOrigin = 'anonymous'; // Ajout pour éviter les problèmes CORS
    image.current.src = currentImageUrl;
  }, [currentImageUrl]);

  useEffect(() => {
    console.log('DrawCanvas déclenché, imageLoaded:', imageLoaded, 'currentImageUrl:', currentImageUrl);
    if (imageLoaded) {
      drawCanvas();
    }
  }, [imageLoaded, blocs, placementPosition, showConfirmButton, selectedFace, scale, tempPositions, draggingBloc, isPlacingMode, showCrosshair, mousePosition, blocConfig, showGrid, editingBloc]);

  const calculateCanvasSize = () => {
    const { width: formatWidth, height: formatHeight } = getCanvasDimensions(formatPage);
    const maxWidth = 700; // Container size
    const maxHeight = 500;
    
    // Calculer le scale pour adapter les dimensions du format au conteneur
    const scaleX = maxWidth / formatWidth;
    const scaleY = maxHeight / formatHeight;
    const calculatedScale = Math.min(scaleX, scaleY, 1); // Ne pas agrandir au-delà de la taille originale
    
    setScale(calculatedScale);
    setCanvasSize({ 
      width: Math.floor(formatWidth * calculatedScale), 
      height: Math.floor(formatHeight * calculatedScale) 
    });
  };

  const drawCanvas = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas || !imageLoaded) {
      console.log('Canvas ou image non disponible:', { canvas: !!canvas, imageLoaded, currentImageUrl });
      return;
    }

    const ctx = canvas.getContext('2d');
    if (!ctx) {
      console.log('Contexte canvas non disponible');
      return;
    }

    console.log('Début du dessin canvas, dimensions:', canvas.width, 'x', canvas.height);

    // Clear canvas
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // Draw background image
    if (image.current && image.current.complete && image.current.naturalWidth > 0) {
      console.log('Dessin de l\'image de fond, dimensions originales:', image.current.naturalWidth, 'x', image.current.naturalHeight);
      ctx.drawImage(image.current, 0, 0, canvas.width, canvas.height);
    } else {
      console.log('Image non prête:', {
        imageExists: !!image.current,
        complete: image.current?.complete,
        naturalWidth: image.current?.naturalWidth
      });
    }

    // Draw reference grid if enabled
    if (showGrid) {
      ctx.strokeStyle = 'rgba(102, 102, 102, 0.6)'; // Plus visible
      ctx.lineWidth = 1;
      ctx.setLineDash([]);
      
      // Calculer l'espacement selon le format réel
      const baseGridSpacing = 50; // 50px en coordonnées originales
      const scaledSpacing = baseGridSpacing * scale;
      
      console.log('Affichage grille:', { showGrid, scaledSpacing, canvasWidth: canvas.width, canvasHeight: canvas.height });
      
      // Vertical lines
      for (let x = 0; x <= canvas.width; x += scaledSpacing) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, canvas.height);
        ctx.stroke();
      }
      
      // Horizontal lines
      for (let y = 0; y <= canvas.height; y += scaledSpacing) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(canvas.width, y);
        ctx.stroke();
      }
      
      console.log('Grille dessinée avec espacement:', scaledSpacing);
    }

    // Draw crosshair guides when in placing mode
    if (isPlacingMode && showCrosshair && mousePosition) {
      const mouseX = mousePosition.x * scale;
      const mouseY = mousePosition.y * scale;
      
      // Vérifier que les coordonnées sont dans les limites du canvas
      if (mouseX >= 0 && mouseX <= canvas.width && mouseY >= 0 && mouseY <= canvas.height) {
        // Vertical guide line
        ctx.strokeStyle = 'rgba(239, 68, 68, 0.8)';
        ctx.lineWidth = 2;
        ctx.setLineDash([8, 4]);
        ctx.beginPath();
        ctx.moveTo(mouseX, 0);
        ctx.lineTo(mouseX, canvas.height);
        ctx.stroke();
        
        // Horizontal guide line
        ctx.beginPath();
        ctx.moveTo(0, mouseY);
        ctx.lineTo(canvas.width, mouseY);
        ctx.stroke();
        ctx.setLineDash([]);
        
        // Intersection point indicator
        ctx.fillStyle = '#ef4444';
        ctx.beginPath();
        ctx.arc(mouseX, mouseY, 6, 0, 2 * Math.PI);
        ctx.fill();
        
        // Position coordinates display
        ctx.fillStyle = 'rgba(55, 65, 81, 0.9)';
        ctx.font = `normal normal ${12}px Arial`;
        const coordText = `${Math.round(mousePosition.x)}, ${Math.round(mousePosition.y)}`;
        const textWidth = ctx.measureText(coordText).width;
        ctx.fillRect(mouseX + 10, mouseY - 25, textWidth + 10, 20);
        ctx.fillStyle = '#ffffff';
        ctx.fillText(coordText, mouseX + 15, mouseY - 10);
      }
    }

    // Draw existing blocs for current face
    const faceBlocs = blocs.filter(bloc => bloc.face === selectedFace);
    
    faceBlocs.forEach(bloc => {
      // Utiliser la position temporaire si elle existe, sinon la position normale
      const tempPos = tempPositions[bloc.id];
      const anchorX = (tempPos ? tempPos.x : bloc.position_x) * scale;
      const anchorY = (tempPos ? tempPos.y : bloc.position_y) * scale;
      
      // Style différent si le bloc est en cours de déplacement
      const isDragging = draggingBloc?.id === bloc.id;
      
      // Draw anchor point indicator
      ctx.fillStyle = isDragging ? '#ef4444' : '#3b82f6';
      ctx.beginPath();
      ctx.arc(anchorX, anchorY, 6, 0, 2 * Math.PI);
      ctx.fill();
      
      // Draw text sample - utiliser les styles du blocConfig si on édite ce bloc
      const isEditingThisBloc = editingBloc?.id === bloc.id;
      const rawStyles = isEditingThisBloc ? {
        color: blocConfig.color,
        fontSize: blocConfig.fontSize,
        fontWeight: blocConfig.fontWeight,
        fontStyle: blocConfig.fontStyle,
        fontFamily: blocConfig.fontFamily,
        textAlign: blocConfig.textAlign,
        verticalAlign: blocConfig.verticalAlign
      } : (typeof bloc.styles_css === 'string' ? JSON.parse(bloc.styles_css) : bloc.styles_css);
      
      // 🔧 CONVERSION JSPDF: Utiliser les mêmes règles que le PDF pour une cohérence parfaite
      console.log(`🎨 BLOC "${bloc.nom_bloc}": fontSize stocké=${rawStyles?.fontSize}pt → conversion canvas...`);
      const canvasStyles = generateCanvasCSS(rawStyles, formatPage, scale);
      
      ctx.fillStyle = canvasStyles.color;
      ctx.font = `${canvasStyles.fontStyle} ${canvasStyles.fontWeight} ${canvasStyles.fontSize} ${canvasStyles.fontFamily}`;
      
      // Debug pour vérifier la conversion
      if (isEditingThisBloc) {
        debugFontConversion(rawStyles.fontSize || 14, formatPage);
      }
      
      // Get display text based on type
      const contentType = isEditingThisBloc ? blocConfig.type_contenu : bloc.type_contenu;
      
      // Special rendering for photo candidat blocks
      if (contentType === 'photo_candidat') {
        // Get current size (from temp or original)
        const currentSize = tempSizes[bloc.id] || { width: bloc.largeur, height: bloc.hauteur };
        const rectWidth = currentSize.width * scale;
        const rectHeight = currentSize.height * scale;
        
        ctx.fillStyle = '#3b82f6'; // Bleu solide
        ctx.strokeStyle = '#1d4ed8'; // Bordure bleu foncé
        ctx.lineWidth = 2;
        
        ctx.fillRect(anchorX, anchorY, rectWidth, rectHeight);
        ctx.strokeRect(anchorX, anchorY, rectWidth, rectHeight);
        
        // Draw 4 corner points (resize handles)
        const cornerSize = 8 * scale; // Plus gros pour faciliter l'interaction
        ctx.fillStyle = '#ffffff';
        ctx.strokeStyle = '#1d4ed8';
        ctx.lineWidth = 2;
        
        // Top-left corner
        ctx.fillRect(anchorX - cornerSize/2, anchorY - cornerSize/2, cornerSize, cornerSize);
        ctx.strokeRect(anchorX - cornerSize/2, anchorY - cornerSize/2, cornerSize, cornerSize);
        
        // Top-right corner  
        ctx.fillRect(anchorX + rectWidth - cornerSize/2, anchorY - cornerSize/2, cornerSize, cornerSize);
        ctx.strokeRect(anchorX + rectWidth - cornerSize/2, anchorY - cornerSize/2, cornerSize, cornerSize);
        
        // Bottom-left corner
        ctx.fillRect(anchorX - cornerSize/2, anchorY + rectHeight - cornerSize/2, cornerSize, cornerSize);
        ctx.strokeRect(anchorX - cornerSize/2, anchorY + rectHeight - cornerSize/2, cornerSize, cornerSize);
        
        // Bottom-right corner
        ctx.fillRect(anchorX + rectWidth - cornerSize/2, anchorY + rectHeight - cornerSize/2, cornerSize, cornerSize);
        ctx.strokeRect(anchorX + rectWidth - cornerSize/2, anchorY + rectHeight - cornerSize/2, cornerSize, cornerSize);
        
        // Draw camera icon in center (white text on blue background)
        ctx.fillStyle = '#ffffff';
        ctx.font = `normal normal ${16 * scale}px Arial`;
        ctx.textAlign = 'center';
        ctx.fillText('📷', anchorX + rectWidth/2, anchorY + rectHeight/2 + 8*scale);
        ctx.textAlign = 'left';
        
        // Draw label above rectangle
        ctx.fillStyle = '#1d4ed8';
        ctx.font = `normal normal ${10 * scale}px Arial`;
        ctx.fillText(bloc.nom_bloc, anchorX, anchorY - 10);
        
        // Show resize cursor hints
        if (isResizingPhotoFrame && draggingBloc?.id === bloc.id) {
          ctx.fillStyle = 'rgba(29, 78, 216, 0.1)';
          ctx.fillRect(anchorX - 5, anchorY - 5, rectWidth + 10, rectHeight + 10);
        }
        
      } else {
        // Regular text rendering for other bloc types
        const displayText = contentType === 'cin' ? 'CIN123456' :
                           contentType === 'nom' ? 'DUPONT' :
                           contentType === 'prenom' ? 'Jean' :
                           contentType === 'email' ? 'jean.dupont@email.com' :
                           contentType === 'telephone' ? '06 12 34 56 78' :
                           contentType === 'whatsapp' ? '06 12 34 56 78' :
                           contentType === 'date_naissance' ? '01/01/1990' :
                           contentType === 'lieu_naissance' ? 'Paris' :
                           contentType === 'adresse' ? '123 Rue Example, Paris' :
                           contentType === 'date_delivrance' ? '15/12/2024' :
                            contentType === 'lieu_delivrance' ? 'Casablanca' :
                            contentType === 'serie' ? 'SERIE001' :
                            contentType === 'id_etudiant' ? 'ETU-2024-0001' :
                            bloc.nom_bloc;
        
        // Calculate text position based on alignment from styles
        const textAlign = canvasStyles.textAlign || 'left';
        const verticalAlign = canvasStyles.verticalAlign || 'top';
        
        let textX = anchorX;
        let textY = anchorY;
        
        // Set text alignment
        ctx.textAlign = textAlign === 'center' ? 'center' : textAlign === 'right' ? 'right' : 'left';
        
        // Vertical alignment relative to anchor point - utiliser la taille convertie
        const fontSizeInPixels = parseFloat(canvasStyles.fontSize);
        if (verticalAlign === 'middle') {
          textY = anchorY + fontSizeInPixels / 4; // Center text vertically on anchor
        } else if (verticalAlign === 'bottom') {
          textY = anchorY; // Anchor point at text bottom
        } else {
          textY = anchorY + fontSizeInPixels; // Anchor point at text top (default)
        }
        
        ctx.fillText(displayText, textX, textY);
        
        // Reset text alignment for other drawings
        ctx.textAlign = 'left';
        
        // Draw label above anchor point
        ctx.fillStyle = '#3b82f6';
        ctx.font = `normal normal ${10 * scale}px Arial`;
        ctx.fillText(bloc.nom_bloc, anchorX + 10, anchorY - 10);
      }
      
      // Visual selection area for drag detection (invisible but used for hit testing)
      const hitArea = 15; // Pixels around anchor point for easier selection
      if (isDragging) {
        ctx.strokeStyle = 'rgba(59, 130, 246, 0.3)';
        ctx.lineWidth = 2;
        ctx.setLineDash([3, 3]);
        ctx.strokeRect(anchorX - hitArea, anchorY - hitArea, hitArea * 2, hitArea * 2);
        ctx.setLineDash([]);
      }
    });

    // Draw placement indicator if position confirmed
    if (placementPosition && showConfirmButton) {
      const x = placementPosition.x * scale;
      const y = placementPosition.y * scale;
      
      // Draw larger anchor point for new placement
      ctx.fillStyle = '#22c55e';
      ctx.beginPath();
      ctx.arc(x, y, 8, 0, 2 * Math.PI);
      ctx.fill();
      
      // Draw pulsing ring around anchor
      ctx.strokeStyle = '#22c55e';
      ctx.lineWidth = 3;
      ctx.setLineDash([]);
      ctx.beginPath();
      ctx.arc(x, y, 15, 0, 2 * Math.PI);
      ctx.stroke();
      
      // Draw preview text based on current config - utiliser la conversion jsPDF
      const previewCanvasStyles = generateCanvasCSS(blocConfig, formatPage, scale);
      ctx.fillStyle = previewCanvasStyles.color;
      ctx.font = `${previewCanvasStyles.fontStyle} ${previewCanvasStyles.fontWeight} ${previewCanvasStyles.fontSize} ${previewCanvasStyles.fontFamily}`;
      
      const previewText = blocConfig.type_contenu === 'cin' ? 'CIN123456' :
                         blocConfig.type_contenu === 'nom' ? 'DUPONT' :
                         blocConfig.type_contenu === 'prenom' ? 'Jean' :
                         blocConfig.type_contenu === 'email' ? 'jean.dupont@email.com' :
                         blocConfig.type_contenu === 'telephone' ? '06 12 34 56 78' :
                         blocConfig.type_contenu === 'whatsapp' ? '06 12 34 56 78' :
                         blocConfig.type_contenu === 'date_naissance' ? '01/01/1990' :
                         blocConfig.type_contenu === 'lieu_naissance' ? 'Paris' :
                         blocConfig.type_contenu === 'adresse' ? '123 Rue Example, Paris' :
                         blocConfig.type_contenu === 'date_delivrance' ? '15/12/2024' :
                         blocConfig.type_contenu === 'lieu_delivrance' ? 'Casablanca' :
                         blocConfig.type_contenu === 'serie' ? 'SERIE001' :
                         blocConfig.type_contenu === 'id_etudiant' ? 'ETU-2024-0001' :
                         blocConfig.type_contenu === 'photo_candidat' ? '[PHOTO]' :
                         'Aperçu texte';
      
      // Apply alignment for preview
      let previewX = x;
      let previewY = y;
      
      // Set text alignment
      ctx.textAlign = blocConfig.textAlign === 'center' ? 'center' : 
                     blocConfig.textAlign === 'right' ? 'right' : 'left';
      
      // Vertical alignment - utiliser la taille convertie
      const previewFontSize = parseFloat(previewCanvasStyles.fontSize);
      if (blocConfig.verticalAlign === 'middle') {
        previewY = y + previewFontSize / 4; // Center text vertically on anchor
      } else if (blocConfig.verticalAlign === 'bottom') {
        previewY = y; // Anchor point at text bottom
      } else {
        previewY = y + previewFontSize; // Anchor point at text top (default)
      }
      
      ctx.fillText(previewText, previewX, previewY);
      ctx.textAlign = 'left'; // Reset
      
      // Draw label
      ctx.fillStyle = '#22c55e';
      ctx.font = `normal normal ${12 * scale}px Arial`;
      ctx.fillText('Nouveau point d\'ancrage', x + 20, y - 10);
    }

    // Draw photo frame preview if in drawing mode
    if (isDrawingPhotoFrame && photoFrameStart && photoFrameEnd) {
      const x1 = photoFrameStart.x * scale;
      const y1 = photoFrameStart.y * scale;
      const x2 = photoFrameEnd.x * scale;
      const y2 = photoFrameEnd.y * scale;
      
      const rectX = Math.min(x1, x2);
      const rectY = Math.min(y1, y2);
      const rectWidth = Math.abs(x2 - x1);
      const rectHeight = Math.abs(y2 - y1);
      
      // Draw photo frame rectangle with blue fill
      ctx.fillStyle = '#3b82f6'; // Bleu solide
      ctx.strokeStyle = '#1d4ed8'; // Bordure bleu foncé
      ctx.lineWidth = 2;
      
      ctx.fillRect(rectX, rectY, rectWidth, rectHeight);
      ctx.strokeRect(rectX, rectY, rectWidth, rectHeight);
      
      // Draw 4 corner points
      const cornerSize = 6 * scale;
      ctx.fillStyle = '#ffffff';
      ctx.strokeStyle = '#1d4ed8';
      ctx.lineWidth = 1;
      
      // Top-left corner
      ctx.fillRect(rectX - cornerSize/2, rectY - cornerSize/2, cornerSize, cornerSize);
      ctx.strokeRect(rectX - cornerSize/2, rectY - cornerSize/2, cornerSize, cornerSize);
      
      // Top-right corner
      ctx.fillRect(rectX + rectWidth - cornerSize/2, rectY - cornerSize/2, cornerSize, cornerSize);
      ctx.strokeRect(rectX + rectWidth - cornerSize/2, rectY - cornerSize/2, cornerSize, cornerSize);
      
      // Bottom-left corner
      ctx.fillRect(rectX - cornerSize/2, rectY + rectHeight - cornerSize/2, cornerSize, cornerSize);
      ctx.strokeRect(rectX - cornerSize/2, rectY + rectHeight - cornerSize/2, cornerSize, cornerSize);
      
      // Bottom-right corner
      ctx.fillRect(rectX + rectWidth - cornerSize/2, rectY + rectHeight - cornerSize/2, cornerSize, cornerSize);
      ctx.strokeRect(rectX + rectWidth - cornerSize/2, rectY + rectHeight - cornerSize/2, cornerSize, cornerSize);
      
      // Draw camera icon in center (white text on blue background)
      ctx.fillStyle = '#ffffff';
      ctx.font = `normal normal ${16 * scale}px Arial`;
      ctx.textAlign = 'center';
      ctx.fillText('📷', rectX + rectWidth/2, rectY + rectHeight/2 + 8*scale);
      ctx.textAlign = 'left';
      
      // Draw dimensions
      ctx.fillStyle = '#1d4ed8';
      ctx.font = `normal normal ${10 * scale}px Arial`;
      const dimensions = `${Math.round(Math.abs(photoFrameEnd.x - photoFrameStart.x))}×${Math.round(Math.abs(photoFrameEnd.y - photoFrameStart.y))}px`;
      ctx.fillText(dimensions, rectX, rectY - 5);
    }
  }, [blocs, selectedFace, imageLoaded, placementPosition, showConfirmButton, scale, tempPositions, draggingBloc, isPlacingMode, showCrosshair, mousePosition, blocConfig, showGrid]);

  // Fonction pour gérer le zoom
  const handleZoom = (delta: number) => {
    setScale(prevScale => {
      const newScale = Math.max(0.3, Math.min(2, prevScale + delta));
      console.log('Nouveau zoom:', newScale);
      return newScale;
    });
  };

  // Recalculer la taille du canvas quand le zoom change
  useEffect(() => {
    if (imageLoaded) {
      const { width: formatWidth, height: formatHeight } = getCanvasDimensions(formatPage);
      const newCanvasSize = { 
        width: Math.floor(formatWidth * scale), 
        height: Math.floor(formatHeight * scale) 
      };
      console.log('Nouvelle taille canvas:', newCanvasSize, 'zoom:', scale);
      setCanvasSize(newCanvasSize);
      
      // Forcer le redessin après le changement de taille
      setTimeout(() => {
        drawCanvas();
      }, 10);
    }
  }, [scale, imageLoaded, formatPage, drawCanvas]);

  const getCanvasPosition = useCallback((e: React.MouseEvent) => {
    const canvas = canvasRef.current;
    if (!canvas) return { x: 0, y: 0 };

    // Cache the bounding rect to avoid forced reflows
    const rect = canvas.getBoundingClientRect();
    // Corriger le calcul des coordonnées pour le zoom
    const x = (e.clientX - rect.left) / scale;
    const y = (e.clientY - rect.top) / scale;
    
    return { x: Math.max(0, x), y: Math.max(0, y) };
  }, [scale]);

  const getResizeHandle = (pos: { x: number; y: number }, bloc: DocumentBloc) => {
    if (bloc.type_contenu !== 'photo_candidat') return null;
    
    const cornerSize = 8; // Taille des poignées
    const tolerance = 5; // Tolérance pour la détection
    
    const currentSize = tempSizes[bloc.id] || { width: bloc.largeur, height: bloc.hauteur };
    
    // Top-left
    if (Math.abs(pos.x - bloc.position_x) <= tolerance && Math.abs(pos.y - bloc.position_y) <= tolerance) {
      return 'tl';
    }
    // Top-right
    if (Math.abs(pos.x - (bloc.position_x + currentSize.width)) <= tolerance && Math.abs(pos.y - bloc.position_y) <= tolerance) {
      return 'tr';
    }
    // Bottom-left
    if (Math.abs(pos.x - bloc.position_x) <= tolerance && Math.abs(pos.y - (bloc.position_y + currentSize.height)) <= tolerance) {
      return 'bl';
    }
    // Bottom-right
    if (Math.abs(pos.x - (bloc.position_x + currentSize.width)) <= tolerance && Math.abs(pos.y - (bloc.position_y + currentSize.height)) <= tolerance) {
      return 'br';
    }
    
    return null;
  };

  const isInsidePhotoFrame = (pos: { x: number; y: number }, bloc: DocumentBloc) => {
    if (bloc.type_contenu !== 'photo_candidat') return false;
    
    const currentSize = tempSizes[bloc.id] || { width: bloc.largeur, height: bloc.hauteur };
    return pos.x >= bloc.position_x && pos.x <= bloc.position_x + currentSize.width &&
           pos.y >= bloc.position_y && pos.y <= bloc.position_y + currentSize.height;
  };

  const handleCanvasMouseDown = (e: React.MouseEvent) => {
    if (draggingBloc) return;
    
    const pos = getCanvasPosition(e);
    
    // Mode dessin de cadre photo
    if (isDrawingPhotoFrame) {
      setPhotoFrameStart(pos);
      setPhotoFrameEnd(null);
      return;
    }
    
    if (!isPlacingMode) {
      // Check for photo frame interactions first
      const faceBlocs = blocs.filter(bloc => bloc.face === selectedFace);
      
      for (const bloc of faceBlocs) {
        if (bloc.type_contenu === 'photo_candidat') {
          // Check for resize handle
          const handle = getResizeHandle(pos, bloc);
          if (handle) {
            setIsResizingPhotoFrame(true);
            setResizeHandle(handle);
            setDraggingBloc(bloc);
            return;
          }
          
          // Check if inside photo frame for moving
          if (isInsidePhotoFrame(pos, bloc)) {
            setDraggingBloc(bloc);
            setDragOffset({
              x: pos.x - bloc.position_x,
              y: pos.y - bloc.position_y
            });
            setOriginalPositions(prev => ({
              ...prev,
              [bloc.id]: { x: bloc.position_x, y: bloc.position_y }
            }));
            return;
          }
        }
      }
      
      // Check for regular text blocs
      const clickedBloc = faceBlocs.find(bloc => {
        if (bloc.type_contenu === 'photo_candidat') return false;
        const distance = Math.sqrt(Math.pow(pos.x - bloc.position_x, 2) + Math.pow(pos.y - bloc.position_y, 2));
        return distance <= 15;
      });
      
      if (clickedBloc) {
        setDraggingBloc(clickedBloc);
        setDragOffset({
          x: pos.x - clickedBloc.position_x,
          y: pos.y - clickedBloc.position_y
        });
        setOriginalPositions(prev => ({
          ...prev,
          [clickedBloc.id]: { x: clickedBloc.position_x, y: clickedBloc.position_y }
        }));
      }
      return;
    }

    // Single point placement for new bloc
    setPlacementPosition(pos);
    setShowConfirmButton(true);
    setShowCrosshair(false);
  };

  const handleCanvasMouseMove = (e: React.MouseEvent) => {
    const pos = getCanvasPosition(e);
    
    // Mode dessin de cadre photo
    if (isDrawingPhotoFrame && photoFrameStart) {
      setPhotoFrameEnd(pos);
      return;
    }
    
    // Update mouse position for crosshair guides uniquement en mode placement
    if (isPlacingMode && !showConfirmButton) {
      setMousePosition(pos);
      setShowCrosshair(true);
    }
    
    if (draggingBloc) {
      e.preventDefault();
      
      if (isResizingPhotoFrame && resizeHandle) {
        // Handle resizing
        const currentSize = tempSizes[draggingBloc.id] || { width: draggingBloc.largeur, height: draggingBloc.hauteur };
        const currentPos = tempPositions[draggingBloc.id] || { x: draggingBloc.position_x, y: draggingBloc.position_y };
        
        let newX = currentPos.x;
        let newY = currentPos.y;
        let newWidth = currentSize.width;
        let newHeight = currentSize.height;
        
        switch (resizeHandle) {
          case 'tl': // Top-left
            newWidth = Math.max(20, currentPos.x + currentSize.width - pos.x);
            newHeight = Math.max(20, currentPos.y + currentSize.height - pos.y);
            newX = pos.x;
            newY = pos.y;
            break;
          case 'tr': // Top-right
            newWidth = Math.max(20, pos.x - currentPos.x);
            newHeight = Math.max(20, currentPos.y + currentSize.height - pos.y);
            newY = pos.y;
            break;
          case 'bl': // Bottom-left
            newWidth = Math.max(20, currentPos.x + currentSize.width - pos.x);
            newHeight = Math.max(20, pos.y - currentPos.y);
            newX = pos.x;
            break;
          case 'br': // Bottom-right
            newWidth = Math.max(20, pos.x - currentPos.x);
            newHeight = Math.max(20, pos.y - currentPos.y);
            break;
        }
        
        setTempPositions(prev => ({
          ...prev,
          [draggingBloc.id]: { x: Math.max(0, newX), y: Math.max(0, newY) }
        }));
        
        setTempSizes(prev => ({
          ...prev,
          [draggingBloc.id]: { width: newWidth, height: newHeight }
        }));
        
      } else {
        // Handle normal dragging
        const newX = Math.max(0, pos.x - dragOffset.x);
        const newY = Math.max(0, pos.y - dragOffset.y);
        
        setTempPositions(prev => ({
          ...prev,
          [draggingBloc.id]: { x: newX, y: newY }
        }));
      }
    }
  };

  const handleCanvasMouseUp = (e: React.MouseEvent) => {
    // Mode dessin de cadre photo
    if (isDrawingPhotoFrame && photoFrameStart && photoFrameEnd) {
      const width = Math.abs(photoFrameEnd.x - photoFrameStart.x);
      const height = Math.abs(photoFrameEnd.y - photoFrameStart.y);
      
      if (width > 10 && height > 10) { // Rectangle minimum
        const x = Math.min(photoFrameStart.x, photoFrameEnd.x);
        const y = Math.min(photoFrameStart.y, photoFrameEnd.y);
        
        // Créer le bloc photo directement
        const newBloc: DocumentBloc = {
          id: `temp_${Date.now()}`,
          nom_bloc: `photo_candidat_${Date.now()}`,
          type_contenu: 'photo_candidat',
          face: selectedFace,
          position_x: Math.round(x),
          position_y: Math.round(y),
          largeur: Math.round(width),
          hauteur: Math.round(height),
          styles_css: {
            fontSize: 14,
            fontFamily: 'Arial',
            fontWeight: 'normal',
            fontStyle: 'normal',
            color: '#000000',
            textAlign: 'left',
            backgroundColor: 'transparent'
          },
          ordre_affichage: blocs.length + 1
        };

        onBlocsChange([...blocs, newBloc]);
        toast.success('Cadre photo créé localement - Cliquez sur "Mettre à jour" pour sauvegarder');
        
        // Réinitialiser le mode dessin
        setIsDrawingPhotoFrame(false);
        setPhotoFrameStart(null);
        setPhotoFrameEnd(null);
      }
      return;
    }
    
    if (draggingBloc) {
      // Confirmer la nouvelle position et/ou taille
      const tempPos = tempPositions[draggingBloc.id];
      const tempSize = tempSizes[draggingBloc.id];
      
      if (tempPos || tempSize) {
        const updatedBlocs = blocs.map(bloc => {
          if (bloc.id === draggingBloc.id) {
            const updates: any = { ...bloc };
            if (tempPos) {
              updates.position_x = Math.round(tempPos.x);
              updates.position_y = Math.round(tempPos.y);
            }
            if (tempSize) {
              updates.largeur = Math.round(tempSize.width);
              updates.hauteur = Math.round(tempSize.height);
            }
            return updates;
          }
          return bloc;
        });
        onBlocsChange(updatedBlocs);
        toast.success('Modifications appliquées localement - Cliquez sur "Mettre à jour" pour sauvegarder');
      }
      
      // Cleanup
      setTempPositions(prev => {
        const newPositions = { ...prev };
        delete newPositions[draggingBloc.id];
        return newPositions;
      });
      setTempSizes(prev => {
        const newSizes = { ...prev };
        delete newSizes[draggingBloc.id];
        return newSizes;
      });
      setOriginalPositions(prev => {
        const newPositions = { ...prev };
        delete newPositions[draggingBloc.id];
        return newPositions;
      });
      setDraggingBloc(null);
      setDragOffset({ x: 0, y: 0 });
      setIsResizingPhotoFrame(false);
      setResizeHandle(null);
    }
  };

  const handleCanvasMouseLeave = () => {
    setShowCrosshair(false);
    setMousePosition(null);
  };

  const handleCanvasDoubleClick = (e: React.MouseEvent) => {
    const pos = getCanvasPosition(e);
    
    // Check if double-clicking on an existing bloc anchor point
    const faceBlocs = blocs.filter(bloc => bloc.face === selectedFace);
    
    const clickedBloc = faceBlocs.find(bloc => {
      const distance = Math.sqrt(Math.pow(pos.x - bloc.position_x, 2) + Math.pow(pos.y - bloc.position_y, 2));
      return distance <= 15; // 15px radius around anchor point
    });
    
    if (clickedBloc) {
      // Open edit popup for the bloc
      setEditingBloc(clickedBloc);
      setBlocConfig({
        type_contenu: clickedBloc.type_contenu,
        fontSize: (typeof clickedBloc.styles_css === 'string' ? JSON.parse(clickedBloc.styles_css) : clickedBloc.styles_css)?.fontSize || 14,
        fontWeight: (typeof clickedBloc.styles_css === 'string' ? JSON.parse(clickedBloc.styles_css) : clickedBloc.styles_css)?.fontWeight || 'normal',
        fontStyle: (typeof clickedBloc.styles_css === 'string' ? JSON.parse(clickedBloc.styles_css) : clickedBloc.styles_css)?.fontStyle || 'normal',
        fontFamily: (typeof clickedBloc.styles_css === 'string' ? JSON.parse(clickedBloc.styles_css) : clickedBloc.styles_css)?.fontFamily || 'Arial',
        color: (typeof clickedBloc.styles_css === 'string' ? JSON.parse(clickedBloc.styles_css) : clickedBloc.styles_css)?.color || '#000000',
        textAlign: (typeof clickedBloc.styles_css === 'string' ? JSON.parse(clickedBloc.styles_css) : clickedBloc.styles_css)?.textAlign || 'left',
        verticalAlign: (typeof clickedBloc.styles_css === 'string' ? JSON.parse(clickedBloc.styles_css) : clickedBloc.styles_css)?.verticalAlign || 'top',
        styles: (typeof clickedBloc.styles_css === 'string' ? JSON.parse(clickedBloc.styles_css) : clickedBloc.styles_css) || {}
      });
      setShowConfigPopup(true);
    }
  };

  const handleAddBloc = () => {
    if (isNewModel) {
      toast.error('Sauvegardez d\'abord le modèle pour ajouter des blocs');
      return;
    }
    
    setIsPlacingMode(true);
    setIsDrawingPhotoFrame(false);
    setPlacementPosition(null);
    setShowConfirmButton(false);
    setShowConfigPopup(false);
  };

  const handleAddPhotoFrame = () => {
    if (isNewModel) {
      toast.error('Sauvegardez d\'abord le modèle pour ajouter des blocs');
      return;
    }
    
    setIsDrawingPhotoFrame(true);
    setIsPlacingMode(false);
    setPhotoFrameStart(null);
    setPhotoFrameEnd(null);
    setShowConfirmButton(false);
    setShowConfigPopup(false);
    setBlocConfig({
      type_contenu: 'photo_candidat',
      fontSize: 14,
      fontWeight: 'normal',
      fontStyle: 'normal',
      fontFamily: 'Arial',
      color: '#000000',
      textAlign: 'left',
      verticalAlign: 'top',
      styles: {}
    });
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
    setShowCrosshair(false);
    setMousePosition(null);
    setEditingBloc(null);
  };

  const handleClosePopup = () => {
    setShowConfigPopup(false);
    setEditingBloc(null);
    // NE PAS réinitialiser isPlacingMode pour permettre de continuer à ajouter des blocs
  };

  const handleValidateBloc = (e?: React.MouseEvent) => {
    // Empêcher la propagation de l'événement vers le formulaire parent
    if (e) {
      e.preventDefault();
      e.stopPropagation();
    }
    
    if (editingBloc) {
      // Update existing bloc localement seulement
      const updatedBlocs = blocs.map(b => 
        b.id === editingBloc.id 
          ? {
              ...b,
              type_contenu: blocConfig.type_contenu,
                styles_css: {
                  fontSize: blocConfig.fontSize,
                  fontFamily: blocConfig.fontFamily,
                  fontWeight: blocConfig.fontWeight,
                  fontStyle: blocConfig.fontStyle,
                  color: blocConfig.color,
                  textAlign: blocConfig.textAlign,
                  verticalAlign: blocConfig.verticalAlign,
                  backgroundColor: 'transparent'
                }
            }
          : b
      );
      onBlocsChange(updatedBlocs);
      
      toast.success('Bloc modifié localement - Cliquez sur "Mettre à jour" pour sauvegarder');
      setEditingBloc(null);
      setShowConfigPopup(false); // FERMER le popup après modification
    } else if (placementPosition) {
      // Create new bloc localement seulement
      const newBloc: DocumentBloc = {
        id: `temp_${Date.now()}`, // ID temporaire
        nom_bloc: `${blocConfig.type_contenu}_${Date.now()}`,
        type_contenu: blocConfig.type_contenu,
        face: selectedFace,
        position_x: Math.round(placementPosition.x),
        position_y: Math.round(placementPosition.y),
        largeur: 100, // Default width for anchor-based positioning
        hauteur: 25, // Default height for anchor-based positioning
        styles_css: {
          fontSize: blocConfig.fontSize,
          fontFamily: blocConfig.fontFamily,
          fontWeight: blocConfig.fontWeight,
          fontStyle: blocConfig.fontStyle,
          color: blocConfig.color,
          textAlign: 'left',
          backgroundColor: 'transparent'
        },
        ordre_affichage: blocs.length + 1
      };

      onBlocsChange([...blocs, newBloc]);
      
      toast.success('Bloc créé localement - Cliquez sur "Mettre à jour" pour sauvegarder');
      
      // FORCER l'arrêt du mode placement - obliger à re-cliquer sur "Ajouter un Bloc"
      setIsPlacingMode(false); // STOPPER le mode placement
      setPlacementPosition(null);
      setShowConfirmButton(false);
      setShowConfigPopup(false); // FERMER le popup
      
      // Reset bloc config pour le prochain bloc
      setBlocConfig({
        type_contenu: 'nom',
        fontSize: 14,
        fontWeight: 'normal',
        fontStyle: 'normal',
        fontFamily: 'Arial',
        color: '#000000',
        textAlign: 'left',
        verticalAlign: 'top',
        styles: {}
      });
    }
  };

  const handleDeleteBloc = (blocId: string) => {
    if (!confirm('Êtes-vous sûr de vouloir supprimer ce bloc ?')) return;

    // Suppression locale uniquement
    const updatedBlocs = blocs.filter(bloc => bloc.id !== blocId);
    onBlocsChange(updatedBlocs);

    toast.success('Bloc supprimé localement - Cliquez sur "Mettre à jour" pour sauvegarder');
  };

  const handleMouseDown = (e: React.MouseEvent, bloc: DocumentBloc) => {
    e.stopPropagation();
    const pos = getCanvasPosition(e);
    setDraggingBloc(bloc);
    setDragOffset({
      x: pos.x - bloc.position_x,
      y: pos.y - bloc.position_y
    });
    
    // Sauvegarder la position originale
    setOriginalPositions(prev => ({
      ...prev,
      [bloc.id]: { x: bloc.position_x, y: bloc.position_y }
    }));
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (!draggingBloc) return;
    e.preventDefault();
    
    const pos = getCanvasPosition(e);
    const newX = Math.max(0, pos.x - dragOffset.x);
    const newY = Math.max(0, pos.y - dragOffset.y);
    
    // Mise à jour uniquement visuelle avec tempPositions
    setTempPositions(prev => ({
      ...prev,
      [draggingBloc.id]: { x: newX, y: newY }
    }));
  };

  const handleMouseUp = () => {
    if (!draggingBloc) return;
    
    // Simple arrêt du dragging, la position reste temporaire
    setDraggingBloc(null);
    setDragOffset({ x: 0, y: 0 });
  };

  const handleConfirmDragPosition = (blocId: string) => {
    const tempPos = tempPositions[blocId];
    if (!tempPos) return;
    
    // Appliquer la nouvelle position localement
    const updatedBlocs = blocs.map(b => 
      b.id === blocId 
        ? { ...b, position_x: tempPos.x, position_y: tempPos.y }
        : b
    );
    onBlocsChange(updatedBlocs);
    
    // Nettoyer les positions temporaires
    setTempPositions(prev => {
      const newTemp = { ...prev };
      delete newTemp[blocId];
      return newTemp;
    });
    
    setOriginalPositions(prev => {
      const newOrig = { ...prev };
      delete newOrig[blocId];
      return newOrig;
    });
    
    toast.success('Position confirmée localement - Cliquez sur "Mettre à jour" pour sauvegarder');
  };

  const handleCancelDragPosition = (blocId: string) => {
    const originalPos = originalPositions[blocId];
    if (!originalPos) return;
    
    // Restaurer la position originale
    const updatedBlocs = blocs.map(b => 
      b.id === blocId 
        ? { ...b, position_x: originalPos.x, position_y: originalPos.y }
        : b
    );
    onBlocsChange(updatedBlocs);
    
    // Nettoyer les positions temporaires et originales
    setTempPositions(prev => {
      const newTemp = { ...prev };
      delete newTemp[blocId];
      return newTemp;
    });
    
    setOriginalPositions(prev => {
      const newOrig = { ...prev };
      delete newOrig[blocId];
      return newOrig;
    });
  };

  // Fonctions pour gérer le déplacement de la popup
  const handlePopupMouseDown = (e: React.MouseEvent) => {
    if ((e.target as HTMLElement).closest('.popup-header')) {
      setIsDraggingPopup(true);
      setDragStartPosition({
        x: e.clientX - popupPosition.x,
        y: e.clientY - popupPosition.y
      });
    }
  };

  const handlePopupMouseMove = (e: React.MouseEvent) => {
    if (isDraggingPopup) {
      setPopupPosition({
        x: e.clientX - dragStartPosition.x,
        y: e.clientY - dragStartPosition.y
      });
    }
  };

  const handlePopupMouseUp = () => {
    setIsDraggingPopup(false);
  };

  // Gestionnaire global pour les événements de souris
  useEffect(() => {
    const handleGlobalMouseMove = (e: MouseEvent) => {
      if (isDraggingPopup) {
        setPopupPosition({
          x: e.clientX - dragStartPosition.x,
          y: e.clientY - dragStartPosition.y
        });
      }
    };

    const handleGlobalMouseUp = () => {
      setIsDraggingPopup(false);
    };

    if (isDraggingPopup) {
      document.addEventListener('mousemove', handleGlobalMouseMove);
      document.addEventListener('mouseup', handleGlobalMouseUp);
    }

    return () => {
      document.removeEventListener('mousemove', handleGlobalMouseMove);
      document.removeEventListener('mouseup', handleGlobalMouseUp);
    };
  }, [isDraggingPopup, dragStartPosition]);

  return (
    <div className="bg-green-50 p-6 rounded-lg space-y-6 min-h-[600px]">
      <div className="flex justify-between items-center">
        <h3 className="text-lg font-semibold">Édition Visuelle des Blocs</h3>
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2">
            <Label>Face :</Label>
            <div className="flex rounded-lg border overflow-hidden">
              <Button
                type="button"
                size="sm"
                variant={selectedFace === 'recto' ? 'default' : 'outline'}
                onClick={() => setSelectedFace('recto')}
                className="rounded-none"
              >
                Recto
              </Button>
              <Button
                type="button"
                size="sm"
                variant={selectedFace === 'verso' ? 'default' : 'outline'}
                onClick={() => setSelectedFace('verso')}
                className="rounded-none"
              >
                Verso
              </Button>
            </div>
          </div>
          <Button
            type="button"
            onClick={handleAddBloc}
            disabled={isPlacingMode || isNewModel}
            className="bg-blue-600 hover:bg-blue-700"
          >
            <Plus className="h-4 w-4 mr-2" />
            {isPlacingMode ? 'Mode placement actif...' : 'Ajouter un Bloc'}
          </Button>
          <Button
            type="button"
            onClick={handleAddPhotoFrame}
            disabled={isDrawingPhotoFrame || isNewModel}
            className="bg-purple-600 hover:bg-purple-700"
          >
            <Camera className="h-4 w-4 mr-2" />
            {isDrawingPhotoFrame ? 'Dessinez le cadre...' : 'Cadre Photo'}
          </Button>
        </div>
      </div>

      {isNewModel && (
        <div className="bg-amber-100 border border-amber-300 rounded-lg p-4">
          <p className="text-amber-800 text-sm">
            💡 Sauvegardez d'abord le modèle en cliquant sur "Créer le Modèle" pour pouvoir ajouter et positionner des blocs visuellement.
          </p>
        </div>
      )}

      <div className="grid grid-cols-3 gap-4">
        {/* Zone d'édition visuelle */}
        <div className="col-span-2 space-y-4">
          <h4 className="font-medium">Zone d'Édition - Face {selectedFace === 'recto' ? 'Recto' : 'Verso'}</h4>
          
          {!currentImageUrl ? (
            <div className="border-2 border-dashed border-gray-300 rounded-lg p-8 text-center">
              <p className="text-gray-500">Uploadez d'abord une image pour cette face</p>
            </div>
          ) : (
            <div className="relative border rounded-lg p-4 bg-white">
              <div className="flex justify-between items-center mb-2">
                <div className="text-xs text-gray-500">
                  Format: {formatPage} - {getCanvasDimensions(formatPage).width}x{getCanvasDimensions(formatPage).height}px
                </div>
                <div className="flex items-center space-x-2">
                  <span className="text-xs text-gray-500">Zoom: {Math.round(scale * 100)}%</span>
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => handleZoom(0.1)}
                    disabled={scale >= 2}
                    className="px-2 py-1 text-xs"
                  >
                    ➕
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => handleZoom(-0.1)}
                    disabled={scale <= 0.3}
                    className="px-2 py-1 text-xs"
                  >
                    ➖
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => setScale(1)}
                    className="px-2 py-1 text-xs"
                  >
                    100%
                  </Button>
                  <Button
                    type="button"
                    variant={showGrid ? "default" : "outline"}
                    size="sm"
                    onClick={() => {
                      console.log('Toggle grille, état actuel:', showGrid);
                      setShowGrid(!showGrid);
                    }}
                    className="px-2 py-1 text-xs"
                  >
                    {showGrid ? '🟨' : '⬜'} Grille
                  </Button>
                </div>
              </div>
              <div 
                className="max-w-full max-h-[500px] overflow-auto border border-gray-300 rounded"
                style={{ scrollbarWidth: 'thin', scrollbarColor: 'rgba(0,0,0,0.3) transparent' }}
              >
                <canvas
                  ref={canvasRef}
                  width={canvasSize.width}
                  height={canvasSize.height}
                  className={`border border-gray-200 ${isPlacingMode ? 'cursor-crosshair' : isDrawingPhotoFrame ? 'cursor-crosshair' : isResizingPhotoFrame ? 'cursor-nwse-resize' : draggingBloc ? 'cursor-move' : 'cursor-default'}`}
                  onMouseDown={handleCanvasMouseDown}
                  onMouseMove={handleCanvasMouseMove}
                  onMouseUp={handleCanvasMouseUp}
                  onMouseLeave={handleCanvasMouseLeave}
                  onDoubleClick={handleCanvasDoubleClick}
                />
              </div>
              
              {/* Instructions */}
              {isPlacingMode && !showConfirmButton && (
                <div className="absolute top-2 left-2 bg-blue-100 text-blue-800 px-3 py-1 rounded text-sm">
                  Cliquez pour choisir l'emplacement
                </div>
              )}
              
              {!isPlacingMode && !draggingBloc && (
                <div className="absolute top-2 left-2 bg-gray-100 text-gray-700 px-3 py-1 rounded text-xs">
                  Cliquez sur un bloc bleu pour le déplacer, double-cliquez pour l'éditer
                </div>
              )}
              
              {draggingBloc && (
                <div className="absolute top-2 left-2 bg-orange-100 text-orange-800 px-3 py-1 rounded text-sm">
                  Déplacement en cours...
                </div>
              )}
              
              {/* Instructions pour cadre photo */}
              {isDrawingPhotoFrame && (
                <div className="absolute top-2 left-2 bg-purple-100 text-purple-800 px-3 py-1 rounded text-sm">
                  {!photoFrameStart ? 'Cliquez et glissez pour dessiner le cadre photo' : 'Relâchez pour terminer le cadre'}
                </div>
              )}
              
              {/* Bouton "Confirmer ici" */}
              {showConfirmButton && placementPosition && (
                <div
                  className="absolute bg-green-600 text-white px-3 py-1 rounded shadow-lg cursor-pointer hover:bg-green-700 transition-colors text-sm"
                  style={{
                    left: `${placementPosition.x * scale + 16}px`,
                    top: `${placementPosition.y * scale + 16}px`,
                    transform: 'translate(-50%, -50%)'
                  }}
                  onClick={handleConfirmPosition}
                >
                  Confirmer ici
                </div>
              )}
              
            </div>
          )}
        </div>

        {/* Liste des blocs existants */}
        <div className="space-y-4">
          <h4 className="font-medium">Blocs Configurés - Face {selectedFace === 'recto' ? 'Recto' : 'Verso'}</h4>
          <div className="space-y-3 max-h-96 overflow-y-auto border rounded p-2 bg-white"
               style={{ scrollbarWidth: 'thin' }}>
            {blocs.filter(bloc => bloc.face === selectedFace).map(bloc => (
              <Card key={bloc.id} className={`border-l-4 ${editingBloc?.id === bloc.id ? 'border-l-orange-500 bg-orange-50' : 'border-l-blue-500'}`}>
                <CardContent className="p-4">
                  <div className="flex justify-between items-start">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-2">
                        <Badge variant="outline">{bloc.type_contenu}</Badge>
                        <span className="text-sm font-medium">{bloc.nom_bloc}</span>
                      </div>
                      <div className="text-xs text-gray-500 space-y-1">
                        <div>Position: ({Math.round(bloc.position_x)}, {Math.round(bloc.position_y)})</div>
                        <div>Taille: {bloc.largeur} × {bloc.hauteur}</div>
                      </div>
                    </div>
                    <div className="flex gap-1">
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={(e) => {
                          e.preventDefault();
                          e.stopPropagation();
                          setEditingBloc(bloc);
                           setBlocConfig({
                             type_contenu: bloc.type_contenu,
                             fontSize: (typeof bloc.styles_css === 'string' ? JSON.parse(bloc.styles_css) : bloc.styles_css)?.fontSize || 14,
                             fontWeight: (typeof bloc.styles_css === 'string' ? JSON.parse(bloc.styles_css) : bloc.styles_css)?.fontWeight || 'normal',
                             fontStyle: (typeof bloc.styles_css === 'string' ? JSON.parse(bloc.styles_css) : bloc.styles_css)?.fontStyle || 'normal',
                             fontFamily: (typeof bloc.styles_css === 'string' ? JSON.parse(bloc.styles_css) : bloc.styles_css)?.fontFamily || 'Arial',
                             color: (typeof bloc.styles_css === 'string' ? JSON.parse(bloc.styles_css) : bloc.styles_css)?.color || '#000000',
                             textAlign: (typeof bloc.styles_css === 'string' ? JSON.parse(bloc.styles_css) : bloc.styles_css)?.textAlign || 'left',
                             verticalAlign: (typeof bloc.styles_css === 'string' ? JSON.parse(bloc.styles_css) : bloc.styles_css)?.verticalAlign || 'top',
                             styles: (typeof bloc.styles_css === 'string' ? JSON.parse(bloc.styles_css) : bloc.styles_css) || {}
                           });
                          setShowConfigPopup(true);
                        }}
                      >
                        <Edit className="h-3 w-3" />
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => handleDeleteBloc(bloc.id)}
                      >
                        <Trash2 className="h-3 w-3" />
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
            
            {blocs.filter(bloc => bloc.face === selectedFace).length === 0 && (
              <div className="text-center text-gray-500 py-8">
                <p>Aucun bloc configuré pour cette face</p>
                {!isNewModel && (
                  <p className="text-sm mt-2">Cliquez sur "Ajouter un Bloc" pour commencer</p>
                )}
              </div>
            )}
          </div>
        </div>
      </div>


      {/* Pop-up de configuration */}
      {showConfigPopup && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div 
            className="bg-white rounded-lg p-6 w-80 space-y-4 select-none"
            style={{
              position: 'absolute',
              left: `${popupPosition.x}px`,
              top: `${popupPosition.y}px`,
              cursor: isDraggingPopup ? 'grabbing' : 'default'
            }}
            onMouseDown={handlePopupMouseDown}
            onMouseMove={handlePopupMouseMove}
            onMouseUp={handlePopupMouseUp}
          >
            <div className="popup-header flex items-center justify-between cursor-grab active:cursor-grabbing">
              <h3 className="text-lg font-medium">
                {editingBloc ? 'Modifier le bloc' : 'Configuration du bloc'}
              </h3>
              <Button variant="ghost" size="sm" onClick={handleClosePopup}>
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

              <div>
                <Label>Police</Label>
                <Select 
                  value={blocConfig.fontFamily} 
                  onValueChange={(value) => setBlocConfig(prev => ({ ...prev, fontFamily: value }))}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {FONT_FAMILIES.map(font => (
                      <SelectItem key={font.value} value={font.value}>
                        {font.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="flex space-x-2">
                <Button
                  type="button"
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
                  type="button"
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

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <Label htmlFor="textAlign">Alignement horizontal</Label>
                  <Select value={blocConfig.textAlign} onValueChange={(value) => setBlocConfig(prev => ({ ...prev, textAlign: value }))}>
                    <SelectTrigger className="w-full">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="left">À gauche</SelectItem>
                      <SelectItem value="center">Centré</SelectItem>
                      <SelectItem value="right">À droite</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <Label htmlFor="verticalAlign">Alignement vertical</Label>
                  <Select value={blocConfig.verticalAlign} onValueChange={(value) => setBlocConfig(prev => ({ ...prev, verticalAlign: value }))}>
                    <SelectTrigger className="w-full">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="top">En haut</SelectItem>
                      <SelectItem value="middle">Centré</SelectItem>
                      <SelectItem value="bottom">En bas</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <Button
                type="button"
                onClick={handleValidateBloc}
                className="w-full bg-blue-600 hover:bg-blue-700"
              >
                {editingBloc ? 'Modifier le Bloc' : 'Valider le Bloc'}
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default UnifiedBlocEditor;