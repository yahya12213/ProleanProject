import express from 'express';
import { PrismaClient } from '@prisma/client';
import { jsPDF } from 'jspdf';
import fs from 'fs';
import path from 'path';
// Pour le téléchargement d'images, utiliser node-fetch ou axios
import fetch from 'node-fetch';

const router = express.Router();
const prisma = new PrismaClient();

router.post('/generate-pdf', async (req, res) => {
  try {
    const { etudiant_id, modele_id } = req.body;
    if (!etudiant_id || !modele_id) {
      return res.status(400).json({ error: 'Paramètres manquants' });
    }

    // Récupérer les données depuis Prisma
    const etudiant = await prisma.student.findUnique({ where: { id: etudiant_id } });
    if (!etudiant) {
      throw new Error('Student not found');
    }

    const inscription = await prisma.inscription.findFirst({
      where: { etudiantId: etudiant_id },
      include: { student: true },
    });

    if (!inscription) {
      throw new Error('Inscription not found');
    }

    // Convert createdAt and updatedAt to ISO strings
    const formattedInscription = {
      ...inscription,
      createdAt: inscription.createdAt.toISOString(),
      updatedAt: inscription.updatedAt.toISOString(),
    };

    const modele = await prisma.modeleDocument.findUnique({
      where: { id: modele_id },
    });
    if (!modele) {
      throw new Error('ModeleDocument not found');
    }

    const blocs = await prisma.documentBloc.findMany({
      where: { modeleId: modele.id },
    });

    // Générer le PDF (reprendre la logique de generateAdvancedPdf)
    const pdfContent = Buffer.from(await generateAdvancedPdf(etudiant, formattedInscription, modele, blocs));

    // Enregistrer le PDF localement
    const now = new Date();
    const fileName = `etudiant_${etudiant_id}_${now.getTime()}.pdf`;
    const uploadsDir = path.join(__dirname, '../../uploads');
    if (!fs.existsSync(uploadsDir)) {
      fs.mkdirSync(uploadsDir, { recursive: true });
    }
    const filePath = path.join(uploadsDir, fileName);
    fs.writeFileSync(filePath, pdfContent); // Ensure `pdfContent` is a valid Buffer

    // Fix bloc references
    blocs.forEach((bloc: Bloc) => {
      console.log(`Processing bloc: ${bloc.nom_bloc}`);
    });

    // Enregistrer l’info dans la base
    await prisma.documentGenere.create({
      data: {
        etudiantId: etudiant.id,
        content: JSON.stringify({ message: 'Generated PDF content' }), // Example content
        filePath,
        student: { connect: { id: etudiant_id } } // Connect to the Student model
      }
    });

    res.json({ success: true, filePath, fileName });
  } catch (error: unknown) {
    if (error instanceof Error) {
      res.status(500).json({ error: error.message });
    } else {
      res.status(500).json({ error: 'An unknown error occurred.' });
    }
  }
});

// Fonction adaptée pour Node.js
interface Etudiant {
  id: string;
  nom: string;
  prenom: string;
  date_naissance?: string;
  lieu_naissance?: string;
  ville?: string;
  cin?: string;
  photo_url?: string;
}

interface Inscription {
  id: string;
  etudiantId: string;
  statut_inscription: string;
  statut_compte: string;
  createdAt: string;
  updatedAt: string;
  student: {
    nom: string;
    prenom: string;
    date_naissance?: string;
    lieu_naissance?: string;
    ville?: string;
    cin?: string;
    id: string;
    photo_url?: string;
  };
}

interface ModeleDocument {
  id: string;
  nom_modele: string;
  type_document: string;
  format_page: string;
  orientation: string;
  image_recto_url?: string;
  image_verso_url?: string;
  famille?: string;
  groupe?: string;
  formations?: Record<string, unknown>;
}

interface Bloc {
  id: string;
  nom_bloc: string;
  type_contenu: string;
  face: string;
  position_x: number;
  position_y: number;
  largeur: number;
  hauteur: number;
  styles_css?: Record<string, unknown>;
  ordre_affichage: number;
}

export async function generateAdvancedPdf(
  etudiant: Etudiant,
  inscription: Inscription,
  modele: ModeleDocument,
  blocs: Bloc[]
) {
  // Déterminer les dimensions selon format ET orientation
  let pageWidth, pageHeight;
  if (modele.format_page === 'carte') {
    if (modele.orientation === 'paysage') {
      pageWidth = 85.6;
      pageHeight = 53.98;
    } else {
      pageWidth = 53.98;
      pageHeight = 85.6;
    }
  } else if (modele.format_page === 'A4') {
    if (modele.orientation === 'paysage') {
      pageWidth = 297;
      pageHeight = 210;
    } else {
      pageWidth = 210;
      pageHeight = 297;
    }
  } else {
    if (modele.orientation === 'paysage') {
      pageWidth = 297;
      pageHeight = 210;
    } else {
      pageWidth = 210;
      pageHeight = 297;
    }
  }
  const orientation = modele.orientation === 'paysage' ? 'landscape' : 'portrait';
  const doc = new jsPDF({ orientation, unit: 'mm', format: [pageWidth, pageHeight] });

  function mapContentToData(type: string): string {
    switch (type) {
      case 'nom':
      case 'nom_etudiant':
        return etudiant.nom || '';
      case 'prenom':
      case 'prenom_etudiant':
        return etudiant.prenom || '';
      case 'nom_complet_etudiant':
        return `${etudiant.prenom || ''} ${etudiant.nom || ''}`.trim();
      case 'date_naissance':
        return etudiant.date_naissance ? new Date(etudiant.date_naissance).toLocaleDateString('fr-FR') : '';
      case 'lieu_naissance':
        return etudiant.lieu_naissance || '';
      case 'lieu_delivrance':
        return etudiant.lieu_naissance || '';
      case 'ville_etudiant':
        return etudiant.ville || '';
      case 'cin':
        return etudiant.cin || '';
      case 'serie':
        return etudiant.id || '';
      case 'mohammedia':
        return 'mohammedia';
      case 'photo_candidat':
        return etudiant.photo_url || '';
      default:
        if (/^\d{2}\/\d{2}\/\d{4}$/.test(type)) {
          return type;
        }
        return type;
    }
  }

  async function addPhotoToDoc(
    bloc: Bloc,
    x: number,
    y: number,
    scaleX: number,
    scaleY: number
  ): Promise<void> {
    const photoUrl = etudiant.photo_url;
    if (!photoUrl) return;
    try {
      const photoResponse = await fetch(photoUrl);
      if (!photoResponse.ok) return;
      const photoBuffer = await photoResponse.buffer();
      const photoBase64 = photoBuffer.toString('base64');
      const frameWidthMM = Number(bloc.largeur) * scaleX;
      const frameHeightMM = Number(bloc.hauteur) * scaleY;
      doc.addImage(`data:image/jpeg;base64,${photoBase64}`, 'JPEG', x, y, frameWidthMM, frameHeightMM);
    } catch (error: unknown) {
      if (error instanceof Error) {
        console.error('Error:', error.message);
      } else {
        console.error('An unknown error occurred.');
      }
    }
  }

  function getCanvasDimensions(format: string): { width: number; height: number } {
    switch(format){
      case 'A4': return { width: 600, height: 849 };
      case 'carte': return { width: 600, height: 378 };
      case 'A5': return { width: 600, height: 425 };
      default: return { width: 600, height: 849 };
    }
  }
  const editorDimensions = getCanvasDimensions(modele.format_page || 'carte');
  const scaleX = pageWidth / editorDimensions.width;
  const scaleY = pageHeight / editorDimensions.height;

  const blocsRecto = blocs.filter((bloc: Bloc)=>bloc.face === 'recto');
  const blocsVerso = blocs.filter((bloc: Bloc)=>bloc.face === 'verso');

  // Recto
  if (blocsRecto.length > 0 || modele.image_recto_url) {
    if (modele.image_recto_url) {
      try {
        const imageResponse = await fetch(modele.image_recto_url);
        if (imageResponse.ok) {
          const imageBuffer = await imageResponse.buffer();
          const imageBase64 = imageBuffer.toString('base64');
          doc.addImage(`data:image/jpeg;base64,${imageBase64}`, 'JPEG', 0, 0, pageWidth, pageHeight);
        }
      } catch (error) {
        // log l'erreur si besoin
      }
    }
    for (const bloc of blocsRecto){
      const content = mapContentToData(bloc.type_contenu);
      const x = Number(bloc.position_x) * scaleX;
      const y = Number(bloc.position_y) * scaleY;
      if (bloc.type_contenu === 'photo_candidat') {
        await addPhotoToDoc(bloc, x, y, scaleX, scaleY);
        continue;
      }
      type BlocStyles = {
        fontSize?: number;
        fontWeight?: string;
        fontStyle?: string;
        fontFamily?: string;
        color?: string;
        textAlign?: string;
        verticalAlign?: string;
      };
  let styles: BlocStyles = {};
      if (bloc.styles_css) {
        try {
          styles = typeof bloc.styles_css === 'string' ? JSON.parse(bloc.styles_css) : bloc.styles_css;
        } catch (e) {
          styles = {
            fontSize: 14,
            fontWeight: 'normal',
            fontStyle: 'normal',
            fontFamily: 'Arial',
            color: '#000000',
            textAlign: 'left',
            verticalAlign: 'top'
          };
        }
      } else {
        styles = {
          fontSize: 14,
          fontWeight: 'normal',
          fontStyle: 'normal',
          fontFamily: 'Arial',
          color: '#000000',
          textAlign: 'left',
          verticalAlign: 'top'
        };
      }
  let fontName = 'helvetica';
      const fontFamily = styles.fontFamily || 'Arial';
      if (fontFamily.toLowerCase().includes('arial') || fontFamily.toLowerCase().includes('helvetica') || fontFamily.toLowerCase().includes('roboto') || fontFamily.toLowerCase().includes('open sans') || fontFamily.toLowerCase().includes('verdana') || fontFamily.toLowerCase().includes('tahoma')) fontName = 'helvetica';
      else if (fontFamily.toLowerCase().includes('times') || fontFamily.toLowerCase().includes('georgia') || fontFamily.toLowerCase().includes('merriweather') || fontFamily.toLowerCase().includes('playfair')) fontName = 'times';
      else if (fontFamily.toLowerCase().includes('courier') || fontFamily.toLowerCase().includes('monaco') || fontFamily.toLowerCase().includes('source code')) fontName = 'courier';
      const fontWeight = styles.fontWeight || 'normal';
      const fontStyle = styles.fontStyle || 'normal';
      const jsPDFStyle = `${fontWeight}${fontStyle === 'italic' ? 'italic' : ''}`;
      const baseFontSize = Number(styles.fontSize || 14);
      const fontSize = Math.max(baseFontSize, 6);
      const textColor = styles.color || '#000000';
      doc.setFont(fontName, jsPDFStyle);
      doc.setFontSize(fontSize);
      doc.setTextColor(textColor);
      const textAlign = styles.textAlign || 'left';
      const verticalAlign = styles.verticalAlign || 'top';
  const textX = x;
      let textY = y;
      const fontSizeMM = fontSize * 0.352778;
      if (verticalAlign === 'middle') textY = y + fontSizeMM / 4;
      else if (verticalAlign === 'bottom') textY = y;
      else textY = y + fontSizeMM;
  let jsPDFAlign: 'left' | 'center' | 'right' | 'justify' = 'left';
  if (textAlign === 'center') jsPDFAlign = 'center';
  else if (textAlign === 'right') jsPDFAlign = 'right';
  doc.text(content, textX, textY, { align: jsPDFAlign });
    }
  }
  // Verso
  if ((blocsVerso.length > 0 || modele.image_verso_url) && modele.image_verso_url) {
    doc.addPage([pageWidth, pageHeight], orientation);
    if (modele.image_verso_url) {
      try {
        const imageResponse = await fetch(modele.image_verso_url);
        if (imageResponse.ok) {
          const imageBuffer = await imageResponse.buffer();
          const imageBase64 = imageBuffer.toString('base64');
          doc.addImage(`data:image/jpeg;base64,${imageBase64}`, 'JPEG', 0, 0, pageWidth, pageHeight);
        }
      } catch (error) {
        // log l'erreur si besoin
      }
    }
    for (const bloc of blocsVerso){
      const content = mapContentToData(bloc.type_contenu);
      const x = Number(bloc.position_x) * scaleX;
      const y = Number(bloc.position_y) * scaleY;
      if (bloc.type_contenu === 'photo_candidat') {
        await addPhotoToDoc(bloc, x, y, scaleX, scaleY);
        continue;
      }
      type BlocStyles = {
        fontSize?: number;
        fontWeight?: string;
        fontStyle?: string;
        fontFamily?: string;
        color?: string;
        textAlign?: string;
        verticalAlign?: string;
      };
  let styles: BlocStyles = {};
      if (bloc.styles_css) {
        try {
          styles = typeof bloc.styles_css === 'string' ? JSON.parse(bloc.styles_css) : bloc.styles_css;
        } catch (e) {
          styles = {
            fontSize: 14,
            fontWeight: 'normal',
            fontStyle: 'normal',
            fontFamily: 'Arial',
            color: '#000000',
            textAlign: 'left',
            verticalAlign: 'top'
          };
        }
      } else {
        styles = {
          fontSize: 14,
          fontWeight: 'normal',
          fontStyle: 'normal',
          fontFamily: 'Arial',
          color: '#000000',
          textAlign: 'left',
          verticalAlign: 'top'
        };
      }
  let fontName = 'helvetica';
      const fontFamily = styles.fontFamily || 'Arial';
      if (fontFamily.toLowerCase().includes('arial') || fontFamily.toLowerCase().includes('helvetica') || fontFamily.toLowerCase().includes('roboto') || fontFamily.toLowerCase().includes('open sans') || fontFamily.toLowerCase().includes('verdana') || fontFamily.toLowerCase().includes('tahoma')) fontName = 'helvetica';
      else if (fontFamily.toLowerCase().includes('times') || fontFamily.toLowerCase().includes('georgia') || fontFamily.toLowerCase().includes('merriweather') || fontFamily.toLowerCase().includes('playfair')) fontName = 'times';
      else if (fontFamily.toLowerCase().includes('courier') || fontFamily.toLowerCase().includes('monaco') || fontFamily.toLowerCase().includes('source code')) fontName = 'courier';
      const fontWeight = styles.fontWeight || 'normal';
      const fontStyle = styles.fontStyle || 'normal';
      const jsPDFStyle = `${fontWeight}${fontStyle === 'italic' ? 'italic' : ''}`;
      const baseFontSize = Number(styles.fontSize || 14);
      const fontSize = Math.max(baseFontSize, 6);
      const textColor = styles.color || '#000000';
      doc.setFont(fontName, jsPDFStyle);
      doc.setFontSize(fontSize);
      doc.setTextColor(textColor);
      const textAlign = styles.textAlign || 'left';
      const verticalAlign = styles.verticalAlign || 'top';
  const textX = x;
      let textY = y;
      const fontSizeMM = fontSize * 0.352778;
      if (verticalAlign === 'middle') textY = y + fontSizeMM / 4;
      else if (verticalAlign === 'bottom') textY = y;
      else textY = y + fontSizeMM;
  let jsPDFAlign: 'left' | 'center' | 'right' | 'justify' = 'left';
  if (textAlign === 'center') jsPDFAlign = 'center';
  else if (textAlign === 'right') jsPDFAlign = 'right';
  doc.text(content, textX, textY, { align: jsPDFAlign });
    }
  }
  // Retourner le PDF sous forme de Buffer
  return Buffer.from(doc.output('arraybuffer'));
}

export default router;
