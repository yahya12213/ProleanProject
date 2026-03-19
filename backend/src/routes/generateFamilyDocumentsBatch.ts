// Type for modeles_documents table (adjust fields as needed)
type ModeleDocument = {
  id: string;
  nom_modele: string;
  famille_type: string;
};
import express, { Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';
import path from 'path';
import fs from 'fs';
import { PDFDocument } from 'pdf-lib';
import { generateAdvancedPdf } from './generatePdf';

const router = express.Router();
const prisma = new PrismaClient();

function normalizeFamille(input: string): string {
  const f = String(input || '').trim().toLowerCase();
  const map: Record<string, string> = { bade: 'badge' };
  return map[f] || f;
}

router.post('/generate-family-documents-batch', async (req: Request, res: Response) => {
  try {
    const { etudiant_ids, famille, modele_ids }: { etudiant_ids: string[]; famille: string; modele_ids?: string[] } = req.body;
    if (!famille || !Array.isArray(etudiant_ids) || etudiant_ids.length === 0) {
      return res.status(400).json({ success: false, error: 'Paramètres invalides: fournir famille et etudiant_ids[]' });
    }
    const fam = normalizeFamille(famille);
    type BatchResult = {
      success: boolean;
      modele: string;
      fileName?: string;
      filePath?: string;
      error?: string;
      etudiant_id: string;
    };
    const allSuccessful: BatchResult[] = [];
    const allFailed: BatchResult[] = [];

    // Helper pour une génération par étudiant
    const generateForStudent = async (etudiant_id: string) => {
      // 1. Récupérer inscription et formation
      const inscription = await prisma.inscriptions.findFirst({
        where: { etudiant_id },
        include: { classes: true, sessions_en_ligne: true }
      });
      if (!inscription) throw new Error('Aucune inscription trouvée');
      if (inscription.statut_compte !== 'valide') throw new Error('Statut compte non valide');
      const formationId = inscription.formation_id;
      if (!formationId) throw new Error('Formation introuvable');
      // 2. Récupérer les modèles liés à la famille et à la formation
      let modeles = await prisma.modeles_documents.findMany({
        where: {
          famille_type: fam,
          formations: { some: { id: formationId } }
        }
      });
      // Filtrer par liste imposée si fournie
      if (Array.isArray(modele_ids) && modele_ids.length > 0) {
        const idsSet = new Set(modele_ids);
        modeles = modeles.filter((m: ModeleDocument) => idsSet.has(m.id));
      }
      if (!modeles || modeles.length === 0) throw new Error(`Aucun modèle pour la famille "${famille}"`);
      // 3. Générer les PDF pour cet étudiant
      for (const modele of modeles) {
        try {
          const etudiant = await prisma.etudiants.findUnique({ where: { id: etudiant_id } });
          const blocs = await prisma.document_blocs.findMany({ where: { modele_id: modele.id, is_active: true }, orderBy: { ordre_affichage: 'asc' } });
          const pdfContent = await generateAdvancedPdf(etudiant, inscription, modele, blocs);
          const now = new Date();
          const fileName = `etudiant_${etudiant_id}_${modele.nom_modele}_${now.getTime()}.pdf`;
          const uploadsDir = path.join(__dirname, '../../uploads');
          if (!fs.existsSync(uploadsDir)) {
            fs.mkdirSync(uploadsDir, { recursive: true });
          }
          const filePath = path.join(uploadsDir, fileName);
          fs.writeFileSync(filePath, pdfContent);
          allSuccessful.push({ success: true, modele: modele.nom_modele, fileName, filePath, etudiant_id });
        } catch (err) {
          let errorMsg = 'Erreur inconnue';
          if (err instanceof Error) errorMsg = err.message;
          allFailed.push({ success: false, modele: modele.nom_modele, error: errorMsg, etudiant_id });
        }
      }
    };

    // Traiter tous les étudiants (séquentiel)
    for (const id of etudiant_ids) {
      try {
        await generateForStudent(id);
      } catch (e) {
        let errorMsg = 'Erreur inconnue';
        if (e instanceof Error) errorMsg = e.message;
        allFailed.push({ success: false, modele: '', error: errorMsg, etudiant_id: id });
      }
    }

    // 4. Combiner TOUS les PDF success en un seul
    let combined: { filePath: string; fileName: string } | null = null;
    if (allSuccessful.length > 0) {
      const mergedPdf = await PDFDocument.create();
      // Optionnel: trier par etudiant puis par modèle pour un ordre stable
      const sorted = [...allSuccessful].sort((a, b) => (a.etudiant_id + a.modele).localeCompare(b.etudiant_id + b.modele));
      for (const item of sorted) {
        try {
          if (!item.filePath) continue;
          const pdfBytes = fs.readFileSync(item.filePath);
          const src = await PDFDocument.load(pdfBytes);
          const pages = await mergedPdf.copyPages(src, src.getPageIndices());
          pages.forEach((p) => mergedPdf.addPage(p));
        } catch (e) {
          // log l'erreur si besoin
        }
      }
      const mergedBytes = await mergedPdf.save();
      const now = new Date();
      const fileName = `combined_batch_${fam}_${now.getTime()}.pdf`;
      const uploadsDir = path.join(__dirname, '../../uploads');
      const filePath = path.join(uploadsDir, fileName);
      fs.writeFileSync(filePath, mergedBytes);
      combined = { filePath, fileName };
    }

    res.json({
      success: true,
      message: `Batch terminé: ${allSuccessful.length} succès, ${allFailed.length} échecs`,
      results: {
        successful: allSuccessful,
        failed: allFailed,
        total: allSuccessful.length + allFailed.length,
        famille,
        combined
      }
    });
  } catch (error) {
    let errorMsg = 'Erreur inconnue';
    if (error instanceof Error) errorMsg = error.message;
    res.status(500).json({ success: false, error: errorMsg });
  }
});

export default router;
