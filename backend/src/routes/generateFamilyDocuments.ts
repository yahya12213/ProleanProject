import express, { Request, Response } from 'express';
import { PrismaClient, Student } from '@prisma/client';
import path from 'path';
import fs from 'fs';
import { PDFDocument } from 'pdf-lib';
import { generateAdvancedPdf } from './generatePdf';

const router = express.Router();
const prisma = new PrismaClient();

// Normalise et corrige les noms de familles courants (typos)
function normalizeFamille(input: string): string {
	const f = String(input || '').trim().toLowerCase();
	const map: Record<string, string> = { bade: 'badge' };
	return map[f] || f;
}

router.post('/generate-family-documents', async (req: Request, res: Response) => {
  try {
    const { familyId } = req.body;

    if (!familyId) {
      return res.status(400).json({ success: false, error: 'Family ID is required.' });
    }

    // Fetch family and students
    const family = await prisma.family.findUnique({
      where: { id: familyId },
      include: { students: true },
    });

    if (!family) {
      return res.status(404).json({ success: false, error: 'Family not found.' });
    }

    // Generate PDFs for each student
    const pdfs = await Promise.all(
      family.students.map(async (student) => {
        // Map student to include `nom` and `prenom`
        const mappedStudent = {
          ...student,
          nom: student.nom, // Updated to use `nom`
          prenom: student.prenom, // Updated to use `prenom`
          id: student.id.toString(), // Convert id to string
        };

        // Fetch or construct a valid Inscription object
        const inscription = {
          id: '1', // Example ID, replace with actual logic
          etudiantId: student.id, // Link to the student
          createdAt: new Date().toISOString(), // Convert to ISO string
          updatedAt: new Date().toISOString(), // Convert to ISO string
          student: mappedStudent, // Include the mapped student
          statut_inscription: 'valid',
          statut_compte: 'active',
        };

        // Fetch or construct a valid ModeleDocument object
        const modele = {
          id: '1', // Changed to string
          nom_modele: 'Default Model',
          type_document: 'PDF',
          format_page: 'A4',
          orientation: 'portrait',
          // Add other required properties here
        };

        const pdf = await generateAdvancedPdf(
          mappedStudent, // etudiant
          inscription, // inscription
          modele, // modele
          []  // blocs (replace with actual content blocks)
        );
        return pdf;
      })
    );

    // Combine PDFs
    const combinedPdf = await PDFDocument.create();
    for (const pdfBytes of pdfs) {
      const pdf = await PDFDocument.load(pdfBytes);
      const copiedPages = await combinedPdf.copyPages(pdf, pdf.getPageIndices());
      copiedPages.forEach((page) => combinedPdf.addPage(page));
    }

    const combinedPdfBytes = await combinedPdf.save();

    // Save the combined PDF to the server
    const filePath = path.join(__dirname, '../../uploads', `family_${familyId}.pdf`);
    fs.writeFileSync(filePath, combinedPdfBytes);

    res.status(200).json({ success: true, filePath });
  } catch (error) {
    console.error('Error generating family documents:', error);
    res.status(500).json({ success: false, error: 'Internal server error.' });
  }
});

export default router;
