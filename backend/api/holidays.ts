import express, { Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';

// Named function export to avoid interop issues across CommonJS/ESM
export function createHolidaysRouter(prismaClient?: PrismaClient) {
  const prisma = prismaClient ?? new PrismaClient();
  const router = express.Router();

  // Get all holidays
  router.get('/holidays', async (req: Request, res: Response) => {
    try {
      const result = await prisma.$queryRaw`SELECT * FROM jours_feries_collectifs ORDER BY date_debut ASC`;
      res.json(result);
    } catch (error) {
      console.error('Error fetching holidays:', error);
      res.status(500).json({ error: 'Internal Server Error' });
    }
  });

  // Add a new holiday
  router.post('/holidays', async (req: Request, res: Response) => {
    const { nom, date_debut, date_fin, type_conge, description, is_recurrent } = req.body;
    try {
      await prisma.$executeRaw`
        INSERT INTO jours_feries_collectifs (nom, date_debut, date_fin, type_conge, description, is_recurrent)
        VALUES (${nom}, ${date_debut}, ${date_fin}, ${type_conge}, ${description}, ${is_recurrent})
      `;
      res.status(201).json({ message: 'Holiday added successfully' });
    } catch (error) {
      console.error('Error adding holiday:', error);
      res.status(500).json({ error: 'Internal Server Error' });
    }
  });

  // Update a holiday
  router.put('/holidays/:id', async (req: Request, res: Response) => {
    const { id } = req.params;
    const { nom, date_debut, date_fin, type_conge, description, is_recurrent } = req.body;
    try {
      await prisma.$executeRaw`
        UPDATE jours_feries_collectifs
        SET nom = ${nom}, date_debut = ${date_debut}, date_fin = ${date_fin}, type_conge = ${type_conge}, description = ${description}, is_recurrent = ${is_recurrent}
        WHERE id = ${id}
      `;
      res.json({ message: 'Holiday updated successfully' });
    } catch (error) {
      console.error('Error updating holiday:', error);
      res.status(500).json({ error: 'Internal Server Error' });
    }
  });

  // Delete (soft) a holiday
  router.delete('/holidays/:id', async (req: Request, res: Response) => {
    const { id } = req.params;
    try {
      await prisma.$executeRaw`UPDATE jours_feries_collectifs SET is_active = false WHERE id = ${id}`;
      res.json({ message: 'Holiday deactivated successfully' });
    } catch (error) {
      console.error('Error deleting holiday:', error);
      res.status(500).json({ error: 'Internal Server Error' });
    }
  });

  return router;
}

export default createHolidaysRouter;
