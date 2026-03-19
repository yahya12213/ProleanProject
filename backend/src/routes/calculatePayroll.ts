









import express, { Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';

const router = express.Router();
const prisma = new PrismaClient();

router.post('/calculate-payroll', async (req: Request, res: Response) => {
  try {
    const { periodId } = req.body;
    // Récupère la période
    const period = await prisma.payrollPeriod.findUnique({ where: { id: periodId } });
    if (!period) {
      return res.status(404).json({ error: 'Period not found' });
    }
    // Récupère tous les employés (profiles)
    const employees = await prisma.profile.findMany({});
    // Création de résultats vides (id auto)
    const results = employees.map(() => ({}));
    await prisma.payrollResult.createMany({ data: results });
    await prisma.payrollPeriod.update({ where: { id: periodId }, data: { status: 'calculated' } });
    res.json({ success: true, employeesProcessed: results.length });
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
  }
});

export default router;

router.post('/calculate-payroll', async (req: Request, res: Response) => {
  try {
    const { periodId } = req.body;
    // Récupère la période
    const period = await prisma.payrollPeriod.findUnique({ where: { id: periodId } });
    if (!period) {
      return res.status(404).json({ error: 'Period not found' });
    }
    // Récupère tous les employés (profiles)
    const employees = await prisma.profile.findMany({});
    // Création de résultats vides (id auto)
    const results = employees.map(() => ({}));
    await prisma.payrollResult.createMany({ data: results });
    await prisma.payrollPeriod.update({ where: { id: periodId }, data: { status: 'calculated' } });
    res.json({ success: true, employeesProcessed: results.length });
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
  }
});

