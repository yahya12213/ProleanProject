
import { Router } from 'express';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();
export const apiRouter = Router();

// ============================================================
// Routes publiques - Données depuis la BDD principale
// ============================================================

// Formations (table: formations)
apiRouter.get('/formations', async (req, res) => {
  try {
    const { search, status, corps_formation_id, limit } = req.query;
    const where: any = {};

    if (status) where.status = status as string;
    if (corps_formation_id) where.corps_formation_id = corps_formation_id as string;
    if (search) {
      where.OR = [
        { title: { contains: search as string, mode: 'insensitive' } },
        { description: { contains: search as string, mode: 'insensitive' } },
      ];
    }

    const formations = await prisma.formation.findMany({
      where,
      orderBy: { created_at: 'desc' },
      take: limit ? parseInt(limit as string) : undefined,
    });
    res.status(200).json({ formations, total: formations.length });
  } catch (error) {
    console.error('GET /formations error:', error);
    res.status(500).json({ message: "Erreur lors de la récupération des formations.", error });
  }
});

// Détail d'une formation
apiRouter.get('/formations/:id', async (req, res) => {
  try {
    const formation = await prisma.formation.findUnique({
      where: { id: req.params.id },
    });
    if (!formation) {
      return res.status(404).json({ message: 'Formation introuvable' });
    }

    // Modules et vidéos
    const modules = await prisma.formationModule.findMany({
      where: { formation_id: req.params.id },
      orderBy: { order_index: 'asc' },
      include: {
        videos: { orderBy: { order_index: 'asc' } },
      },
    });

    // Sessions liées
    const sessionLinks = await prisma.sessionFormationLink.findMany({
      where: { formation_id: req.params.id },
    });
    const sessionIds = sessionLinks.map((l: any) => l.session_id);
    const sessions = sessionIds.length > 0
      ? await prisma.sessionFormation.findMany({
          where: { id: { in: sessionIds } },
          orderBy: { date_debut: 'desc' },
        })
      : [];

    res.status(200).json({ formation, modules, sessions });
  } catch (error) {
    console.error('GET /formations/:id error:', error);
    res.status(500).json({ message: "Erreur", error });
  }
});

// Corps de formation
apiRouter.get('/corps-formation', async (req, res) => {
  try {
    const corps = await prisma.corpsFormation.findMany({
      orderBy: { order_index: 'asc' },
    });
    res.status(200).json(corps);
  } catch (error) {
    res.status(500).json({ message: "Erreur", error });
  }
});

// Sessions de formation
apiRouter.get('/sessions', async (req, res) => {
  try {
    const { statut, ville_id, segment_id } = req.query;
    const where: any = {};
    if (statut) where.statut = statut as string;
    if (ville_id) where.ville_id = ville_id as string;
    if (segment_id) where.segment_id = segment_id as string;

    const sessions = await prisma.sessionFormation.findMany({
      where,
      orderBy: { date_debut: 'desc' },
      include: {
        session_etudiants: { select: { id: true } },
      },
    });

    const result = sessions.map((s: any) => ({
      ...s,
      nombre_inscrits: s.session_etudiants.length,
      session_etudiants: undefined,
    }));

    res.status(200).json({ sessions: result, total: result.length });
  } catch (error) {
    res.status(500).json({ message: "Erreur", error });
  }
});

// Étudiants
apiRouter.get('/students', async (req, res) => {
  try {
    const { search, limit } = req.query;
    const where: any = {};

    if (search) {
      where.OR = [
        { nom: { contains: search as string, mode: 'insensitive' } },
        { prenom: { contains: search as string, mode: 'insensitive' } },
        { cin: { contains: search as string, mode: 'insensitive' } },
        { email: { contains: search as string, mode: 'insensitive' } },
      ];
    }

    const students = await prisma.student.findMany({
      where,
      orderBy: { created_at: 'desc' },
      take: limit ? parseInt(limit as string) : 50,
    });
    res.status(200).json({ students, total: students.length });
  } catch (error) {
    res.status(500).json({ message: "Erreur", error });
  }
});

// Détail étudiant avec ses sessions
apiRouter.get('/students/:id', async (req, res) => {
  try {
    const student = await prisma.student.findUnique({
      where: { id: req.params.id },
      include: {
        session_etudiants: {
          include: {
            session: true,
            payments: true,
          },
        },
      },
    });

    if (!student) {
      return res.status(404).json({ message: 'Étudiant introuvable' });
    }

    res.status(200).json(student);
  } catch (error) {
    res.status(500).json({ message: "Erreur", error });
  }
});

// Villes (filtrées par segment, exclure "sans ville" et "charge")
apiRouter.get('/cities', async (req, res) => {
  try {
    const { segment_id } = req.query;
    const where: any = {
      NOT: [
        { name: { startsWith: 'Sans ville', mode: 'insensitive' } },
        { name: { startsWith: 'Charge', mode: 'insensitive' } },
      ],
    };
    if (segment_id) where.segment_id = segment_id as string;

    const cities = await prisma.city.findMany({ where, orderBy: { name: 'asc' } });
    res.status(200).json(cities);
  } catch (error) {
    res.status(500).json({ message: "Erreur", error });
  }
});

// Segments
apiRouter.get('/segments', async (req, res) => {
  try {
    const segments = await prisma.segment.findMany({ orderBy: { name: 'asc' } });
    res.status(200).json(segments);
  } catch (error) {
    res.status(500).json({ message: "Erreur", error });
  }
});

// Stats globales
apiRouter.get('/stats', async (req, res) => {
  try {
    const [students, formations, sessions, employees, cities, segments] = await Promise.all([
      prisma.student.count(),
      prisma.formation.count(),
      prisma.sessionFormation.count(),
      prisma.hrEmployee.count(),
      prisma.city.count(),
      prisma.segment.count(),
    ]);

    res.status(200).json({
      total_students: students,
      total_formations: formations,
      total_sessions: sessions,
      total_employees: employees,
      total_cities: cities,
      total_segments: segments,
    });
  } catch (error) {
    res.status(500).json({ message: "Erreur", error });
  }
});

// ============================================================
// RH & Paie
// ============================================================

// Employés
apiRouter.get('/hr/employees', async (req, res) => {
  try {
    const employees = await prisma.hrEmployee.findMany({
      orderBy: { last_name: 'asc' },
    });
    res.status(200).json({ employees, total: employees.length });
  } catch (error) {
    res.status(500).json({ message: "Erreur", error });
  }
});

// Périodes de paie
apiRouter.get('/hr/payroll-periods', async (req, res) => {
  try {
    const periods = await prisma.hrPayrollPeriod.findMany({
      orderBy: [{ year: 'desc' }, { month: 'desc' }],
    });
    res.status(200).json({ periods, total: periods.length });
  } catch (error) {
    res.status(500).json({ message: "Erreur", error });
  }
});

// Bulletins de paie d'une période
apiRouter.get('/hr/payroll-periods/:periodId/payslips', async (req, res) => {
  try {
    const payslips = await prisma.hrPayslip.findMany({
      where: { period_id: req.params.periodId },
      include: { lines: true },
      orderBy: { employee_name: 'asc' },
    });
    res.status(200).json({ payslips, total: payslips.length });
  } catch (error) {
    res.status(500).json({ message: "Erreur", error });
  }
});

// Config paie
apiRouter.get('/hr/payroll-config', async (req, res) => {
  try {
    const config = await prisma.hrPayrollConfig.findMany({
      where: { is_active: true },
      orderBy: { category: 'asc' },
    });
    res.status(200).json(config);
  } catch (error) {
    res.status(500).json({ message: "Erreur", error });
  }
});
