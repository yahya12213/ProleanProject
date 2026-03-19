import express from 'express';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();
const router = express.Router();

router.get('/projects', async (_req, res) => {
  const data = await prisma.project.findMany({ include: { actions: true } });
  res.json(data);
});

router.post('/projects', async (req, res) => {
  const { name } = req.body;
  const created = await prisma.project.create({ data: { name } });
  res.status(201).json(created);
});

router.get('/projects/:id/actions', async (req, res) => {
  const pid = Number(req.params.id);
  const data = await prisma.action.findMany({ where: { projectId: pid } });
  res.json(data);
});

router.post('/projects/:id/actions', async (req, res) => {
  const pid = Number(req.params.id);
  const { title, payload } = req.body;
  const created = await prisma.action.create({ data: { projectId: pid, title, payload } });
  res.status(201).json(created);
});

export default router;
