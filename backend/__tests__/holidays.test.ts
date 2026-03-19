import request from 'supertest';
import express from 'express';
import { PrismaClient } from '@prisma/client';

// Mock Prisma client with minimal behavior
const mockPrisma = {
  $queryRaw: jest.fn(async () => [{ id: 1, nom: 'Test', date_debut: '2025-01-01' }]),
  $executeRaw: jest.fn(async () => undefined),
} as unknown as PrismaClient;

describe('Holidays API (mocked)', () => {
  let server: express.Express;

  beforeAll(() => {
    server = express();
    server.use(express.json());

    const router = express.Router();
    router.get('/holidays', async (_req, res) => {
      const rows = await (mockPrisma.$queryRaw as any)();
      res.json(rows);
    });
    router.post('/holidays', async (_req, res) => {
      await (mockPrisma.$executeRaw as any)();
      res.status(201).json({ message: 'Holiday added successfully' });
    });

    server.use('/api', router);
  });

  it('GET /api/holidays returns list', async () => {
    const res = await request(server).get('/api/holidays');
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
    expect(res.body[0]).toHaveProperty('nom');
  });

  it('POST /api/holidays returns 201', async () => {
    const payload = { nom: 'N', date_debut: '2025-01-01', date_fin: '2025-01-02', type_conge: 'AB', description: '', is_recurrent: false };
    const res = await request(server).post('/api/holidays').send(payload);
    expect(res.status).toBe(201);
  });
});
