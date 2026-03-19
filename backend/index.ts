import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import { PrismaClient } from '@prisma/client';
import { register, login } from './src/auth';
import { apiRouter } from './src/routes';
// dynamic resolution of holidays router to avoid interop issues across CJS/ESM
import path from 'path';

// Config
dotenv.config();
export const app = express();
const prisma = new PrismaClient();
const PORT = Number(process.env.PORT || 3002);

// Middlewares
app.use(cors());
// Sécurité prod uniquement
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';

if (process.env.NODE_ENV === 'production') {
  app.use(helmet());
  app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 1000 }));
}
// Add a minimal Content-Security-Policy that allows same-origin and local dev servers to connect.
app.use((req, res, next) => {
  // allow scripts/resources from self and allow connect to backend and vite dev server
  res.setHeader('Content-Security-Policy', "default-src 'self'; connect-src 'self' http://localhost:3001 http://localhost:5173");
  next();
});
app.use(express.json());

// Serve static files from the project's public directory (favicon, placeholders)
app.use(express.static(path.resolve(__dirname, '..', 'public')));

// --- Routes ---

// Santé du serveur
app.get('/api/health', (req, res) => {
  res.status(200).json({ message: 'Le serveur est en pleine forme !' });
});

// Root route to avoid 404 when browsing the backend base URL directly
app.get('/', (req, res) => {
  res.status(200).json({ message: 'Backend API - use /api/* endpoints. See /api/health' });
});

// Authentification
const authRouter = express.Router();
authRouter.post('/register', register);
authRouter.post('/login', login);
app.use('/api/auth', authRouter);

// Routes de l'API (Formations, FAQs, etc.)
app.use('/api', apiRouter);

// --- Ajout des routes non montées ---
import projectsRouter from './src/routes/projects';
import calculatePayrollRouter from './src/routes/calculatePayroll';
import payrollTestEngineRouter from './src/routes/payrollTestEngine';
import payrollCalculateRouter from './src/routes/payrollCalculate';
import createUserAdminRouter from './src/routes/createUserAdmin';
import generateFamilyDocumentsRouter from './src/routes/generateFamilyDocuments';

app.use('/api', calculatePayrollRouter);
app.use('/api', payrollTestEngineRouter);
app.use('/api', payrollCalculateRouter);
app.use('/api', createUserAdminRouter);
app.use('/api', generateFamilyDocumentsRouter);
app.use('/api', projectsRouter);
// Log des routes montées
console.log('Routes montées :');
console.log('POST /api/auth/register');
console.log('POST /api/auth/login');
console.log('GET /api/formations');
console.log('GET /api/faqs');
console.log('POST /api/calculate-payroll');
console.log('POST /api/payroll-test-engine');
console.log('POST /api/payroll-calculate');
console.log('POST /api/create-user-admin');
console.log('POST /api/generate-family-documents');


// Robust bootstrap with Prisma connection and explicit HOST binding
const HOST = process.env.HOST || '127.0.0.1';

export async function start() {
  try {
    // Ensure Prisma connects before listening
    await prisma.$connect();
    console.log('✅ Prisma connecté');

  // Les routes sont montées directement plus haut

  // Middleware d’erreur (JSON stable)
  // Middleware d’erreur (JSON stable)
  app.use((err: any, _req: any, res: any, _next: any) => {
    console.error('🔥 Error handler:', err);
    const status = err.status || 500;
    res.status(status).json({
      message: err.message || 'Internal Server Error',
      code: err.code || 'INTERNAL_ERROR',
      details: process.env.NODE_ENV === 'production' ? undefined : err.stack,
    });
  });

  const server = app.listen(PORT, HOST, () => {
      const addr = server.address() as { address: string; port: number } | null;
      if (addr) {
        const host = addr.address === '::' ? 'localhost' : addr.address;
        console.log(`Serveur backend démarré sur http://${host}:${addr.port}`);
      } else {
        console.log(`Serveur backend démarré sur le port ${PORT}`);
      }
    });

    // Graceful shutdown
    const shutdown = async (signal?: string) => {
      console.log(`🔌 Arrêt du serveur${signal ? ' (' + signal + ')' : ''}...`);
      try {
        server.close(() => console.log('Serveur arrêté'));
      } catch (e) {
        console.error('Erreur lors de la fermeture du serveur', e);
      }
      try {
        await prisma.$disconnect();
        console.log('✅ Prisma déconnecté');
      } catch (e) {
        console.error('Erreur lors de la déconnexion Prisma', e);
      }
      if (signal) process.exit(0);
    };

    process.on('SIGINT', () => shutdown('SIGINT'));
    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('beforeExit', () => shutdown());
  } catch (e) {
    console.error('❌ Échec au démarrage (Prisma/DB?) :', e);
    // If Prisma can't connect, exit with error code so the developer notices
    process.exit(1);
  }
}

// global handlers
process.on('unhandledRejection', (r) => console.error('unhandledRejection', r));
process.on('uncaughtException', (e) => console.error('uncaughtException', e));

// Start the server unless SKIP_SERVER is set (useful for tests)
if (process.env.SKIP_SERVER !== 'true' && process.env.NODE_ENV !== 'test') {
  start();
}
