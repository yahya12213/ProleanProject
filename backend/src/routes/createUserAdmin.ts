import express, { Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';
import cors from 'cors';
import { ParamsDictionary } from 'express-serve-static-core';
import { ParsedQs } from 'qs';

const router = express.Router();
const prisma = new PrismaClient();

router.use(cors({
  origin: '*',
  allowedHeaders: ['authorization', 'x-client-info', 'apikey', 'content-type']
}));

// Extend Request type to include adminUserId
interface AdminRequest extends Request {
  adminUserId?: string;
}

// Middleware to check admin authentication (replace with your logic)
async function requireAdmin(req: AdminRequest, res: Response, next: () => void) {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ success: false, error: 'Authorization header missing' });
  }
  // Simule un contrôle admin : seul l'userId 'admin-user-id' est admin
  const userId = await validateAndGetUserId(authHeader);
  if (userId !== 'admin-user-id') {
    return res.status(403).json({ success: false, error: 'Insufficient permissions - Admin role required' });
  }
  req.adminUserId = userId;
  next();
}

router.post('/create-user-admin', requireAdmin, async (req: AdminRequest, res: Response) => {
  try {
    const { email, password, nom, prenom, role = 'user', userId } = req.body;
    if (!email || !nom || !prenom) {
      return res.status(400).json({ success: false, error: 'Missing required fields: email, nom, prenom' });
    }

    let newUser;
    if (userId) {
      // Update existing user
      newUser = await prisma.user.update({
        where: { id: userId },
        data: { email, password }
      });
    } else {
      // Create new user
      if (!password) {
        return res.status(400).json({ success: false, error: 'Password is required for new users' });
      }
      newUser = await prisma.user.create({
        data: { email, password }
      });
    }

    // Crée un profil simple (name uniquement)
    await prisma.profile.create({
      data: { name: nom }
    });

  // Suppression : roles et user_roles n'existent pas dans le schéma Prisma

    res.status(200).json({
      success: true,
      user: {
        id: newUser.id,
        email: newUser.email,
        nom,
        prenom,
        role
      },
      message: userId ? 'Utilisateur mis à jour avec succès' : 'Utilisateur créé avec succès'
    });
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : String(error);
  res.status(400).json({ success: false, error: errorMsg });
  }
});

export default router;

// Helper: implement your own JWT/session validation
async function validateAndGetUserId(authHeader: string): Promise<string> {
  // TODO: Validate token and return user ID
  // Throw error if not valid
  return 'admin-user-id'; // Replace with real logic
}
