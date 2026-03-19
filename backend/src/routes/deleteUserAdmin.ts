import express, { Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';
import cors from 'cors';

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

// Middleware to check admin authentication (reuse from createUserAdmin)
async function requireAdmin(req: AdminRequest, res: Response, next: () => void) {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ success: false, error: 'Authorization header missing' });
  }
  // TODO: Replace with your local JWT/session validation and admin role check
  const userId = await validateAndGetUserId(authHeader); // Implement this function
  const userRole = await prisma.user_roles.findFirst({
    where: { user_id: userId },
    include: { roles: true }
  });
  if (!userRole || userRole.roles.nom !== 'admin') {
    return res.status(403).json({ success: false, error: 'Insufficient permissions - Admin role required' });
  }
  req.adminUserId = userId;
  next();
}

router.post('/delete-user-admin', requireAdmin, async (req: AdminRequest, res: Response) => {
  try {
    const { userId } = req.body;
    if (!userId) {
      return res.status(400).json({ success: false, error: 'Missing required field: userId' });
    }
    // Fetch profile
    const profileData = await prisma.profiles.findUnique({
      where: { id: userId },
      select: { user_id: true, nom: true, prenom: true, email: true }
    });
    if (!profileData) {
      return res.status(404).json({ success: false, error: 'Utilisateur non trouvé' });
    }
    const userAuthId = profileData.user_id;
    // Delete profile_segments
    await prisma.profile_segments.deleteMany({ where: { profile_id: userId } });
    // Delete user_roles
    await prisma.user_roles.deleteMany({ where: { user_id: userAuthId } });
    // Delete profile
    await prisma.profiles.delete({ where: { id: userId } });
    // Delete user (auth)
    await prisma.users.delete({ where: { id: userAuthId } });
    res.json({
      success: true,
      message: 'Utilisateur supprimé avec succès',
      deletedUser: {
        id: userId,
        authId: userAuthId,
        nom: profileData.nom,
        prenom: profileData.prenom,
        email: profileData.email
      }
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
