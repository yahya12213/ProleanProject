
import { Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

const prisma = new PrismaClient();
const JWT_SECRET = process.env.JWT_SECRET || 'votre_secret_par_defaut';

/**
 * Connexion via la table profiles de l'app principale.
 * Les mots de passe sont hashés avec bcrypt.
 */
export const login = async (req: Request, res: Response) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Nom d\'utilisateur et mot de passe sont requis.' });
  }

  try {
    const profile = await prisma.profile.findFirst({
      where: { username },
    });

    if (!profile) {
      return res.status(401).json({ message: 'Identifiants invalides.' });
    }

    const isPasswordValid = await bcrypt.compare(password, profile.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Identifiants invalides.' });
    }

    const token = jwt.sign(
      { profileId: profile.id, username: profile.username, role: profile.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.status(200).json({
      message: 'Connexion réussie',
      token,
      profile: {
        id: profile.id,
        username: profile.username,
        full_name: profile.full_name,
        role: profile.role,
        profile_image_url: profile.profile_image_url,
      },
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Erreur lors de la connexion', error });
  }
};

/**
 * Inscription - Crée un nouveau profil dans la table profiles.
 * NOTE: utiliser avec prudence car c'est la BDD de production partagée.
 */
export const register = async (req: Request, res: Response) => {
  const { username, password, full_name, role } = req.body;

  if (!username || !password || !full_name) {
    return res.status(400).json({ message: 'Nom d\'utilisateur, mot de passe et nom complet sont requis.' });
  }

  try {
    const existing = await prisma.profile.findFirst({
      where: { username },
    });

    if (existing) {
      return res.status(409).json({ message: 'Ce nom d\'utilisateur existe déjà.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const profile = await prisma.profile.create({
      data: {
        id: crypto.randomUUID(),
        username,
        password: hashedPassword,
        full_name,
        role: role || 'employee',
      },
    });

    res.status(201).json({
      message: 'Profil créé avec succès',
      profile: {
        id: profile.id,
        username: profile.username,
        full_name: profile.full_name,
        role: profile.role,
      },
    });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ message: 'Erreur lors de la création du profil', error });
  }
};

/**
 * Middleware d'authentification JWT
 */
export const authMiddleware = (req: any, res: Response, next: any) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Token manquant' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ message: 'Token invalide' });
  }
};
