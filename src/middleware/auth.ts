import { Request, Response, NextFunction } from 'express';
import { verify } from 'jsonwebtoken';
import { config } from '../config';
import { prisma } from '@/lib/pisma';

interface AuthRequest extends Request {
  user?: any;
}

export const authenticateToken = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    if (!config.jwt || !config.jwt.secret) {
      return res.status(500).json({ error: 'JWT configuration error' });
    }
    const decoded = verify(token, config.jwt.secret as string);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid token' });
  }
};

export const authenticateApiKey = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
) => {
  const apiKey = req.headers['x-api-key'];

  if (!apiKey) {
    return res.status(401).json({ error: 'API key required' });
  }

  try {
    const key = await prisma.apiKey.findUnique({
      where: { key: apiKey as string },
      include: { user: true }
    });

    if (!key || !key.isActive) {
      return res.status(403).json({ error: 'Invalid API key' });
    }

    await prisma.apiKey.update({
      where: { id: key.id },
      data: { lastUsed: new Date() }
    });

    req.user = key.user;
    next();
  } catch (error) {
    return res.status(500).json({ error: 'Authentication error' });
  }
};