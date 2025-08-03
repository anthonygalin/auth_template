import { Response, NextFunction } from 'express';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

interface Request {
    user: User
}

export function requireRole(minRole: number) {
    return async (req: Request, res: Response, next: NextFunction) => {
        const user = req.user;

        if (!user || user.role > minRole) {
            return res.status(403).json({ error: 'Forbidden: insufficient role permission' });
        }

        try {
            const dbUser = await prisma.user.findUnique({
                where: { id: user.id },
            });

            if (!dbUser) {
                return res.status(401).json({ error: 'User does not exist' });
            }

            if (dbUser.role > minRole) {
                return res.status(403).json({ error: 'Insufficient permissions for this action' });
            }

            req.user = dbUser;
            next();
        } catch (err) {
            console.error('Auth middleware error:', err);
            res.status(500).json({ error: 'Internal server error' });
        }
    };
}