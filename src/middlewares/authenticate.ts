import { Response, NextFunction } from 'express';
import { verifyToken } from '../utils/jwt';

enum AuthEnum {
    bearer = 'Bearer',
}

type HeaderType = {
    authorization: AuthEnum
}

interface Request {
    user: User;
    headers: HeaderType;
}

export function authenticateJWT(req: Request, res: Response, next: NextFunction) {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith(AuthEnum.bearer)) {
        return res.status(401).json({ error: 'No token provided' });
    }

    const token = authHeader.split(' ')[1];
    const decoded = verifyToken(token);

    if (!decoded) {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }

    req.user = decoded;
    next();
}