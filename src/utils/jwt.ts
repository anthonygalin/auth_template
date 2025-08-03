import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET!;
const REFRESH_SECRET = process.env.REFRESH_SECRET
const EXPIRATION = '15m';

export function generateAccessToken(payload: object): string {
    return jwt.sign(payload, JWT_SECRET, { expiresIn: EXPIRATION });
}

export function generateRefreshToken(payload: object): string {
    return jwt.sign(payload, REFRESH_SECRET, { expiresIn: '7d' });
}

export function verifyToken(token: string): any {
    try {
        return jwt.verify(token, JWT_SECRET);
    } catch {
        return null;
    }
}

export function verifyRefreshToken(token: string): any {
    try {
        return jwt.verify(token, REFRESH_SECRET);
    } catch {
        return null;
    }
}