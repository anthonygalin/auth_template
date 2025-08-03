import { Router } from 'express';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcrypt';
import speakeasy from 'speakeasy';
import qrcode from 'qrcode';
import {generateAccessToken, generateRefreshToken, verifyRefreshToken} from '../utils/jwt';

const prisma = new PrismaClient();
const router = Router();

router.post('/login', async (req, res) => {
    const { identifier, password } = req.body;

    if (!identifier || !password) {
        return res.status(400).json({ error: 'Missing credentials' });
    }

    try {
        const user = await prisma.user.findFirst({
            where: {
                OR: [{ email: identifier }, { username: identifier }],
            },
        });

        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        if (!user.twoFASecret) {
            return res.status(200).json({
                step: 'setup_2fa',
                message: 'User authenticated, but 2FA setup is required.',
                userId: user.id,
            });
        }

        return res.status(200).json({
            step: 'verify_2fa',
            message: 'Please verify your 2FA code.',
            userId: user.id,
        });
    } catch (error) {
        console.error('Login error:', error);
        return res.status(500).json({ error: 'Internal server error' });
    }
});

router.post('/setup-2fa', async (req, res) => {
    const { userId } = req.body;
    const appName = 'test-auth';

    if (!userId) return res.status(400).json({ error: 'Missing user ID' });

    try {
        const user = await prisma.user.findUnique({ where: { id: userId } });

        if (!user) return res.status(404).json({ error: 'User doesnt exist' });

        if (user.twoFASecret) {
            return res.status(400).json({ error: '2FA is already set up' });
        }

        const secret = speakeasy.generateSecret({
            name: `${appName}:${user.email}`,
        });

        await prisma.user.update({
            where: { id: user.id },
            data: { twoFASecret: secret.base32 },
        });

        const qrDataURL = await qrcode.toDataURL(secret.otpauth_url!);

        res.status(200).json({
            message: '2FA secret generated. Please scan the QR.',
            qr: qrDataURL,
            manualEntryKey: secret.base32,
        });
    } catch (err) {
        console.error('2FA Setup Error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

router.post('/verify-2fa', async (req, res) => {
    const { userId, token } = req.body;

    if (!userId || !token) {
        return res.status(400).json({ error: 'Missing user ID or token' });
    }

    try {
        const user = await prisma.user.findUnique({
            where: { id: userId },
        });

        if (!user || !user.twoFASecret) {
            return res.status(400).json({ error: 'User not found or 2FA not set up' });
        }

        const isValid = speakeasy.totp.verify({
            secret: user.twoFASecret,
            encoding: 'base32',
            token,
            window: 1,
        });

        if (!isValid) {
            return res.status(401).json({ error: 'Invalid 2FA code' });
        }

        const accessToken  = generateAccessToken({
            id: user.id,
            role: user.role,
            email: user.email,
        });

        const refreshToken = generateRefreshToken({ id: user.id });

        await prisma.user.update({
            where: { id: user.id },
            data: { refreshToken },
        });

        return res.status(200).json({
            message: '2FA verification successful. Login complete.',
            accessToken,
            refreshToken,
        });
    } catch (err) {
        console.error('2FA verification error:', err);
        return res.status(500).json({ error: 'Internal server error' });
    }
});

router.post('/refresh-token', async (req, res) => {
    const { refreshToken } = req.body;

    if (!refreshToken) {
        return res.status(400).json({ error: 'Missing refresh token' });
    }

    const payload = verifyRefreshToken(refreshToken);

    if (!payload) {
        return res.status(401).json({ error: 'Invalid refresh token' });
    }

    try {
        const user = await prisma.user.findUnique({
            where: { id: payload.id },
        });

        if (!user || user.refreshToken !== refreshToken) {
            return res.status(401).json({ error: 'Refresh token does not match' });
        }

        const newAccessToken = generateAccessToken({
            id: user.id,
            email: user.email,
            role: user.role,
        });

        const newRefreshToken = generateRefreshToken({ id: user.id });

        await prisma.user.update({
            where: { id: user.id },
            data: { refreshToken: newRefreshToken },
        });

        return res.status(200).json({
            accessToken: newAccessToken,
            refreshToken: newRefreshToken,
        });
    } catch (err) {
        console.error('Refresh token error:', err);
        return res.status(500).json({ error: 'Internal server error' });
    }
});

router.post('/logout', async (req, res) => {
    const { refreshToken } = req.body;

    if (!refreshToken) {
        return res.status(400).json({ error: 'Missing refresh token' });
    }

    const payload = verifyRefreshToken(refreshToken);
    if (!payload) {
        return res.status(401).json({ error: 'Invalid refresh token' });
    }

    try {
        const user = await prisma.user.findUnique({
            where: { id: payload.id },
        });

        if (!user || user.refreshToken !== refreshToken) {
            return res.status(401).json({ error: 'Token mismatch' });
        }

        await prisma.user.update({
            where: { id: user.id },
            data: { refreshToken: null },
        });

        return res.status(200).json({ message: 'Logged out successfully' });
    } catch (err) {
        console.error('Logout error:', err);
        return res.status(500).json({ error: 'Internal server error' });
    }
});

export default router;
