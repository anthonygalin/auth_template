import {generateAccessToken, generateRefreshToken} from "../utils/jwt";
import speakeasy from 'speakeasy';
import qrcode from 'qrcode';
import {PrismaClient} from "@prisma/client";
import {Router} from "express";
const prisma = new PrismaClient();
const router = Router();

router.post('/generate', async (req, res) => {
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

router.post('/verify', async (req, res) => {
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

export default router