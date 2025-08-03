import { Request, Router } from 'express';
import bcrypt from 'bcrypt';
import { PrismaClient } from '@prisma/client';
import { requireRole } from '../middlewares/auth';
import { authenticateJWT } from '../middlewares/authenticate';

const prisma = new PrismaClient();
const router = Router();

router.post('/register', requireRole(1), authenticateJWT, async (req:Request, res) => {
    const currentUser = req.user;
    const { email, username, password, role } = req.body;

    if (!email || !username || !password || role === undefined) {
        return res.status(400).json({ error: 'Missing fields' });
    }

    try {
        if (currentUser.role === 0) {
        } else if (currentUser.role === 1) {
            if (role !== 2) {
                return res.status(403).json({ error: 'Admins can only create normal users' });
            }
        } else {
            return res.status(403).json({ error: 'Permission denied' });
        }

        const existingUser = await prisma.user.findFirst({
            where: {
                OR: [
                    { email },
                    { username }
                ]
            }
        });

        if (existingUser) {
            return res.status(409).json({ error: 'User already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = await prisma.user.create({
            data: {
                email,
                username,
                password: hashedPassword,
                role,
            },
        });

        return res.status(201).json({
            message: 'User created successfully',
            user: {
                id: newUser.id,
                email: newUser.email,
                username: newUser.username,
                role: newUser.role,
            },
        });
    } catch (err) {
        console.error('Error creating user:', err);
        return res.status(500).json({ error: 'Internal server error' });
    }
});

router.put('/users/:id', requireRole(2), authenticateJWT, async (req, res) => {
    const userIdToUpdate = req.params.id;
    const currentUser = req.user;
    const { email, username, role } = req.body;

    try {
        const targetUser = await prisma.user.findUnique({ where: { id: userIdToUpdate } });

        if (!targetUser) {
            return res.status(404).json({ error: 'User not found' });
        }

        const editingSelf = currentUser.id === targetUser.id;

        if (!editingSelf) {
            if (currentUser.role === 2) {
                return res.status(403).json({ error: 'Users can only edit themselves' });
            }

            if (currentUser.role === 1 && targetUser.role !== 2) {
                return res.status(403).json({ error: 'Admins can only edit normal users or themselves' });
            }
        }

        if (currentUser.role === 1 && role !== undefined && role !== 2) {
            return res.status(403).json({ error: 'Admins cannot assign elevated roles' });
        }

        const updatedUser = await prisma.user.update({
            where: { id: userIdToUpdate },
            data: {
                email,
                username,
                role: role ?? targetUser.role,
            },
        });

        return res.status(200).json({
            message: 'User updated successfully',
            user: {
                id: updatedUser.id,
                email: updatedUser.email,
                username: updatedUser.username,
                role: updatedUser.role,
            },
        });
    } catch (err) {
        console.error('Update error:', err);
        return res.status(500).json({ error: 'Internal server error' });
    }
});

router.delete('/users/:id',requireRole(1), authenticateJWT, async (req, res) => {
    const userIdToDelete = req.params.id;
    const currentUser = req.user;

    try {
        const targetUser = await prisma.user.findUnique({ where: { id: userIdToDelete } });

        if (!targetUser) {
            return res.status(404).json({ error: 'User not found' });
        }

        const deletingSelf = currentUser.id === targetUser.id;

        if (currentUser.role === 0) {
            if (deletingSelf) {
                return res.status(403).json({ error: 'Super admin cannot delete themselves' });
            }
        } else if (currentUser.role === 1) {
            if (targetUser.role !== 2) {
                return res.status(403).json({ error: 'Admins can only delete normal users' });
            }
            if (deletingSelf) {
                return res.status(403).json({ error: 'Admins cannot delete themselves' });
            }
        } else {
            return res.status(403).json({ error: 'Permission denied' });
        }

        await prisma.user.delete({ where: { id: userIdToDelete } });

        return res.status(200).json({ message: 'User deleted successfully' });
    } catch (err) {
        console.error('Delete error:', err);
        return res.status(500).json({ error: 'Internal server error' });
    }
});

export default router;