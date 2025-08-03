import { Router } from 'express';
import bcrypt from 'bcrypt';
import { PrismaClient } from '@prisma/client';
import { requireRole } from '../middlewares/auth';
import { authenticateJWT } from '../middlewares/authenticate';

const prisma = new PrismaClient();
const router = Router();

// SuperAdmin (0) puede crear admin(1) y user(2)
// Admin (1) solo puede crear user(2)
router.post('/register', requireRole(1), authenticateJWT, async (req, res) => {
    const currentUser = req.user; // Ya verificado por authenticateJWT
    const { email, username, password, role } = req.body;

    if (!email || !username || !password || role === undefined) {
        return res.status(400).json({ error: 'Missing fields' });
    }

    try {
        // Validación de permisos
        if (currentUser.role === 0) {
            // Super admin puede crear cualquier rol
            // no hay restricción
        } else if (currentUser.role === 1) {
            // Admin solo puede crear usuarios normales
            if (role !== 2) {
                return res.status(403).json({ error: 'Admins can only create normal users' });
            }
        } else {
            // Usuario normal no puede crear usuarios
            return res.status(403).json({ error: 'Permission denied' });
        }

        // Check existentes
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

        // Si el usuario quiere editarse a sí mismo, siempre lo puede hacer
        const editingSelf = currentUser.id === targetUser.id;

        // Reglas por rol
        if (!editingSelf) {
            if (currentUser.role === 2) {
                return res.status(403).json({ error: 'Users can only edit themselves' });
            }

            if (currentUser.role === 1 && targetUser.role !== 2) {
                return res.status(403).json({ error: 'Admins can only edit normal users or themselves' });
            }
        }

        // Validar que un admin no pueda cambiar el rol a admin o superadmin
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
            // Super admin puede eliminar a cualquiera excepto a sí mismo
            if (deletingSelf) {
                return res.status(403).json({ error: 'Super admin cannot delete themselves' });
            }
        } else if (currentUser.role === 1) {
            // Admin solo puede eliminar usuarios normales
            if (targetUser.role !== 2) {
                return res.status(403).json({ error: 'Admins can only delete normal users' });
            }

            if (deletingSelf) {
                return res.status(403).json({ error: 'Admins cannot delete themselves' });
            }
        } else {
            // Usuario normal no puede eliminar a nadie
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