import express from 'express';
import { PrismaClient } from '@prisma/client';
import userRoutes from './routes/users';
import authRoutes from './routes/auth';

const app = express();
const prisma = new PrismaClient();

app.use(express.json());

app.use((req, _res, next) => {
    // Simular que el super admin está logueado
    req.user = {
        id: 'cmdrwgbyo0000loe0wsws5635',
        email: 'anthonygalin@gmail.com',
        role: 0, // cambiar por 1 para simular admin
    };
    next();
});

app.use('/api/users', userRoutes);
app.use('/api/auth', authRoutes);

app.get('/', (_req, res) => {
    res.send('API is running 🚀');
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`Server listening on http://localhost:${PORT}`);
});