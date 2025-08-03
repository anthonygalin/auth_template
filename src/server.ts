import express from 'express';
import userRoutes from './routes/users';
import authRoutes from './routes/auth';

const app = express();

app.use(express.json());

app.use('/api/users', userRoutes);
app.use('/api/auth', authRoutes);
app.use('/api/2fa', authRoutes);
app.get('/', (_req, res) => {
    res.send('API is running 🚀');
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`Server listening on http://localhost:${PORT}`);
});