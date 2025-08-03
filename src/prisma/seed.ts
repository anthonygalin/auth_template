import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcrypt';

const prisma = new PrismaClient();

async function main() {
    const existing = await prisma.user.findFirst({ where: { role: 0 } });
    if (existing) {
        console.log("Super Admin already exists.");
        return;
    }

    const hashedPassword = await bcrypt.hash('test2025', 10);

    const superAdmin = await prisma.user.create({
        data: {
            email: 'anthonygalin@gmail.com',
            username: 'su_anthony',
            password: hashedPassword,
            role: 0,
        },
    });

    console.log("✅ Super Admin created:", superAdmin);
}

main().finally(() => prisma.$disconnect());