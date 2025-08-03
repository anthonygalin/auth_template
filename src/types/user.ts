
enum Roles {
    super_admin = 0,
    admin = 1,
    normal = 2,
}

interface User {
    id: string;
    email: string;
    username: string;
    password: string;
    twoFASecret?: string | null;
    refreshToken?: string | null;
    role: Roles;
    createdAt: Date;
    updatedAt: Date;
}