# Proyecto Backend Express + Prisma + 2FA (Google Authenticator) + Roles

## 📋 Descripción

Este proyecto es un backend construido con **Express.js** y **TypeScript**, usando **Prisma** como ORM para PostgreSQL. Implementa autenticación segura con JWT y autenticación de dos factores (2FA) basada en TOTP usando Google Authenticator. 

El sistema maneja usuarios divididos en tres roles jerárquicos con permisos específicos:

| Rol          | Código | Permisos principales                                           |
| ------------ | ------ | ------------------------------------------------------------- |
| Super Admin  | 0      | Puede crear, modificar y eliminar admins y usuarios normales. |
| Admin        | 1      | Puede crear, modificar y eliminar usuarios normales. Se puede modificar a sí mismo. |
| Usuario      | 2      | Solo puede modificar su propia información personal.          |

---

## ⚙️ Tecnologías usadas

- **Express.js** — Framework backend para Node.js.
- **TypeScript** — Tipado estático y mejoras de desarrollo.
- **Prisma** — ORM para PostgreSQL, facilita gestión de datos.
- **PostgreSQL** — Base de datos relacional.
- **jsonwebtoken** — Para creación y validación de JWT.
- **bcrypt** — Para hashing seguro de contraseñas.
- **speakeasy** — Para generación y verificación de códigos TOTP 2FA.
- **qrcode** — Generación de códigos QR para el secret de 2FA.
- **Postman** — Para pruebas y colecciones de API.

---

## 🗂 Estructura del proyecto

```
src/
  controllers/          # Lógica de control para rutas
  middlewares/          # Middlewares para auth, validación roles, etc.
  routes/               # Definición de rutas Express
  services/             # Servicios como manejo de 2FA, JWT, etc.
  utils/                # Utilidades generales (hash, validaciones)
  index.ts              # Punto de entrada del servidor Express
prisma/
  schema.prisma         # Definición del modelo de datos
  migrations/           # Migraciones de base de datos
.env                    # Variables de entorno (DB, JWT keys, etc.)
```

---

## 🔌 Rutas principales

| Método | Ruta                   | Descripción                                    | Roles permitidos                 |
|--------|------------------------|-----------------------------------------------|---------------------------------|
| POST   | `/api/auth/register`   | Crear nuevo usuario (con validación de rol)  | Super Admin (0), Admin (1)       |
| POST   | `/api/auth/login`      | Login con email/username y password           | Todos                          |
| POST   | `/api/auth/logout`     | Logout y eliminación del refresh token        | Todos                          |
| POST   | `/api/2fa/generate`   | Generar QR y secreto para configurar 2FA      | Usuarios autenticados           |
| POST   | `/api/2fa/verify`     | Verificar código 2FA e activar 2FA             | Usuarios autenticados           |
| GET    | `/api/users`           | Obtener listado de usuarios                     | Solo Super Admin               |
| PUT    | `/api/users/:id`       | Editar usuario (con control de permisos)       | Según rol (ver reglas en código)|
| DELETE | `/api/users/:id`       | Eliminar usuario (según rol)                    | Según rol (ver reglas en código)|

---

## 🔐 Seguridad y autenticación

- Uso de JWT para autenticación y manejo de sesiones.
- Refresh tokens con expiración y revocación.
- 2FA basado en TOTP con Google Authenticator.
- Hashing de contraseñas con bcrypt.
- Control riguroso de acceso por roles.
- Validaciones para evitar que usuarios escalen permisos o eliminen a otros indebidamente.

---

## 🛠 Cómo usar el proyecto

### 1. Clonar repositorio

```bash
git clone <url-del-repo>
cd proyecto-backend
```

### 2. Instalar dependencias

```bash
npm install
```

### 3. Configurar variables de entorno

Crear archivo `.env` con:

```
DATABASE_URL="postgresql://usuario:contraseña@localhost:5432/mi_db"
JWT_SECRET="tu_clave_jwt_secreta"
REFRESH_TOKEN_SECRET="tu_clave_refresh_secreta"
```

### 4. Ejecutar migraciones

```bash
npx prisma migrate dev --name init
```

### 5. Ejecutar servidor

```bash
npm run dev
```

Servidor correrá en `http://localhost:3001`.

---

## 🧪 Pruebas

- Se incluye una colección Postman con pruebas para todos los endpoints y casos de uso (roles, 2FA, etc.).
- Puedes importar el archivo `coleccion_postman_api_pruebas.json` para facilitar pruebas.
- Usa variables de entorno en Postman para tokens JWT.

---

## 🤝 Contribuciones

Este proyecto está abierto a mejoras. Si quieres contribuir, abre un issue o pull request.

---

Si quieres que te prepare el frontend con Vite para consumir esta API, o alguna otra funcionalidad, dime y seguimos.

---

¿Querés que te genere también una plantilla para la documentación Swagger/OpenAPI?
