import NextAuth from 'next-auth';
import Credentials from 'next-auth/providers/credentials';
import { authConfig } from './auth.config';
import { z } from 'zod';
import type { User } from '@/app/lib/definitions';
import bcrypt from 'bcrypt';
import postgres from 'postgres';

const sql = postgres(process.env.POSTGRES_URL!, { ssl: 'require' });

async function getUser(email: string): Promise<User | undefined> {
  try {
    const user = await sql<User[]>`
      SELECT * FROM users WHERE email=${email}
    `;
    return user[0];
  } catch (error) {
    console.error('Failed to fetch user:', error);
    throw new Error('Failed to fetch user.');
  }
}

export const { auth, signIn, signOut } = NextAuth({
  ...authConfig,
  providers: [
    Credentials({
      async authorize(credentials) {
        try {
          const parsedCredentials = z
            .object({
              email: z.string().email(),
              password: z.string().min(6),
            })
            .safeParse(credentials);

          // Validación fallida
          if (!parsedCredentials.success) {
            console.log('Invalid input format');
            return null;
          }

          const { email, password } = parsedCredentials.data;

          const user = await getUser(email);

          // Usuario no existe
          if (!user) {
            console.log('User not found');
            return null;
          }

          // Usuario sin password (por seguridad)
          if (!user.password) {
            console.log('User has no password');
            return null;
          }

          const passwordsMatch = await bcrypt.compare(
            password,
            user.password
          );

          // Password incorrecta
          if (!passwordsMatch) {
            console.log('Password does not match');
            return null;
          }

          // Login correcto
          return user;
        } catch (error) {
          console.error('Authorize error:', error);
          return null;
        }
      },
    }),
  ],
});