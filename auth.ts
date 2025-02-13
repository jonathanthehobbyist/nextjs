import NextAuth, { NextAuthConfig } from 'next-auth';
import { authConfig } from './auth.config';
import Credentials from 'next-auth/providers/credentials';
import { z } from 'zod';
import type { User } from '@/app/lib/definitions';
import bcrypt from 'bcrypt';
import postgres from 'postgres';

// Initialize the PostgreSQL connection
const sql = postgres(process.env.POSTGRES_URL!, { ssl: 'require' });

// Define the Zod schema for credentials validation
const credentialsSchema = z.object({
  email: z.string().email(),
  password: z.string().min(6),
});

// Helper function to retrieve the user from the database
async function getUser(email: string): Promise<User | null> {
  try {
    const users = await sql<User[]>`SELECT * FROM users WHERE email=${email}`;
    return users.length ? users[0] : null;
  } catch (error) {
    console.error('Failed to fetch user', error);
    return null;
  }
}

// Define NextAuth configuration
const nextAuthConfig: NextAuthConfig = {
  ...authConfig,
  providers: [
    Credentials({
      name: 'Credentials',
      credentials: {
        email: { label: 'Email', type: 'text' },
        password: { label: 'Password', type: 'password' },
      },
      async authorize(credentials) {
        // Validate credentials using Zod
        const parsedCredentials = credentialsSchema.safeParse(credentials);
        if (!parsedCredentials.success) {
          console.log('Invalid credentials structure');
          return null;
        }

        const { email, password } = parsedCredentials.data;

        // Fetch the user from the database
        const user = await getUser(email);
        if (!user) {
          console.log('User not found');
          return null;
        }

        // Verify the provided password
        const passwordsMatch = await bcrypt.compare(password, user.password);
        if (!passwordsMatch) {
          console.log('Invalid password');
          return null;
        }

        // Return the user object for NextAuth session
        return {
          id: user.id.toString(),
          email: user.email,
          name: user.name,
          role: user.role, // Include if role-based access is needed
        };
      },
    }),
  ],
  callbacks: {
    session({ session, user }) {
      // Include user ID in the session object
      if (session?.user) {
        session.user.id = user.id;
      }
      return session;
    },
    async jwt({ token, user }) {
      // Attach user ID to the token
      if (user) {
        token.id = user.id;
      }
      return token;
    },
  },
  pages: {
    signIn: '/login',
    error: '/login?error=1', // Redirect to a custom error page if needed
  },
  session: {
    strategy: 'jwt', // v5 defaults to JWT sessions; confirm this if needed
  },
  debug: process.env.NODE_ENV === 'development',
};

// Export NextAuth handler
const handler = NextAuth(nextAuthConfig);
export { handler as GET, handler as POST };
