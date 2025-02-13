import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export async function middleware(request: NextRequest) {
  const isLoggedIn = !!request.cookies.get('next-auth.session-token'); // Check for session token
  const isOnDashboard = request.nextUrl.pathname.startsWith('/dashboard');

  // Handle unauthenticated access to protected routes
  if (isOnDashboard && !isLoggedIn) {
    return NextResponse.redirect(new URL('/login', request.url));
  }

  // Redirect logged-in users away from login page
  if (request.nextUrl.pathname === '/login' && isLoggedIn) {
    return NextResponse.redirect(new URL('/dashboard', request.url));
  }

  return NextResponse.next();
}

// Restrict middleware to dashboard and login routes only
export const config = {
  matcher: ['/dashboard/:path*', '/login'],
};
