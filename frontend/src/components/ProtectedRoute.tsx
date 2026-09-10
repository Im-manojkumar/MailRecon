'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/lib/auth-context';

export default function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { analyst, isLoading } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (!isLoading && !analyst) {
      router.push('/login');
    }
  }, [isLoading, analyst, router]);

  if (isLoading) {
    return <div className="flex items-center justify-center min-h-screen">Loading...</div>;
  }

  if (!analyst) {
    return null;
  }

  return <>{children}</>;
}
