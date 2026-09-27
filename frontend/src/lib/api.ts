import { API_BASE_URL } from '../config';
import { getSession } from './supabase';

/**
 * ECDAT Centralized API Fetch Wrapper.
 * Automatically injects the Supabase JWT Bearer token into Authorization headers
 * if a valid session exists. Prepends API_BASE_URL if a relative endpoint is provided.
 */
export async function apiFetch(input: string, init?: RequestInit): Promise<Response> {
  const url = input.startsWith('http://') || input.startsWith('https://')
    ? input
    : `${API_BASE_URL}${input.startsWith('/') ? input : `/${input}`}`;

  const headers = new Headers(init?.headers);

  try {
    const session = await getSession();
    if (session?.access_token && !headers.has('Authorization')) {
      headers.set('Authorization', `Bearer ${session.access_token}`);
    }
  } catch (err) {
    // Session lookup failed or offline; continue without bearer token
    console.debug('[apiFetch] Session token check failed, proceeding unauthenticated:', err);
  }

  return fetch(url, {
    ...init,
    headers,
  });
}
