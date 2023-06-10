import { getSupabaseAdmin } from "~/integrations/supabase";
import { SERVER_URL } from "~/utils";
import type { AuthSession } from "./types";
import { mapAuthSession } from "./utils";

export async function createEmailAuthAccount(email: string, password: string) {
  const { data, error } = await getSupabaseAdmin().auth.admin.createUser({
    email,
    password,
    // TODO: add email confirm
    email_confirm: true,
  });

  if (!data.user || error) return null;

  return data.user;
}

export async function deleteAuthAccount(userId: string) {
  const { error } = await getSupabaseAdmin().auth.admin.deleteUser(userId);

  if (error) return null;

  return true;
}

export async function signInWithEmail(email: string, password: string) {
  const { data, error } = await getSupabaseAdmin().auth.signInWithPassword({
    email,
    password,
  });

  // There is no session or there was an error, just return null
  if (!data.session || error) return null;

  return mapAuthSession(data.session);
}

export async function getAuthAccountByAccessToken(accessToken: string) {
  const { data, error } = await getSupabaseAdmin().auth.getUser(accessToken);

  if (!data.user || error) return null;

  return data.user;
}

export async function verifyAuthSession(authSession: AuthSession) {
  const authAccount = await getAuthAccountByAccessToken(
    authSession.accessToken
  );

  return Boolean(authAccount);
}

export async function refreshAccessToken(
  refreshToken?: string
): Promise<AuthSession | null> {
  if (!refreshToken) return null;

  const { data, error } = await getSupabaseAdmin().auth.refreshSession({
    refresh_token: refreshToken,
  });

  if (!data.session || error) return null;

  return mapAuthSession(data.session);
}

export async function sendMagicLink(email: string) {
  return getSupabaseAdmin().auth.signInWithOtp({
    email,
    options: {
      emailRedirectTo: `${SERVER_URL}/oauth/callback`,
    },
  });
}

export async function sendResetPasswordLink(email: string) {
  return getSupabaseAdmin().auth.resetPasswordForEmail(email, {
    redirectTo: `${SERVER_URL}/reset-password`,
  });
}

export async function updateAccountPassword(id: string, password: string) {
  const { data, error } = await getSupabaseAdmin().auth.admin.updateUserById(
    id,
    { password }
  );

  if (!data.user || error) return null;

  return data.user;
}
