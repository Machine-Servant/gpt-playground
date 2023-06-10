import { createClient } from "@supabase/supabase-js";
import {
  SUPABASE_ANON_PUBLIC,
  SUPABASE_SERVICE_ROLE,
  SUPABASE_URL,
} from "~/utils/env.server";
import { isBrowser } from "~/utils/is-browser";

// ⚠️ cloudflare needs you define fetch option : https://github.com/supabase/supabase-js#custom-fetch-implementation
// Use Remix fetch polyfill for node (See https://remix.run/docs/en/v1/other-api/node)
function getSupabaseClient(
  supabaseKey: string,
  accessToken?: string | null,
  supabaseUrl?: string
) {
  const global = accessToken
    ? {
        global: {
          headers: {
            Authorization: `Bearer ${accessToken}`,
          },
        },
      }
    : {};

  return createClient(supabaseUrl || SUPABASE_URL, supabaseKey, {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
    },
    ...global,
  });
}

/**
 * Provides a Supabase Client for the logged in user or get back a public and safe client without admin privileges
 *
 * It's a per request scoped client to prevent access token leaking over multiple concurrent requests and from different users.
 *
 * Reason : https://github.com/rphlmr/supa-fly-stack/pull/43#issue-1336412790
 */
function getSupabase(
  accessToken?: string | null,
  {
    supabaseAnonPublic,
    supabaseUrl,
  }: { supabaseAnonPublic?: string; supabaseUrl?: string } = {}
) {
  return getSupabaseClient(
    supabaseAnonPublic || SUPABASE_ANON_PUBLIC,
    accessToken,
    supabaseUrl
  );
}

/**
 * Provides a Supabase Admin Client with full admin privileges
 *
 * It's a per request scoped client, to prevent access token leaking if you don't use it like `getSupabaseAdmin().auth.api`.
 *
 * Reason : https://github.com/rphlmr/supa-fly-stack/pull/43#issue-1336412790
 */
function getSupabaseAdmin() {
  if (isBrowser)
    throw new Error(
      "getSupabaseAdmin is not available in browser and should NOT be used in insecure environments"
    );

  return getSupabaseClient(SUPABASE_SERVICE_ROLE);
}

export { getSupabaseAdmin, getSupabase };
