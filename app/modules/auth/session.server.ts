import { createCookieSessionStorage, redirect } from "@remix-run/node";
import { safeRedirect } from "~/utils";
import { NODE_ENV, SESSION_SECRET } from "~/utils/env.server";
import { getCurrentPath, isGet, makeRedirectToFromHere } from "~/utils/http";
import { refreshAccessToken, verifyAuthSession } from "./service.server";
import type { AuthSession } from "./types";

const SESSION_KEY = "authenticated";
const SESSION_ERROR_KEY = "error";
const SESSION_MAX_AGE = 60 * 60 * 24 * 7; // 7 days
const LOGIN_URL = "/login";
const REFRESH_ACCESS_TOKEN_THRESHOLD = 60 * 10; // 10 minutes

const sessionStorage = createCookieSessionStorage({
  cookie: {
    name: "__authSession",
    httpOnly: true,
    path: "/",
    sameSite: "lax",
    secrets: [SESSION_SECRET],
    secure: NODE_ENV === "production",
  },
});

async function getSession(request: Request) {
  const cookie = request.headers.get("Cookie");
  return sessionStorage.getSession(cookie);
}

export async function getAuthSession(
  request: Request
): Promise<AuthSession | null> {
  const session = await getSession(request);
  return session.get(SESSION_KEY);
}

export async function commitAuthSession(
  request: Request,
  {
    authSession,
    flashErrorMessage,
  }: {
    authSession?: AuthSession | null;
    flashErrorMessage?: string | null;
  } = {}
) {
  const session = await getSession(request);

  // Allow the auth session to be null.
  // This lets us clear the session intentionally and display a message
  // explaining why.
  if (authSession !== undefined) {
    session.set(SESSION_KEY, authSession);
  }

  session.flash(SESSION_ERROR_KEY, flashErrorMessage);

  return sessionStorage.commitSession(session, { maxAge: SESSION_MAX_AGE });
}

export async function createAuthSession({
  request,
  authSession,
  redirectTo,
}: {
  request: Request;
  authSession: AuthSession;
  redirectTo: string;
}) {
  return redirect(safeRedirect(redirectTo), {
    headers: {
      "Set-Cookie": await commitAuthSession(request, {
        authSession,
        flashErrorMessage: null,
      }),
    },
  });
}

export async function destroyAuthSession(request: Request) {
  const session = await getSession(request);

  return redirect("/", {
    headers: {
      "Set-Cookie": await sessionStorage.destroySession(session),
    },
  });
}

async function assertAuthSession(
  request: Request,
  { onFailRedirectTo }: { onFailRedirectTo?: string } = {}
) {
  const authSession = await getAuthSession(request);

  // There's no auth session! Redirect as appropriate.
  if (!authSession?.accessToken || !authSession?.refreshToken) {
    throw redirect(
      `${onFailRedirectTo || LOGIN_URL}?${makeRedirectToFromHere(request)}`,
      {
        headers: {
          "Set-Cookie": await commitAuthSession(request, {
            authSession: null,
            flashErrorMessage: "no-user-session",
          }),
        },
      }
    );
  }

  return authSession;
}

function isExpiringSoon(expiresAt: number) {
  return (expiresAt - REFRESH_ACCESS_TOKEN_THRESHOLD) * 1000 < Date.now();
}

export async function refreshAuthSession(
  request: Request
): Promise<AuthSession> {
  const authSession = await getAuthSession(request);

  const refreshedAuthSession = await refreshAccessToken(
    authSession?.refreshToken
  );

  // You're screwed. There's no way to refresh the access token. Log in again
  if (!refreshedAuthSession) {
    const redirectUrl = `${LOGIN_URL}?${makeRedirectToFromHere(request)}`;

    throw redirect(redirectUrl, {
      headers: {
        "Set-Cookie": await commitAuthSession(request, {
          authSession: null,
          flashErrorMessage: "fail-refresh-auth-session",
        }),
      },
    });
  }

  // The refresh is okay and we can redirect
  if (isGet(request)) {
    throw redirect(getCurrentPath(request), {
      headers: {
        "Set-Cookie": await commitAuthSession(request, {
          authSession: refreshedAuthSession,
        }),
      },
    });
  }

  // We can't redirect because we are in the middle of an action.
  // So, deal with it and don't forget to handle session commit.
  return refreshedAuthSession;
}

export async function requireAuthSession(
  request: Request,
  {
    onFailRedirectTo,
    verify,
  }: { onFailRedirectTo?: string; verify: boolean } = { verify: false }
): Promise<AuthSession> {
  const authSession = await assertAuthSession(request, { onFailRedirectTo });

  // Challenge the access token.
  // By default, we don't verify the access token from supabase auth api to save
  // some time.
  const isValidSession = verify ? await verifyAuthSession(authSession) : true;

  // The access token is not valid or expires soon! Refresh it.
  if (!isValidSession || isExpiringSoon(authSession.expiresAt)) {
    return refreshAuthSession(request);
  }

  // This is a valid session!
  return authSession;
}
