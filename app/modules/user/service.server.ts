import type { User } from "@prisma/client";
import { db } from "~/database";
import type { AuthSession } from "../auth";
import {
  createEmailAuthAccount,
  deleteAuthAccount,
  signInWithEmail,
} from "../auth/service.server";

export async function getUserByEmail(email: User["email"]) {
  return db.user.findUnique({ where: { email: email.toLowerCase() } });
}

async function createUser({
  email,
  userId,
}: Pick<AuthSession, "userId" | "email">) {
  return db.user
    .create({
      data: {
        email: email.toLowerCase(),
        id: userId,
      },
    })
    .then((user) => user)
    .catch(() => null);
}

export async function tryCreateUser({
  email,
  userId,
}: Pick<AuthSession, "userId" | "email">) {
  const user = await createUser({ email, userId });

  // The user account was created and there is a session but we are unable to
  // store the user in the User table.
  // We shoud delete the auth account so it can be re-created if/when this user
  // is created again later.
  if (!user) {
    await deleteAuthAccount(email);
    return null;
  }

  return user;
}

export async function createUserAccount(
  email: string,
  password: string
): Promise<AuthSession | null> {
  const authAccount = await createEmailAuthAccount(email, password);

  // No auth account was created, No problem. Just return null
  if (!authAccount) return null;

  const authSession = await signInWithEmail(email, password);

  // The auth account was created but there is no session
  // We should delete the auth account so it can be re-created if/when this user
  // is created again later.
  if (!authSession) {
    await deleteAuthAccount(authAccount.id);
    return null;
  }

  const user = await tryCreateUser(authSession);

  if (!user) return null;

  return authSession;
}
