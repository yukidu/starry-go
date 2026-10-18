import type { Env, User } from "./types";
import { createSession } from "./db";
import { checkCentralAppEntitlement } from "./centralAppAccess";
import { cookie, sha256 } from "./security";

const STARRY_ID_ORIGIN = "https://id.starry.phd";
const APP_ID = "gostarry";
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 30;
const CODE_RE = /^[A-Za-z0-9_-]{30,}$/;
const RESERVED_PROFILE_SLUGS = new Set(["api", "robots.txt", "login", "logout", "admin", "manifest.webmanifest", "favicon.ico", "assets"]);
let localSchemaReady: Promise<void> | null = null;

interface CentralMember {
  id: string;
  primaryEmail: string;
  status: string;
  name: string | null;
  avatar: string | null;
  googleAvatar: string | null;
  membershipStatus: string | null;
}

interface CentralProfileSnapshot extends CentralMember {
  approvedRank: string | null;
  rank: string | null;
}

function centralProfileSlug(value: unknown): string {
  const slug = String(value || "").trim().toLowerCase().normalize("NFKC")
    .replace(/[^a-z0-9_-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 64);
  return RESERVED_PROFILE_SLUGS.has(slug) ? "" : slug;
}

export function startStarryAuth(): Response {
  return Response.redirect(`${STARRY_ID_ORIGIN}/auth/${APP_ID}`, 302);
}

async function ensureLocalSchema(env: Env): Promise<void> {
  if (!localSchemaReady) {
    localSchemaReady = env.DB.prepare(`CREATE TABLE IF NOT EXISTS starry_identities (
      starry_user_id TEXT PRIMARY KEY,
      local_user_id TEXT NOT NULL UNIQUE,
      linked_at TEXT NOT NULL,
      FOREIGN KEY (local_user_id) REFERENCES users(id) ON DELETE CASCADE
    )`).run().then(() => undefined).catch((error) => {
      localSchemaReady = null;
      throw error;
    });
  }
  await localSchemaReady;
}

async function consumeCode(env: Env, code: string): Promise<string | null> {
  const codeHash = await sha256(code);
  const row = await env.STARRY_ID_DB.prepare(`
    DELETE FROM starry_app_auth_codes
    WHERE codeHash = ? AND appId = ? AND expiresAt > ?
    RETURNING userId
  `).bind(codeHash, APP_ID, Date.now()).first<{ userId: string }>();
  return row?.userId ? String(row.userId) : null;
}

async function readCentralMember(env: Env, userId: string): Promise<CentralMember | null> {
  return env.STARRY_ID_DB.prepare(`
    SELECT
      u.id,
      u.primaryEmail,
      u.status,
      p.name,
      p.avatar,
      p.googleAvatar,
      am.status AS membershipStatus
    FROM users u
    JOIN app_memberships am ON am.userId = u.id AND am.appId = ?
    LEFT JOIN profiles p ON p.userId = u.id
    WHERE u.id = ?
    LIMIT 1
  `).bind(APP_ID, userId).first<CentralMember>();
}

async function readCentralProfile(env: Env, userId: string): Promise<CentralProfileSnapshot | null> {
  return env.STARRY_ID_DB.prepare(`
    SELECT
      u.id,
      u.primaryEmail,
      u.status,
      p.name,
      p.avatar,
      p.googleAvatar,
      p.approvedRank,
      p.rank,
      am.status AS membershipStatus
    FROM users u
    LEFT JOIN profiles p ON p.userId = u.id
    LEFT JOIN app_memberships am ON am.userId = u.id AND am.appId = ?
    WHERE u.id = ?
    LIMIT 1
  `).bind(APP_ID, userId).first<CentralProfileSnapshot>();
}

async function findCentralProfileByEmail(env: Env, email: string): Promise<CentralProfileSnapshot | null> {
  return env.STARRY_ID_DB.prepare(`
    SELECT
      u.id,
      u.primaryEmail,
      u.status,
      p.name,
      p.avatar,
      p.googleAvatar,
      p.approvedRank,
      p.rank,
      am.status AS membershipStatus
    FROM users u
    LEFT JOIN profiles p ON p.userId = u.id
    LEFT JOIN app_memberships am ON am.userId = u.id AND am.appId = ?
    WHERE lower(trim(u.primaryEmail)) = lower(trim(?))
    LIMIT 1
  `).bind(APP_ID, email).first<CentralProfileSnapshot>();
}

async function ensureCentralPublicCard(env: Env, starryUserId: string): Promise<string | null> {
  type Card = { seq: number; slug: string; cardNumber: string };
  const now = Date.now();
  const profile = await env.STARRY_ID_DB.prepare(`
    SELECT amwayId FROM profiles WHERE userId = ? LIMIT 1
  `).bind(starryUserId).first<{ amwayId: string | null }>();

  let card = await env.STARRY_ID_DB.prepare(`
    SELECT seq, slug, cardNumber
    FROM public_cards
    WHERE userId = ?
    LIMIT 1
  `).bind(starryUserId).first<Card>();

  if (!card) {
    const pending = `pending-${crypto.randomUUID()}`;
    try {
      await env.STARRY_ID_DB.prepare(`
        INSERT INTO public_cards (userId, slug, cardNumber, createdAt, updatedAt)
        VALUES (?, ?, ?, ?, ?)
      `).bind(starryUserId, pending, pending, now, now).run();
    } catch {
      // A concurrent Starry ID request may have created the same member card first.
    }
    card = await env.STARRY_ID_DB.prepare(`
      SELECT seq, slug, cardNumber
      FROM public_cards
      WHERE userId = ?
      LIMIT 1
    `).bind(starryUserId).first<Card>();
  }
  if (!card) return null;

  if (String(card.slug || "").startsWith("pending-") || String(card.cardNumber || "").startsWith("pending-")) {
    const number = `n${Number(card.seq)}`;
    await env.STARRY_ID_DB.prepare(`
      UPDATE public_cards
      SET slug = ?, cardNumber = ?, updatedAt = ?
      WHERE userId = ?
    `).bind(number, number, now, starryUserId).run();
    card = { ...card, slug: number, cardNumber: number };
  }

  const amwaySlug = centralProfileSlug(profile?.amwayId);
  const desiredSlug = amwaySlug || String(card.cardNumber || "").trim();
  if (desiredSlug && desiredSlug !== card.slug) {
    const owner = await env.STARRY_ID_DB.prepare(`
      SELECT userId FROM public_cards WHERE slug = ? LIMIT 1
    `).bind(desiredSlug).first<{ userId: string }>();
    if (!owner || String(owner.userId) === starryUserId) {
      await env.STARRY_ID_DB.prepare(`
        UPDATE public_cards SET slug = ?, updatedAt = ? WHERE userId = ?
      `).bind(desiredSlug, now, starryUserId).run();
      card = { ...card, slug: desiredSlug };
    }
  }

  return String(card.slug || "").trim() || null;
}

export async function enrichStarryUser(env: Env, user: User): Promise<User> {
  try {
    await ensureLocalSchema(env);

    const mapping = await env.DB.prepare(`
      SELECT starry_user_id
      FROM starry_identities
      WHERE local_user_id = ?
      LIMIT 1
    `).bind(user.id).first<{ starry_user_id: string }>();

    let central = mapping?.starry_user_id
      ? await readCentralProfile(env, mapping.starry_user_id)
      : await findCentralProfileByEmail(env, user.email);

    if (!central || central.status !== "active" || central.membershipStatus === "inactive") return user;

    if (!mapping?.starry_user_id) {
      await env.DB.prepare(`
        INSERT OR IGNORE INTO starry_identities (starry_user_id, local_user_id, linked_at)
        VALUES (?, ?, datetime('now'))
      `).bind(central.id, user.id).run();
    }

    const displayName = String(central.name || user.display_name || "").trim() || user.display_name;
    const avatarUrl = String(central.avatar || central.googleAvatar || user.avatar_url || "").trim() || user.avatar_url;
    const rank = String(central.approvedRank || central.rank || "").trim() || null;
    const slug = await ensureCentralPublicCard(env, central.id);

    if (displayName !== user.display_name || avatarUrl !== user.avatar_url) {
      await env.DB.prepare(`
        UPDATE users
        SET display_name = ?, avatar_url = ?, updated_at = datetime('now')
        WHERE id = ?
      `).bind(displayName || null, avatarUrl || null, user.id).run();
    }

    return {
      ...user,
      display_name: displayName || null,
      avatar_url: avatarUrl || null,
      starry_rank: rank,
      starry_profile_url: slug ? `${STARRY_ID_ORIGIN}/${encodeURIComponent(slug)}` : null
    };
  } catch (error) {
    console.error("Starry ID profile enrichment failed", error);
    return user;
  }
}

async function resolveLocalUser(env: Env, member: CentralMember): Promise<User> {
  await ensureLocalSchema(env);
  const email = String(member.primaryEmail || "").trim().toLowerCase();
  if (!email) throw new Error("central_email_missing");

  const mapped = await env.DB.prepare(`
    SELECT u.id, u.email, u.display_name, u.avatar_url, u.status
    FROM starry_identities s
    JOIN users u ON u.id = s.local_user_id
    WHERE s.starry_user_id = ?
    LIMIT 1
  `).bind(member.id).first<User>();

  const emailOwner = await env.DB.prepare(`
    SELECT id, email, display_name, avatar_url, status
    FROM users
    WHERE lower(email) = lower(?)
    LIMIT 1
  `).bind(email).first<User>();

  if (mapped && emailOwner && mapped.id !== emailOwner.id) {
    throw new Error("local_identity_conflict");
  }

  let localUser = mapped || emailOwner;
  if (!localUser) {
    const localUserId = crypto.randomUUID();
    await env.DB.prepare(`
      INSERT INTO users (id, email, display_name, avatar_url, status, created_at, updated_at, last_login_at)
      VALUES (?, ?, ?, ?, 'active', datetime('now'), datetime('now'), datetime('now'))
    `).bind(
      localUserId,
      email,
      member.name || null,
      member.avatar || member.googleAvatar || null
    ).run();
    localUser = {
      id: localUserId,
      email,
      display_name: member.name || null,
      avatar_url: member.avatar || member.googleAvatar || null,
      status: "active"
    };
  }

  if (localUser.status !== "active") throw new Error("local_account_inactive");

  await env.DB.batch([
    env.DB.prepare(`
      INSERT INTO starry_identities (starry_user_id, local_user_id, linked_at)
      VALUES (?, ?, datetime('now'))
      ON CONFLICT(starry_user_id) DO UPDATE SET local_user_id = excluded.local_user_id
    `).bind(member.id, localUser.id),
    env.DB.prepare(`
      UPDATE users
      SET email = ?, display_name = ?, avatar_url = ?, updated_at = datetime('now'), last_login_at = datetime('now')
      WHERE id = ?
    `).bind(
      email,
      member.name || localUser.display_name || null,
      member.avatar || member.googleAvatar || localUser.avatar_url || null,
      localUser.id
    )
  ]);

  const synced = await env.DB.prepare(`
    SELECT id, email, display_name, avatar_url, status
    FROM users WHERE id = ? LIMIT 1
  `).bind(localUser.id).first<User>();
  if (!synced) throw new Error("local_user_sync_failed");
  return synced;
}

export async function finishStarryAuth(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const code = url.searchParams.get("code")?.trim() || "";
  if (!CODE_RE.test(code)) return Response.redirect(`${url.origin}/?starry=error`, 302);

  try {
    const centralUserId = await consumeCode(env, code);
    if (!centralUserId) return Response.redirect(`${url.origin}/?starry=error`, 302);

    const member = await readCentralMember(env, centralUserId);
    if (!member || member.status !== "active" || member.membershipStatus !== "active") {
      return Response.redirect(`${url.origin}/?starry=error`, 302);
    }
    const access = await checkCentralAppEntitlement(env.STARRY_ID_DB,member.id,APP_ID);
    if (!access.allowed) return Response.redirect(`${url.origin}/?starry=denied`,302);

    const localUser = await resolveLocalUser(env, member);
    await ensureCentralPublicCard(env, member.id);
    const session = await createSession(env, localUser.id);
    return new Response(null, {
      status: 302,
      headers: {
        location: `${url.origin}/?starry=login`,
        "set-cookie": cookie("starry_session", session, SESSION_TTL_SECONDS),
        "cache-control": "no-store",
        "referrer-policy": "no-referrer"
      }
    });
  } catch (error) {
    console.error("Starry ID callback failed", error);
    return Response.redirect(`${url.origin}/?starry=unavailable`, 302);
  }
}
