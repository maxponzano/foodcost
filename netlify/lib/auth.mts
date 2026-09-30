import bcrypt from "bcryptjs";
import { SignJWT, jwtVerify } from "jose";
import { randomInt, timingSafeEqual } from "node:crypto";
import { q } from "./db.mts";

export const COOKIE = "fc_session";
const SESSION_DAYS = 7;
const WINDOW_MIN = 15;
const MAX_PER_EMAIL = 8;
const MAX_PER_IP = 40;

export class HttpError extends Error {
  status: number;
  code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export function env(name: string): string | undefined {
  const n = (globalThis as any).Netlify;
  const v = n?.env?.get ? n.env.get(name) : process.env[name];
  return v === "" ? undefined : v;
}

function secret() {
  const s = env("JWT_SECRET");
  if (!s || s.length < 32) throw new HttpError(500, "CONFIG", "Configurazione mancante sul server (JWT_SECRET).");
  return new TextEncoder().encode(s);
}

export const hashPassword = (pw: string) => bcrypt.hash(pw, 10);
export const checkPassword = (pw: string, hash: string) => bcrypt.compare(pw, hash);
// hash fittizio per rendere uguali i tempi di risposta quando l'email non esiste
const DUMMY_HASH = "$2b$10$xVbwClZMukoaMfpVzIgB7e89jrBtxfVih4Yi1pPd1CmK3RSZdaEce";
export const burnTime = (pw: string) => bcrypt.compare(pw, DUMMY_HASH).catch(() => false);

export function safeEqual(a: string, b: string) {
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

export function validPassword(pw: unknown): pw is string {
  return typeof pw === "string" && pw.length >= 10 && pw.length <= 200;
}

export function tempPassword() {
  const A = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789";
  let s = "";
  for (let i = 0; i < 12; i++) s += A[randomInt(A.length)];
  return s;
}

export async function signSession(userId: string, sv: number) {
  return new SignJWT({ sv })
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(userId)
    .setIssuedAt()
    .setExpirationTime(`${SESSION_DAYS}d`)
    .sign(secret());
}

export async function readSession(token: string): Promise<{ sub: string; sv: number } | null> {
  try {
    const { payload } = await jwtVerify(token, secret(), { algorithms: ["HS256"] });
    if (typeof payload.sub !== "string" || typeof payload.sv !== "number") return null;
    return { sub: payload.sub, sv: payload.sv };
  } catch (e) {
    if (e instanceof HttpError) throw e;
    return null;
  }
}

export function sessionCookie(token: string) {
  return `${COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_DAYS * 86400}`;
}
export function clearCookie() {
  return `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

export function getCookie(req: Request, name: string) {
  const h = req.headers.get("cookie") || "";
  for (const part of h.split(";")) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return null;
}

/* ---------- limitazione tentativi ---------- */
async function attempts(key: string) {
  const r = await q(
    `SELECT count FROM login_attempts WHERE key=$1 AND first_at > NOW() - make_interval(mins => $2)`,
    [key, WINDOW_MIN]
  );
  return r.length ? r[0].count : 0;
}
export async function checkRate(email: string, ip: string) {
  if ((await attempts("e:" + email)) >= MAX_PER_EMAIL || (ip && (await attempts("ip:" + ip)) >= MAX_PER_IP))
    throw new HttpError(429, "TOO_MANY", "Troppi tentativi. Riprova tra qualche minuto.");
}
export async function addAttempt(key: string, windowMin = WINDOW_MIN) {
  await q(
    `INSERT INTO login_attempts(key,count,first_at) VALUES ($1,1,NOW())
     ON CONFLICT (key) DO UPDATE SET
       count = CASE WHEN login_attempts.first_at > NOW() - make_interval(mins => $2) THEN login_attempts.count + 1 ELSE 1 END,
       first_at = CASE WHEN login_attempts.first_at > NOW() - make_interval(mins => $2) THEN login_attempts.first_at ELSE NOW() END`,
    [key, windowMin]
  );
}
export async function failedLogin(email: string, ip: string) {
  await addAttempt("e:" + email);
  if (ip) await addAttempt("ip:" + ip);
}
export async function resetAttempts(email: string) {
  await q(`DELETE FROM login_attempts WHERE key=$1`, ["e:" + email]);
}
/** Limite generico (es. registrazioni per IP): max n in windowMin minuti */
export async function limitKey(key: string, n: number, windowMin: number, msg: string) {
  const r = await q(
    `SELECT count FROM login_attempts WHERE key=$1 AND first_at > NOW() - make_interval(mins => $2)`,
    [key, windowMin]
  );
  if (r.length && r[0].count >= n) throw new HttpError(429, "TOO_MANY", msg);
  await addAttempt(key, windowMin);
}
