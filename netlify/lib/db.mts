import { getDatabase } from "@netlify/database";

export interface Queryable {
  query(text: string, params?: unknown[]): Promise<{ rows: any[]; rowCount?: number | null }>;
}
export interface Client extends Queryable {
  release(): void;
}
export interface PoolLike extends Queryable {
  connect(): Promise<Client>;
}

let override: PoolLike | null = null;
let cached: PoolLike | null = null;

/** Usato solo dai test per puntare a un Postgres locale. */
export function setPool(p: PoolLike | null) {
  override = p;
}

export function pool(): PoolLike {
  if (override) return override;
  if (!cached) cached = getDatabase().pool as unknown as PoolLike;
  return cached;
}

export async function q(text: string, params: unknown[] = []) {
  return (await pool().query(text, params)).rows;
}

export async function tx<T>(fn: (c: Queryable) => Promise<T>): Promise<T> {
  const c = await pool().connect();
  try {
    await c.query("BEGIN");
    const r = await fn(c);
    await c.query("COMMIT");
    return r;
  } catch (e) {
    await c.query("ROLLBACK").catch(() => {});
    throw e;
  } finally {
    c.release();
  }
}
