import { randomUUID } from "node:crypto";
import { q, tx, type Queryable } from "./db.mts";
import {
  HttpError, env, hashPassword, checkPassword, burnTime, safeEqual, validPassword, tempPassword,
  signSession, readSession, sessionCookie, clearCookie, getCookie, COOKIE,
  checkRate, failedLogin, resetAttempts, limitKey,
} from "./auth.mts";
import { DEFAULT_LISTS, demoData } from "./seed.mts";

/* =====================================================================
   Tipi e utilità
   ===================================================================== */
type User = { id: string; email: string; role: "super_admin" | "client_admin" | "viewer"; status: string; must_change_pw: boolean; session_ver: number };
type Scope = { tenant: any; canWrite: boolean; isSuper: boolean };

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const LIST_KINDS = ["reparti", "fornitori", "tipologie"];
const LIMIT_MSG_BASIC = "Hai raggiunto il limite del piano base. Contatta l'amministratore per ampliarlo.";
const LIMIT_MSG_OTHER = "Hai raggiunto il limite di ricette del tuo piano. Contatta l'amministratore per ampliarlo.";

const bad = (msg: string, code = "BAD_REQUEST") => new HttpError(400, code, msg);
const forbidden = (msg = "Non hai i permessi per questa operazione.", code = "FORBIDDEN") => new HttpError(403, code, msg);
const notFound = (msg = "Non trovato.") => new HttpError(404, "NOT_FOUND", msg);

function json(data: unknown, status = 200, headers: Record<string, string> = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers },
  });
}
const str = (v: unknown, max = 200) => (v == null ? "" : String(v)).trim().slice(0, max);
function numOrNull(v: unknown, min = 0, max = 1e9): number | null {
  if (v === "" || v == null) return null;
  const n = typeof v === "number" ? v : parseFloat(String(v).replace(",", "."));
  if (!isFinite(n)) return null;
  if (n < min || n > max) throw bad("Valore numerico fuori intervallo.");
  return n;
}
const N = (v: any) => (v == null ? "" : Number(v));
const uuidOrNull = (v: unknown) => (typeof v === "string" && UUID_RE.test(v) ? v : null);
function needUuid(v: unknown) {
  if (typeof v !== "string" || !UUID_RE.test(v)) throw notFound();
  return v;
}

/* =====================================================================
   Ingresso principale
   ===================================================================== */
export async function handle(req: Request, ip = ""): Promise<Response> {
  try {
    const url = new URL(req.url);
    const path = url.pathname.replace(/^\/api/, "").replace(/\/+$/, "") || "/";
    const m = req.method.toUpperCase();
    let body: any = {};
    if (m !== "GET" && m !== "HEAD") {
      // difesa CSRF: solo JSON e, se presente, Origin uguale al sito
      const origin = req.headers.get("origin");
      if (origin && origin !== url.origin) throw forbidden("Richiesta non consentita.");
      if (!(req.headers.get("content-type") || "").includes("application/json")) throw bad("Formato richiesta non valido.");
      const text = await req.text();
      if (text.length > 5_000_000) throw bad("Richiesta troppo grande.");
      try { body = text ? JSON.parse(text) : {}; } catch { throw bad("JSON non valido."); }
      if (!body || typeof body !== "object") body = {};
    }

    // --- rotte pubbliche ---
    if (path === "/public/tipi" && m === "GET") return json({ tipi: await globalTipi() });
    if (path === "/register" && m === "POST") return await register(body, ip);
    if (path === "/login" && m === "POST") return await login(body, ip);
    if (path === "/logout" && m === "POST") return json({ ok: true }, 200, { "set-cookie": clearCookie() });

    // --- da qui serve la sessione ---
    const user = await currentUser(req);
    if (path === "/me" && m === "GET") return json(await me(user));
    if (path === "/password" && m === "POST") return await changePassword(user, body);

    if (path.startsWith("/admin/")) {
      if (user.role !== "super_admin") throw forbidden("Area riservata all'amministratore.");
      return await admin(m, path.slice(6), body, url);
    }

    const scope = await resolveTenant(user, url.searchParams.get("tenant") || req.headers.get("x-tenant-id"));
    if (m !== "GET" && !scope.canWrite) throw forbidden("Accesso in sola lettura.", "READ_ONLY");
    return await tenantRoutes(m, path, body, scope);
  } catch (e: any) {
    if (e instanceof HttpError) return json({ error: e.code, message: e.message }, e.status);
    if (e?.code === "23505") return json({ error: "DUPLICATE", message: "Esiste già un elemento con questo nome." }, 409);
    console.error(e);
    return json({ error: "SERVER", message: "Errore del server. Riprova." }, 500);
  }
}

/* =====================================================================
   Sessione, registrazione, login
   ===================================================================== */
async function currentUser(req: Request): Promise<User> {
  const tok = getCookie(req, COOKIE);
  const s = tok ? await readSession(tok) : null;
  if (!s || !UUID_RE.test(s.sub)) throw new HttpError(401, "AUTH", "Accesso richiesto.");
  const r = await q(`SELECT id,email,role,status,must_change_pw,session_ver FROM users WHERE id=$1`, [s.sub]);
  const u = r[0] as User | undefined;
  if (!u || u.status !== "active" || u.session_ver !== s.sv) throw new HttpError(401, "AUTH", "Sessione scaduta. Accedi di nuovo.");
  return u;
}

async function globalTipi(): Promise<string[]> {
  const r = await q(`SELECT value FROM lists WHERE tenant_id IS NULL AND kind='tipiAttivita' ORDER BY value COLLATE "C"`);
  return r.map((x) => x.value).sort((a, b) => a.localeCompare(b, "it"));
}

async function register(b: any, ip: string) {
  const email = str(b.email, 254).toLowerCase();
  const ragione = str(b.ragione, 200);
  const tipo = str(b.tipo, 100);
  if (!EMAIL_RE.test(email)) throw bad("Inserisci un'email valida.");
  if (!validPassword(b.password)) throw bad("La password deve avere almeno 10 caratteri.");
  if (!ragione) throw bad("Inserisci la ragione sociale.");
  if (!(await globalTipi()).includes(tipo)) throw bad("Scegli il tipo di attività.");
  await limitKey("reg:" + (ip || "?"), 5, 60, "Troppe registrazioni da questa connessione. Riprova più tardi.");
  const hash = await hashPassword(b.password);
  await tx(async (c) => {
    const ex = await c.query(`SELECT 1 FROM users WHERE email=$1`, [email]);
    if (ex.rows.length) throw new HttpError(409, "EMAIL_TAKEN", "Questa email è già registrata. Se è la tua, accedi.");
    const u = await c.query(`INSERT INTO users(email,pw_hash,role,status) VALUES ($1,$2,'client_admin','pending') RETURNING id`, [email, hash]);
    const t = await c.query(`INSERT INTO tenants(ragione_sociale,tipo_attivita) VALUES ($1,$2) RETURNING id`, [ragione, tipo]);
    await c.query(`INSERT INTO memberships(user_id,tenant_id,role) VALUES ($1,$2,'client_admin')`, [u.rows[0].id, t.rows[0].id]);
    await insertDefaultLists(c, t.rows[0].id);
  });
  return json({ ok: true, message: "Registrazione inviata. Potrai accedere quando l'amministratore avrà approvato la tua attività." }, 201);
}

async function insertDefaultLists(c: Queryable, tenantId: string) {
  for (const kind of ["reparti", "tipologie"] as const)
    for (const v of DEFAULT_LISTS[kind])
      await c.query(`INSERT INTO lists(tenant_id,kind,value) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`, [tenantId, kind, v]);
}

async function login(b: any, ip: string) {
  const email = str(b.email, 254).toLowerCase();
  const pw = typeof b.password === "string" ? b.password.slice(0, 200) : "";
  const generic = new HttpError(401, "BAD_CREDENTIALS", "Credenziali non valide.");
  if (!email || !pw) throw generic;
  await checkRate(email, ip);

  let u = (await q(`SELECT * FROM users WHERE email=$1`, [email]))[0];
  if (!u) {
    u = await bootstrapSuperAdmin(email, pw);
    if (!u) { await burnTime(pw); await failedLogin(email, ip); throw generic; }
  } else if (!(await checkPassword(pw, u.pw_hash))) {
    await failedLogin(email, ip);
    throw generic;
  }
  // password giusta: da qui si possono dare messaggi specifici
  if (u.status === "disabled") throw forbidden("Account disattivato. Contatta l'amministratore.", "DISABLED");
  if (u.role === "client_admin") {
    const ts = await q(`SELECT t.status FROM memberships m JOIN tenants t ON t.id=m.tenant_id WHERE m.user_id=$1`, [u.id]);
    if (!ts.some((t) => t.status === "approved")) {
      if (u.status === "pending" || ts.some((t) => t.status === "pending"))
        throw forbidden("Account in attesa di approvazione. Riceverai l'accesso appena l'amministratore approva la tua attività.", "PENDING");
      throw forbidden("L'attività è sospesa. Contatta l'amministratore.", "SUSPENDED");
    }
  }
  if (u.status !== "active") throw forbidden("Account in attesa di approvazione.", "PENDING");
  await resetAttempts(email);
  const token = await signSession(u.id, u.session_ver);
  return json({ ok: true }, 200, { "set-cookie": sessionCookie(token) });
}

/** Il primo super amministratore si crea al primo accesso con SUPERADMIN_EMAIL e SUPERADMIN_PASSWORD. */
async function bootstrapSuperAdmin(email: string, pw: string) {
  const se = (env("SUPERADMIN_EMAIL") || "").trim().toLowerCase();
  const sp = env("SUPERADMIN_PASSWORD") || "";
  if (!se || !sp || email !== se || !validPassword(sp) || !safeEqual(pw, sp)) return null;
  const exists = await q(`SELECT 1 FROM users WHERE role='super_admin'`);
  if (exists.length) return null;
  const r = await q(
    `INSERT INTO users(email,pw_hash,role,status) VALUES ($1,$2,'super_admin','active') ON CONFLICT (email) DO NOTHING RETURNING *`,
    [email, await hashPassword(pw)]
  );
  return r[0] || null;
}

async function me(u: User) {
  let tenants: any[];
  if (u.role === "super_admin") {
    tenants = await q(`SELECT id, ragione_sociale, tipo_attivita, status FROM tenants ORDER BY lower(ragione_sociale)`);
    tenants = tenants.map((t) => ({ ...t, role: "admin" }));
  } else {
    tenants = await q(
      `SELECT t.id, t.ragione_sociale, t.tipo_attivita, t.status, m.role FROM memberships m JOIN tenants t ON t.id=m.tenant_id
       WHERE m.user_id=$1 AND t.status='approved' ORDER BY lower(t.ragione_sociale)`, [u.id]);
    tenants = tenants.map((t) => ({ ...t, role: t.role === "client_admin" ? "admin" : "viewer" }));
  }
  return {
    user: { id: u.id, email: u.email, role: u.role, mustChangePw: u.must_change_pw },
    tenants: tenants.map((t) => ({ id: t.id, ragione: t.ragione_sociale, tipo: t.tipo_attivita, status: t.status, role: t.role })),
  };
}

async function changePassword(u: User, b: any) {
  const row = (await q(`SELECT pw_hash FROM users WHERE id=$1`, [u.id]))[0];
  if (!(await checkPassword(String(b.old || ""), row.pw_hash))) throw bad("La password attuale non è corretta.", "BAD_PASSWORD");
  if (!validPassword(b.new)) throw bad("La nuova password deve avere almeno 10 caratteri.");
  const r = await q(
    `UPDATE users SET pw_hash=$2, must_change_pw=false, session_ver=session_ver+1 WHERE id=$1 RETURNING session_ver`,
    [u.id, await hashPassword(b.new)]
  );
  const token = await signSession(u.id, r[0].session_ver);
  return json({ ok: true }, 200, { "set-cookie": sessionCookie(token) });
}

/* =====================================================================
   Scelta del cliente: sempre verificata sul server
   ===================================================================== */
async function resolveTenant(u: User, requested: string | null): Promise<Scope> {
  if (requested && !UUID_RE.test(requested)) throw forbidden("Attività non accessibile.");
  if (u.role === "super_admin") {
    if (!requested) throw bad("Seleziona un cliente.", "NO_TENANT");
    const t = (await q(`SELECT * FROM tenants WHERE id=$1`, [requested]))[0];
    if (!t) throw notFound("Cliente non trovato.");
    return { tenant: t, canWrite: true, isSuper: true };
  }
  const rows = await q(
    `SELECT t.*, m.role AS m_role FROM memberships m JOIN tenants t ON t.id=m.tenant_id
     WHERE m.user_id=$1 AND t.status='approved'`, [u.id]);
  let t = requested ? rows.find((r) => r.id === requested) : rows.length === 1 ? rows[0] : null;
  if (!t) throw requested ? forbidden("Attività non accessibile.") : bad("Seleziona un'attività.", "NO_TENANT");
  // un viewer non scrive mai, anche se per errore avesse una membership diversa
  return { tenant: t, canWrite: u.role === "client_admin" && t.m_role === "client_admin", isSuper: false };
}

/* =====================================================================
   Rotte dei dati del cliente
   ===================================================================== */
async function tenantRoutes(m: string, path: string, b: any, s: Scope): Promise<Response> {
  const tid = s.tenant.id;
  const parts = path.split("/").filter(Boolean); // es. ["foods","<id>"]

  if (path === "/data" && m === "GET") return json(await tenantData(tid, s));

  if (path === "/tenant" && m === "PUT") {
    const ragione = str(b.ragione, 200);
    if (!ragione) throw bad("La ragione sociale non può essere vuota.");
    const iva = numOrNull(b.iva, 0, 100) ?? 10;
    const fc = numOrNull(b.fcTarget, 1, 100) ?? 30;
    await q(`UPDATE tenants SET ragione_sociale=$2, tipo_attivita=$3, iva=$4, fc_target=$5 WHERE id=$1`, [tid, ragione, str(b.tipo, 100), iva, fc]);
    return json({ ok: true });
  }

  if (path === "/tenant" && m === "PATCH") {
    // modo di inserimento delle vendite: mensile (M) o settimanale (W); lo decide solo il super admin
    if (!s.isSuper) throw forbidden("Solo l'amministratore può cambiare il modo di inserimento delle vendite.");
    const g = String(b.salesGrain || "");
    if (!["M", "W"].includes(g)) throw bad("Modo di inserimento non valido.");
    await q(`UPDATE tenants SET sales_grain=$2 WHERE id=$1`, [tid, g]);
    return json({ ok: true });
  }

  if (path === "/sales" && m === "PUT") {
    // vendite di un mese ("AAAA-MM") o di una settimana ISO ("AAAA-Wnn"): [{recipeId, qty}]; qty vuoto o 0 = cancella
    const per = parsePeriod(b.period);
    if (!per) throw bad("Periodo non valido.");
    const items = (Array.isArray(b.items) ? b.items : []).slice(0, 2000);
    const ids = [...new Set(items.map((x: any) => uuidOrNull(x?.recipeId)).filter(Boolean))];
    if (items.some((x: any) => !uuidOrNull(x?.recipeId))) throw bad("Piatto non valido.");
    if (ids.length) {
      const ok = await q(`SELECT count(*) AS n FROM recipes WHERE tenant_id=$1 AND id = ANY($2::uuid[])`, [tid, ids]);
      if (Number(ok[0].n) !== ids.length) throw forbidden("Piatto non accessibile.");
    }
    await tx(async (c) => {
      for (const it of items) await putSale(c, tid, it.recipeId, per, numOrNull(it.qty, 0, 1e7));
    });
    return json({ ok: true, saved: items.length });
  }

  if (path === "/sales/import" && m === "POST") {
    // importazione di una settimana o di un mese dall'export della cassa (solo super admin):
    // rows = [{name, recipeId|null, qty, ignore}]; sostituisce le vendite della settimana e ricorda gli abbinamenti
    // (ignore = scelta esplicita "non è un piatto"; senza ricetta e senza ignore la voce resta "da assegnare")
    if (!s.isSuper) throw forbidden("Solo l'amministratore può importare le vendite dalla cassa.");
    const per = parsePeriod(b.period);
    if (!per) throw bad("Periodo non valido.");
    const rows = (Array.isArray(b.rows) ? b.rows : []).slice(0, 3000).map((x: any) => ({
      name: str(x?.name, 150).toLowerCase(), recipeId: x?.recipeId ? uuidOrNull(x.recipeId) : null, qty: numOrNull(x?.qty, 0, 1e7) || 0, ignore: x?.ignore === true, bad: x?.recipeId && !uuidOrNull(x.recipeId),
    })).filter((x: any) => x.name);
    if (rows.some((x: any) => x.bad)) throw bad("Piatto non valido.");
    const ids = [...new Set(rows.map((x: any) => x.recipeId).filter(Boolean))];
    if (ids.length) {
      const ok = await q(`SELECT count(*) AS n FROM recipes WHERE tenant_id=$1 AND id = ANY($2::uuid[])`, [tid, ids]);
      if (Number(ok[0].n) !== ids.length) throw forbidden("Piatto non accessibile.");
    }
    const tot = new Map<string, number>();
    for (const x of rows) if (x.recipeId && x.qty) tot.set(x.recipeId, (tot.get(x.recipeId) || 0) + x.qty);
    await tx(async (c) => {
      await c.query(`DELETE FROM sales WHERE tenant_id=$1 AND grain=$2 AND period=$3::date`, [tid, per.grain, per.date]);
      for (const [rid, qty] of tot) await putSale(c, tid, rid, per, qty, "cassa");
      for (const x of rows) {
        if (x.recipeId || x.ignore)
          await c.query(`INSERT INTO sales_aliases(tenant_id,cash_name,recipe_id) VALUES ($1,$2,$3)
            ON CONFLICT (tenant_id,cash_name) DO UPDATE SET recipe_id=EXCLUDED.recipe_id`, [tid, x.name, x.recipeId]);
        else await c.query(`DELETE FROM sales_aliases WHERE tenant_id=$1 AND cash_name=$2`, [tid, x.name]);
      }
      await c.query(`UPDATE tenants SET sales_grain=$2 WHERE id=$1`, [tid, per.grain]);
    });
    return json({ ok: true, recipes: tot.size, qty: [...tot.values()].reduce((a, v) => a + v, 0) });
  }

  if (path === "/sales/reset" && m === "POST") {
    // azzera le vendite: di un solo periodo oppure tutte (scope "all")
    if (b.scope === "all") {
      const r = await q(`DELETE FROM sales WHERE tenant_id=$1 RETURNING 1`, [tid]);
      return json({ ok: true, deleted: r.length });
    }
    const per = parsePeriod(b.period);
    if (!per) throw bad("Periodo non valido.");
    const r = await q(`DELETE FROM sales WHERE tenant_id=$1 AND grain=$2 AND period=$3::date RETURNING 1`, [tid, per.grain, per.date]);
    return json({ ok: true, deleted: r.length });
  }

  if (path === "/lists" && (m === "POST" || m === "DELETE")) {
    const kind = String(b.kind || "");
    const value = str(b.value, 100);
    if (!LIST_KINDS.includes(kind) || !value) throw bad("Elenco non valido.");
    if (m === "POST") await q(`INSERT INTO lists(tenant_id,kind,value) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`, [tid, kind, value]);
    else await q(`DELETE FROM lists WHERE tenant_id=$1 AND kind=$2 AND value=$3`, [tid, kind, value]);
    return json({ ok: true });
  }

  if (parts[0] === "foods") {
    if (m === "PATCH" && parts.length === 1) {
      // cambio massivo del prezzo da usare (minimo/medio/massimo/ultimo), solo sugli alimenti di questo cliente
      const mode = String(b.mode || "");
      if (!["min", "avg", "max", "last"].includes(mode)) throw bad("Prezzo da usare non valido.");
      const ids = [...new Set((Array.isArray(b.ids) ? b.ids : []).filter((x: unknown) => uuidOrNull(x)))].slice(0, 5000);
      if (!ids.length) throw bad("Nessun alimento selezionato.");
      const r = await q(`UPDATE foods SET price_mode=$1 WHERE tenant_id=$2 AND id = ANY($3::uuid[]) RETURNING id`, [mode, tid, ids]);
      return json({ ok: true, updated: r.length });
    }
    if (m === "POST" && parts.length === 1) {
      if (!s.isSuper && !s.tenant.can_add_foods)
        throw forbidden("La creazione di alimenti non è abilitata per la tua attività. Contatta l'amministratore.", "FOODS_DISABLED");
      const id = await tx((c) => saveFood(c, tid, null, b));
      return json({ ok: true, id }, 201);
    }
    if (parts.length === 2) {
      const id = needUuid(parts[1]);
      const own = await q(`SELECT 1 FROM foods WHERE id=$1 AND tenant_id=$2`, [id, tid]);
      if (!own.length) throw notFound("Alimento non trovato.");
      if (m === "PUT") { await tx((c) => saveFood(c, tid, id, b)); return json({ ok: true, id }); }
      if (m === "DELETE") { await q(`DELETE FROM foods WHERE id=$1 AND tenant_id=$2`, [id, tid]); return json({ ok: true }); }
    }
  }

  if (parts[0] === "recipes") {
    if (m === "POST" && parts.length === 1) {
      const id = await tx(async (c) => {
        // blocco la riga del cliente: due creazioni in parallelo non superano il limite
        const t = (await c.query(`SELECT * FROM tenants WHERE id=$1 FOR UPDATE`, [tid])).rows[0];
        if (!s.isSuper) {
          if (!t.can_add_recipes)
            throw forbidden("La creazione di ricette non è abilitata per la tua attività. Contatta l'amministratore.", "RECIPES_DISABLED");
          if (t.max_recipes != null) {
            const n = Number((await c.query(`SELECT count(*) AS n FROM recipes WHERE tenant_id=$1`, [tid])).rows[0].n);
            if (n >= t.max_recipes) throw forbidden(t.plan === "basic" ? LIMIT_MSG_BASIC : LIMIT_MSG_OTHER, "LIMIT_REACHED");
          }
        }
        return saveRecipe(c, tid, null, b);
      });
      return json({ ok: true, id }, 201);
    }
    if (parts.length === 2) {
      const id = needUuid(parts[1]);
      const own = await q(`SELECT 1 FROM recipes WHERE id=$1 AND tenant_id=$2`, [id, tid]);
      if (!own.length) throw notFound("Ricetta non trovata.");
      if (m === "PUT") { await tx((c) => saveRecipe(c, tid, id, b)); return json({ ok: true, id }); }
      if (m === "PATCH") {
        // campi rapidi da Marginalità e Menu engineering
        const sets: string[] = [], vals: unknown[] = [id, tid];
        const map: Record<string, [string, number]> = { price: ["price", 1e6], sold: ["sold", 1e9], time: ["prep_time", 1e5] };
        for (const k of Object.keys(map)) if (k in b) { vals.push(numOrNull(b[k], 0, map[k][1])); sets.push(`${map[k][0]}=$${vals.length}`); }
        if (typeof b.inAvg === "boolean") { vals.push(b.inAvg); sets.push(`in_avg=$${vals.length}`); }
        if (typeof b.checkNote === "string") { vals.push(str(b.checkNote, 500)); sets.push(`check_note=$${vals.length}`); }
        if (sets.length) await q(`UPDATE recipes SET ${sets.join(",")} WHERE id=$1 AND tenant_id=$2`, vals);
        return json({ ok: true });
      }
      if (m === "DELETE") { await q(`DELETE FROM recipes WHERE id=$1 AND tenant_id=$2`, [id, tid]); return json({ ok: true }); }
    }
  }
  throw notFound("Operazione non trovata.");
}

async function saveFood(c: Queryable, tid: string, id: string | null, b: any): Promise<string> {
  const name = str(b.name, 150);
  if (!name) throw bad("Inserisci la descrizione del prodotto.");
  const unit = ["kg", "lt", "pz", "conf"].includes(b.unit) ? b.unit : "kg";
  const packUnit = ["g", "ml", "pz"].includes(b.packUnit) ? b.packUnit : "g";
  const mode = ["min", "avg", "max", "last"].includes(b.mode) ? b.mode : "max";
  const supplier = str(b.supplier, 150);
  const dup = await c.query(`SELECT 1 FROM foods WHERE tenant_id=$1 AND lower(name)=lower($2) AND id IS DISTINCT FROM $3`, [tid, name, id]);
  if (dup.rows.length) throw new HttpError(409, "DUPLICATE", "Esiste già un alimento con questo nome.");
  const vals = [tid, name, str(b.category, 100), supplier, unit, numOrNull(b.packQty, 0, 1e7), packUnit, mode];
  if (id) await c.query(`UPDATE foods SET name=$2,category=$3,supplier=$4,unit=$5,pack_qty=$6,pack_unit=$7,price_mode=$8 WHERE id=$9 AND tenant_id=$1`, [...vals, id]);
  else id = (await c.query(`INSERT INTO foods(tenant_id,name,category,supplier,unit,pack_qty,pack_unit,price_mode) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`, vals)).rows[0].id;
  await c.query(`DELETE FROM food_prices WHERE food_id=$1`, [id]);
  const hist = Array.isArray(b.history) ? b.history.slice(0, 1000) : [];
  for (const h of hist) {
    const p = numOrNull(h?.price, 0, 1e6);
    const d = /^\d{4}-\d{2}-\d{2}$/.test(String(h?.date)) ? h.date : null;
    if (p && p > 0 && d) await c.query(`INSERT INTO food_prices(food_id,date,price) VALUES ($1,$2,$3)`, [id, d, p]);
  }
  if (supplier) await c.query(`INSERT INTO lists(tenant_id,kind,value) VALUES ($1,'fornitori',$2) ON CONFLICT DO NOTHING`, [tid, supplier]);
  return id!;
}

async function saveRecipe(c: Queryable, tid: string, id: string | null, b: any): Promise<string> {
  const name = str(b.name, 150);
  if (!name) throw bad("Inserisci il nome del piatto.");
  const isNew = !id;
  const rid = id || randomUUID();
  const rows = (Array.isArray(b.rows) ? b.rows : []).slice(0, 300).filter((r: any) => r && (r.foodId || r.subId || str(r.name)));

  // ogni alimento o sotto-ricetta citata deve appartenere allo STESSO cliente
  const foodIds = [...new Set(rows.map((r: any) => uuidOrNull(r.foodId)).filter(Boolean))];
  const subIds = [...new Set(rows.map((r: any) => uuidOrNull(r.subId)).filter(Boolean))];
  if (rows.some((r: any) => (r.foodId && !uuidOrNull(r.foodId)) || (r.subId && !uuidOrNull(r.subId)))) throw bad("Ingrediente non valido.");
  if (foodIds.length) {
    const ok = await c.query(`SELECT count(*) AS n FROM foods WHERE tenant_id=$1 AND id = ANY($2::uuid[])`, [tid, foodIds]);
    if (Number(ok.rows[0].n) !== foodIds.length) throw forbidden("Ingrediente non accessibile.");
  }
  if (subIds.length) {
    if (subIds.includes(rid)) throw bad("Una ricetta non può contenere se stessa.", "CYCLE");
    const ok = await c.query(`SELECT count(*) AS n FROM recipes WHERE tenant_id=$1 AND id = ANY($2::uuid[])`, [tid, subIds]);
    if (Number(ok.rows[0].n) !== subIds.length) throw forbidden("Ricetta ingrediente non accessibile.");
    if (!isNew) await checkCycle(c, tid, rid, subIds as string[]);
  }

  const vals = [tid, name, str(b.type, 100), numOrNull(b.portions, 0, 1e5) || 1, numOrNull(b.yieldG, 0, 1e8),
    numOrNull(b.price, 0, 1e6), numOrNull(b.sold, 0, 1e9), numOrNull(b.time, 0, 1e5), rid, b.inAvg !== false, str(b.checkNote, 500)];
  if (isNew) await c.query(`INSERT INTO recipes(tenant_id,name,type,portions,yield_g,price,sold,prep_time,id,in_avg,check_note) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, vals);
  else await c.query(`UPDATE recipes SET name=$2,type=$3,portions=$4,yield_g=$5,price=$6,sold=$7,prep_time=$8,in_avg=$10,check_note=$11 WHERE id=$9 AND tenant_id=$1`, vals);

  await c.query(`DELETE FROM recipe_rows WHERE recipe_id=$1`, [rid]);
  let pos = 0;
  for (const r of rows) {
    const sub = uuidOrNull(r.subId);
    await c.query(
      `INSERT INTO recipe_rows(recipe_id,food_id,sub_recipe_id,label,qty,waste_pct,position) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [rid, sub ? null : uuidOrNull(r.foodId), sub, str(r.name, 150), numOrNull(r.qty, 0, 1e7), numOrNull(r.waste, 0, 99.9), pos++]
    );
  }
  return rid;
}

/** Impedisce cicli (A dentro B dentro A) tra ricette usate come ingredienti. */
async function checkCycle(c: Queryable, tid: string, rid: string, subIds: string[]) {
  const edges = await c.query(
    `SELECT rr.recipe_id, rr.sub_recipe_id FROM recipe_rows rr JOIN recipes r ON r.id=rr.recipe_id
     WHERE r.tenant_id=$1 AND rr.sub_recipe_id IS NOT NULL AND rr.recipe_id<>$2`, [tid, rid]);
  const g = new Map<string, string[]>();
  for (const e of edges.rows) g.set(e.recipe_id, [...(g.get(e.recipe_id) || []), e.sub_recipe_id]);
  const seen = new Set<string>();
  const stack = [...subIds];
  while (stack.length) {
    const x = stack.pop()!;
    if (x === rid) throw bad("Questa ricetta è già usata dentro una delle ricette che stai aggiungendo: si creerebbe un ciclo.", "CYCLE");
    if (seen.has(x)) continue;
    seen.add(x);
    stack.push(...(g.get(x) || []));
  }
}

/* =====================================================================
   Periodi delle vendite: mese "AAAA-MM" oppure settimana ISO "AAAA-Wnn"
   (lunedì-domenica; la settimana 1 è quella con il primo giovedì dell'anno)
   ===================================================================== */
const DAY = 86400000;
export function isoWeeks(y: number) {
  const p = (x: number) => (x + Math.floor(x / 4) - Math.floor(x / 100) + Math.floor(x / 400)) % 7;
  return p(y) === 4 || p(y - 1) === 3 ? 53 : 52;
}
export function isoMonday(y: number, w: number) {
  const jan4 = Date.UTC(y, 0, 4);
  const dow = (new Date(jan4).getUTCDay() + 6) % 7;
  return new Date(jan4 - dow * DAY + (w - 1) * 7 * DAY).toISOString().slice(0, 10);
}
type Period = { grain: "M" | "W"; date: string };
export function parsePeriod(v: unknown): Period | null {
  const s = String(v ?? "");
  let x = /^(\d{4})-(0[1-9]|1[0-2])$/.exec(s);
  if (x) return { grain: "M", date: s + "-01" };
  x = /^(\d{4})-W(\d{2})$/.exec(s);
  if (x) {
    const y = +x[1], w = +x[2];
    if (y < 2000 || y > 2100 || w < 1 || w > isoWeeks(y)) return null;
    return { grain: "W", date: isoMonday(y, w) };
  }
  return null;
}
async function putSale(c: Queryable, tid: string, rid: string, per: Period, qty: number | null, source = "manuale") {
  if (!qty) await c.query(`DELETE FROM sales WHERE recipe_id=$1 AND grain=$2 AND period=$3::date AND tenant_id=$4`, [rid, per.grain, per.date, tid]);
  else await c.query(
    `INSERT INTO sales(tenant_id,recipe_id,grain,period,qty,source) VALUES ($1,$2,$3,$4::date,$5,$6)
     ON CONFLICT (recipe_id,grain,period) DO UPDATE SET qty=EXCLUDED.qty, source=EXCLUDED.source`, [tid, rid, per.grain, per.date, qty, source]);
}

/* =====================================================================
   Lettura completa dei dati di un cliente (formato usato dall'app)
   ===================================================================== */
async function tenantData(tid: string, s: Scope | null) {
  const t = (await q(`SELECT * FROM tenants WHERE id=$1`, [tid]))[0];
  const lists = await q(`SELECT kind, value FROM lists WHERE tenant_id=$1`, [tid]);
  const foods = await q(`SELECT * FROM foods WHERE tenant_id=$1 ORDER BY lower(name)`, [tid]);
  const prices = await q(
    `SELECT p.id, p.food_id, to_char(p.date,'YYYY-MM-DD') AS date, p.price FROM food_prices p JOIN foods f ON f.id=p.food_id
     WHERE f.tenant_id=$1 ORDER BY p.date, p.id`, [tid]);
  const recipes = await q(`SELECT * FROM recipes WHERE tenant_id=$1 ORDER BY lower(name)`, [tid]);
  const rows = await q(
    `SELECT rr.* FROM recipe_rows rr JOIN recipes r ON r.id=rr.recipe_id WHERE r.tenant_id=$1 ORDER BY rr.recipe_id, rr.position`, [tid]);
  const salesRows = await q(
    `SELECT recipe_id, CASE WHEN grain='W' THEN to_char(period,'IYYY-"W"IW') ELSE to_char(period,'YYYY-MM') END AS m, qty FROM sales WHERE tenant_id=$1`, [tid]);
  const sales: Record<string, Record<string, number>> = {};
  for (const x of salesRows) (sales[x.recipe_id] ||= {})[x.m] = Number(x.qty);

  const salesAliases: Record<string, string> = {};
  if (!s || s.isSuper) for (const a of await q(`SELECT cash_name, recipe_id FROM sales_aliases WHERE tenant_id=$1`, [tid])) salesAliases[a.cash_name] = a.recipe_id || "";

  const L: Record<string, string[]> = { reparti: [], fornitori: [], tipologie: [] };
  for (const l of lists) if (L[l.kind]) L[l.kind].push(l.value);
  // l'ordine delle tipologie conta (raggruppamenti): rispetto quello predefinito, poi alfabetico
  const order = (arr: string[], def: string[]) =>
    arr.sort((a, b) => { const i = def.indexOf(a), j = def.indexOf(b); return i >= 0 && j >= 0 ? i - j : i >= 0 ? -1 : j >= 0 ? 1 : a.localeCompare(b, "it"); });
  order(L.tipologie, DEFAULT_LISTS.tipologie);
  L.reparti.sort((a, b) => a.localeCompare(b, "it"));
  L.fornitori.sort((a, b) => a.localeCompare(b, "it"));

  const ph = new Map<string, any[]>();
  for (const p of prices) ph.set(p.food_id, [...(ph.get(p.food_id) || []), { id: String(p.id), date: p.date, price: Number(p.price) }]);
  const rr = new Map<string, any[]>();
  for (const r of rows) rr.set(r.recipe_id, [...(rr.get(r.recipe_id) || []),
    { foodId: r.food_id || "", subId: r.sub_recipe_id || "", name: r.label, qty: N(r.qty), waste: N(r.waste_pct) }]);

  return {
    tenant: {
      id: t.id, ragione: t.ragione_sociale, tipo: t.tipo_attivita, status: t.status, plan: t.plan,
      maxRecipes: t.max_recipes, canAddFoods: t.can_add_foods, canAddRecipes: t.can_add_recipes,
    },
    canWrite: s ? s.canWrite : true,
    isSuper: s ? s.isSuper : true,
    iva: Number(t.iva), fcTarget: Number(t.fc_target), salesGrain: t.sales_grain === "W" ? "W" : "M",
    recipeCount: recipes.length,
    sales,
    ...(s && !s.isSuper ? {} : { salesAliases }),
    lists: { ...L, tipiAttivita: await globalTipi() },
    foods: foods.map((f) => ({
      id: f.id, name: f.name, category: f.category, supplier: f.supplier, unit: f.unit, mode: f.price_mode,
      packQty: N(f.pack_qty), packUnit: f.pack_unit, history: ph.get(f.id) || [],
    })),
    recipes: recipes.map((r) => ({
      id: r.id, name: r.name, type: r.type, portions: N(r.portions), yieldG: N(r.yield_g),
      price: N(r.price), sold: N(r.sold), time: N(r.prep_time), inAvg: r.in_avg !== false, checkNote: r.check_note || '', rows: rr.get(r.id) || [],
    })),
  };
}

/* =====================================================================
   Importazione (backup dell'app, anche quelli vecchi del localStorage)
   ===================================================================== */
async function importInto(c: Queryable, tid: string, d: any) {
  if (!d || !Array.isArray(d.foods) || !Array.isArray(d.recipes)) throw bad("Backup non valido.");
  await c.query(`DELETE FROM recipes WHERE tenant_id=$1`, [tid]);
  await c.query(`DELETE FROM foods WHERE tenant_id=$1`, [tid]);
  await c.query(`DELETE FROM lists WHERE tenant_id=$1`, [tid]);
  const lists = d.lists || {};
  for (const k of LIST_KINDS) {
    const arr: string[] = Array.isArray(lists[k]) ? lists[k] : (DEFAULT_LISTS as any)[k] || [];
    for (const v of arr) if (str(v)) await c.query(`INSERT INTO lists(tenant_id,kind,value) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`, [tid, k, str(v, 100)]);
  }
  const t = d.tenant || {};
  await c.query(`UPDATE tenants SET iva=$2, fc_target=$3, ragione_sociale=COALESCE(NULLIF($4,''),ragione_sociale), tipo_attivita=COALESCE(NULLIF($5,''),tipo_attivita) WHERE id=$1`,
    [tid, numOrNull(d.iva, 0, 100) ?? 10, numOrNull(d.fcTarget, 1, 100) ?? 30, str(t.ragione, 200), str(t.tipo, 100)]);

  const fmap = new Map<string, string>();
  const seen = new Set<string>();
  for (const f of d.foods) {
    const key = str(f?.name, 150).toLowerCase();
    if (!key || seen.has(key)) continue;
    seen.add(key);
    fmap.set(String(f.id), await saveFood(c, tid, null, f));
  }
  // prima creo tutte le ricette senza righe, poi inserisco le righe con gli id nuovi
  const rmap = new Map<string, string>();
  for (const r of d.recipes) {
    if (!str(r?.name)) continue;
    rmap.set(String(r.id), await saveRecipe(c, tid, null, { ...r, rows: [] }));
  }
  for (const r of d.recipes) {
    const nid = rmap.get(String(r?.id));
    if (!nid) continue;
    const rows = (Array.isArray(r.rows) ? r.rows : []).map((x: any) => ({
      ...x, foodId: fmap.get(String(x.foodId)) || "", subId: rmap.get(String(x.subId)) || "",
    }));
    await saveRecipe(c, tid, nid, { ...r, rows });
  }
  if (d.salesAliases && typeof d.salesAliases === "object")
    for (const [k, v] of Object.entries(d.salesAliases).slice(0, 3000)) {
      const name = str(k, 150).toLowerCase(), rid = v ? rmap.get(String(v)) : null;
      if (name && (rid || !v)) await c.query(`INSERT INTO sales_aliases(tenant_id,cash_name,recipe_id) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`, [tid, name, rid || null]);
    }
  if (d.salesGrain === "W" || d.salesGrain === "M") await c.query(`UPDATE tenants SET sales_grain=$2 WHERE id=$1`, [tid, d.salesGrain]);
  // vendite: formato nuovo {idRicetta: {"AAAA-MM" o "AAAA-Wnn": qty}}; altrimenti il vecchio campo "sold" nel mese soldPeriod (o il mese corrente)
  const fallback = /^\d{4}-\d{2}$/.test(String(d.soldPeriod || "")) ? d.soldPeriod : new Date().toISOString().slice(0, 7);
  for (const r of d.recipes) {
    const nid = rmap.get(String(r?.id));
    if (!nid) continue;
    const per: Record<string, unknown> = (d.sales && typeof d.sales === "object" && d.sales[String(r.id)]) || (numOrNull(r.sold, 0, 1e9) ? { [fallback]: r.sold } : {});
    for (const [mm, v] of Object.entries(per)) {
      const qty = numOrNull(v, 0, 1e7), per = parsePeriod(mm);
      if (qty && per) await putSale(c, tid, nid, per, qty, "import");
    }
  }
}

/* =====================================================================
   Area super amministratore
   ===================================================================== */
async function admin(m: string, path: string, b: any, url: URL): Promise<Response> {
  const parts = path.split("/").filter(Boolean);

  if (path === "/tenants" && m === "GET") {
    const ts = await q(`
      SELECT t.*, (SELECT count(*) FROM recipes r WHERE r.tenant_id=t.id) AS recipe_count,
                  (SELECT count(*) FROM foods f WHERE f.tenant_id=t.id) AS food_count
      FROM tenants t ORDER BY (t.status='pending') DESC, lower(t.ragione_sociale)`);
    const mem = await q(`SELECT m.tenant_id, m.role, u.id, u.email, u.full_name, u.status FROM memberships m JOIN users u ON u.id=m.user_id ORDER BY u.email`);
    return json({
      tenants: ts.map((t) => ({
        id: t.id, ragione: t.ragione_sociale, tipo: t.tipo_attivita, status: t.status, plan: t.plan,
        maxRecipes: t.max_recipes, canAddFoods: t.can_add_foods, canAddRecipes: t.can_add_recipes, salesGrain: t.sales_grain === "W" ? "W" : "M",
        recipeCount: Number(t.recipe_count), foodCount: Number(t.food_count), createdAt: t.created_at,
        admins: mem.filter((x) => x.tenant_id === t.id && x.role === "client_admin").map((x) => ({ id: x.id, email: x.email, name: x.full_name, status: x.status })),
        viewers: mem.filter((x) => x.tenant_id === t.id && x.role === "viewer").map((x) => ({ id: x.id, email: x.email, status: x.status })),
      })),
    });
  }

  if (path === "/tenants" && m === "POST") {
    // creazione diretta di un cliente da parte di Max (già approvato); email facoltativa
    const ragione = str(b.ragione, 200);
    if (!ragione) throw bad("Inserisci la ragione sociale.");
    const email = str(b.email, 254).toLowerCase();
    if (email && !EMAIL_RE.test(email)) throw bad("Email non valida.");
    const pw = email ? tempPassword() : null;
    const hash = pw ? await hashPassword(pw) : null;
    const id = await tx(async (c) => {
      const t = await c.query(`INSERT INTO tenants(ragione_sociale,tipo_attivita,status) VALUES ($1,$2,'approved') RETURNING id`, [ragione, str(b.tipo, 100)]);
      const tid = t.rows[0].id;
      await insertDefaultLists(c, tid);
      if (email) {
        const ex = await c.query(`SELECT 1 FROM users WHERE email=$1`, [email]);
        if (ex.rows.length) throw new HttpError(409, "EMAIL_TAKEN", "Questa email è già registrata.");
        const u = await c.query(`INSERT INTO users(email,pw_hash,role,status,must_change_pw) VALUES ($1,$2,'client_admin','active',true) RETURNING id`, [email, hash]);
        await c.query(`INSERT INTO memberships(user_id,tenant_id,role) VALUES ($1,$2,'client_admin')`, [u.rows[0].id, tid]);
      }
      if (b.demo) await importInto(c, tid, demoData());
      return tid;
    });
    return json({ ok: true, id, tempPassword: pw }, 201);
  }

  if (parts[0] === "tenants" && parts.length === 3 && parts[2] === "admins" && m === "POST") {
    // aggiunge una persona autorizzata a lavorare sui dati di un cliente già esistente
    const tid = needUuid(parts[1]);
    if (!(await q(`SELECT 1 FROM tenants WHERE id=$1`, [tid])).length) throw notFound("Cliente non trovato.");
    const email = str(b.email, 254).toLowerCase(), name = str(b.name, 120);
    if (!EMAIL_RE.test(email)) throw bad("Inserisci un'email valida.");
    const pw = tempPassword(), hash = await hashPassword(pw);
    const id = await tx(async (c) => {
      const ex = await c.query(`SELECT 1 FROM users WHERE email=$1`, [email]);
      if (ex.rows.length) throw new HttpError(409, "EMAIL_TAKEN", "Questa email è già registrata.");
      const u = await c.query(`INSERT INTO users(email,full_name,pw_hash,role,status,must_change_pw) VALUES ($1,$2,$3,'client_admin','active',true) RETURNING id`, [email, name, hash]);
      await c.query(`INSERT INTO memberships(user_id,tenant_id,role) VALUES ($1,$2,'client_admin')`, [u.rows[0].id, tid]);
      return u.rows[0].id;
    });
    return json({ ok: true, id, tempPassword: pw }, 201);
  }

  if (parts[0] === "tenants" && parts.length === 2) {
    const id = needUuid(parts[1]);
    const t = (await q(`SELECT * FROM tenants WHERE id=$1`, [id]))[0];
    if (!t) throw notFound("Cliente non trovato.");
    if (m === "PUT") {
      const status = ["pending", "approved", "suspended"].includes(b.status) ? b.status : t.status;
      const plan = ["basic", "pro"].includes(b.plan) ? b.plan : t.plan;
      let max = t.max_recipes;
      if ("maxRecipes" in b) {
        max = b.maxRecipes === null || b.maxRecipes === "" ? null : numOrNull(b.maxRecipes, 0, 100000);
        if (max != null) max = Math.floor(max);
      }
      const canF = typeof b.canAddFoods === "boolean" ? b.canAddFoods : t.can_add_foods;
      const canR = typeof b.canAddRecipes === "boolean" ? b.canAddRecipes : t.can_add_recipes;
      const ragione = str(b.ragione, 200) || t.ragione_sociale;
      const tipo = "tipo" in b ? str(b.tipo, 100) : t.tipo_attivita;
      const grain = ["M", "W"].includes(b.salesGrain) ? b.salesGrain : t.sales_grain;
      await tx(async (c) => {
        await c.query(`UPDATE tenants SET status=$2,plan=$3,max_recipes=$4,can_add_foods=$5,can_add_recipes=$6,ragione_sociale=$7,tipo_attivita=$8,sales_grain=$9 WHERE id=$1`,
          [id, status, plan, max, canF, canR, ragione, tipo, grain]);
        if (status === "approved")
          await c.query(`UPDATE users SET status='active' WHERE status='pending' AND id IN (SELECT user_id FROM memberships WHERE tenant_id=$1)`, [id]);
      });
      return json({ ok: true });
    }
    if (m === "DELETE") {
      // rifiuta/elimina: cancella l'attività e gli utenti che appartenevano solo a lei (non i viewer condivisi)
      await tx(async (c) => {
        const only = await c.query(
          `SELECT m.user_id FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.tenant_id=$1 AND u.role='client_admin'
           AND NOT EXISTS (SELECT 1 FROM memberships m2 WHERE m2.user_id=m.user_id AND m2.tenant_id<>$1)`, [id]);
        await c.query(`DELETE FROM tenants WHERE id=$1`, [id]);
        for (const r of only.rows) await c.query(`DELETE FROM users WHERE id=$1`, [r.user_id]);
      });
      return json({ ok: true });
    }
  }

  if (path === "/users" && m === "GET") {
    const us = await q(`SELECT id,email,full_name,role,status,must_change_pw,created_at FROM users WHERE role<>'super_admin' ORDER BY email`);
    const mem = await q(`SELECT user_id, tenant_id, role FROM memberships`);
    return json({
      users: us.map((u) => ({
        id: u.id, email: u.email, name: u.full_name, role: u.role, status: u.status, mustChangePw: u.must_change_pw,
        tenantIds: mem.filter((x) => x.user_id === u.id).map((x) => x.tenant_id),
      })),
    });
  }

  if (path === "/viewers" && m === "POST") {
    const email = str(b.email, 254).toLowerCase();
    if (!EMAIL_RE.test(email)) throw bad("Inserisci un'email valida.");
    const tids = await validTenantIds(b.tenantIds);
    const pw = tempPassword();
    const hash = await hashPassword(pw);
    const id = await tx(async (c) => {
      const ex = await c.query(`SELECT 1 FROM users WHERE email=$1`, [email]);
      if (ex.rows.length) throw new HttpError(409, "EMAIL_TAKEN", "Questa email è già registrata.");
      const u = await c.query(`INSERT INTO users(email,pw_hash,role,status,must_change_pw) VALUES ($1,$2,'viewer','active',true) RETURNING id`, [email, hash]);
      for (const t of tids) await c.query(`INSERT INTO memberships(user_id,tenant_id,role) VALUES ($1,$2,'viewer')`, [u.rows[0].id, t]);
      return u.rows[0].id;
    });
    return json({ ok: true, id, tempPassword: pw }, 201);
  }

  if (parts[0] === "users" && parts.length >= 2) {
    const id = needUuid(parts[1]);
    const u = (await q(`SELECT * FROM users WHERE id=$1 AND role<>'super_admin'`, [id]))[0];
    if (!u) throw notFound("Utente non trovato.");
    if (parts[2] === "reset" && m === "POST") {
      const pw = tempPassword();
      await q(`UPDATE users SET pw_hash=$2, must_change_pw=true, session_ver=session_ver+1 WHERE id=$1`, [id, await hashPassword(pw)]);
      return json({ ok: true, tempPassword: pw });
    }
    if (parts.length === 2 && m === "PUT") {
      await tx(async (c) => {
        if (["active", "disabled"].includes(b.status))
          await c.query(`UPDATE users SET status=$2, session_ver=session_ver+1 WHERE id=$1`, [id, b.status]);
        if (u.role === "viewer" && Array.isArray(b.tenantIds)) {
          const tids = await validTenantIds(b.tenantIds);
          await c.query(`DELETE FROM memberships WHERE user_id=$1`, [id]);
          for (const t of tids) await c.query(`INSERT INTO memberships(user_id,tenant_id,role) VALUES ($1,$2,'viewer')`, [id, t]);
        }
      });
      return json({ ok: true });
    }
    if (parts.length === 2 && m === "DELETE") {
      await q(`DELETE FROM users WHERE id=$1`, [id]);
      return json({ ok: true });
    }
  }

  if (path === "/lists" && (m === "POST" || m === "DELETE")) {
    const v = str(b.value, 100);
    if (!v) throw bad("Valore non valido.");
    if (m === "POST") await q(`INSERT INTO lists(tenant_id,kind,value) VALUES (NULL,'tipiAttivita',$1) ON CONFLICT DO NOTHING`, [v]);
    else await q(`DELETE FROM lists WHERE tenant_id IS NULL AND kind='tipiAttivita' AND value=$1`, [v]);
    return json({ ok: true });
  }

  if (path === "/export" && m === "GET") {
    const one = url.searchParams.get("tenant");
    const ids = one ? [needUuid(one)] : (await q(`SELECT id FROM tenants ORDER BY lower(ragione_sociale)`)).map((x) => x.id);
    const out = [];
    for (const id of ids) {
      const t = await q(`SELECT 1 FROM tenants WHERE id=$1`, [id]);
      if (!t.length) throw notFound("Cliente non trovato.");
      const d: any = await tenantData(id, null);
      delete d.canWrite; delete d.isSuper;
      out.push(d);
    }
    const date = new Date().toISOString().slice(0, 10);
    const payload = one ? { exportedAt: new Date().toISOString(), ...out[0] } : { exportedAt: new Date().toISOString(), tenants: out };
    return json(payload, 200, { "content-disposition": `attachment; filename="foodcost-${one ? "cliente" : "tutti"}-${date}.json"` });
  }

  if (path === "/import" && m === "POST") {
    const tid = needUuid(b.tenant);
    if (!(await q(`SELECT 1 FROM tenants WHERE id=$1`, [tid])).length) throw notFound("Cliente non trovato.");
    await tx((c) => importInto(c, tid, b.data));
    return json({ ok: true });
  }

  if (path === "/seed" && m === "POST") {
    const tid = needUuid(b.tenant);
    if (!(await q(`SELECT 1 FROM tenants WHERE id=$1`, [tid])).length) throw notFound("Cliente non trovato.");
    await tx((c) => importInto(c, tid, demoData()));
    return json({ ok: true });
  }

  throw notFound("Operazione non trovata.");
}

async function validTenantIds(v: unknown): Promise<string[]> {
  const ids = [...new Set((Array.isArray(v) ? v : []).filter((x) => typeof x === "string" && UUID_RE.test(x)))] as string[];
  if (!ids.length) return [];
  const r = await q(`SELECT id FROM tenants WHERE id = ANY($1::uuid[])`, [ids]);
  if (r.length !== ids.length) throw bad("Cliente non valido.");
  return ids;
}
