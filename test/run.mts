/* Test di sicurezza e permessi contro un Postgres vero.
   Uso: TEST_DATABASE_URL=postgres://... npm test   (il database viene svuotato!) */
import pg from "pg";
import { readFileSync } from "node:fs";
import { setPool } from "../netlify/lib/db.mts";
import { handle } from "../netlify/lib/app.mts";

const DB = process.env.TEST_DATABASE_URL;
if (!DB) { console.error("Imposta TEST_DATABASE_URL"); process.exit(1); }
process.env.JWT_SECRET = "test-secret-test-secret-test-secret-1234";
process.env.SUPERADMIN_EMAIL = "max@example.com";
process.env.SUPERADMIN_PASSWORD = "password-max-123";

const pool = new pg.Pool({ connectionString: DB });
await pool.query("DROP SCHEMA public CASCADE; CREATE SCHEMA public;");
await pool.query(readFileSync(new URL("../netlify/database/migrations/001_schema/migration.sql", import.meta.url), "utf8"));
setPool(pool as any);

let pass = 0, fail = 0;
const allBodies: string[] = [];
function ok(cond: unknown, name: string) {
  if (cond) { pass++; console.log("  ✓ " + name); } else { fail++; console.log("  ✗ " + name); }
}
function section(s: string) { console.log("\n" + s); }

class Agent {
  cookie = "";
  ip: string;
  constructor(ip = "10.0.0." + Math.floor(Math.random() * 250)) { this.ip = ip; }
  async call(method: string, path: string, body?: unknown, opts: { tenant?: string; headers?: Record<string, string> } = {}) {
    const url = "https://app.test/api" + path + (opts.tenant ? (path.includes("?") ? "&" : "?") + "tenant=" + opts.tenant : "");
    const headers: Record<string, string> = { ...(opts.headers || {}) };
    if (this.cookie) headers.cookie = this.cookie;
    if (body !== undefined) headers["content-type"] = headers["content-type"] || "application/json";
    const res = await handle(new Request(url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) }), this.ip);
    const sc = res.headers.get("set-cookie");
    if (sc) { const v = sc.split(";")[0]; this.cookie = v.endsWith("=") ? "" : v; }
    const text = await res.text();
    allBodies.push(text);
    let data: any = null;
    try { data = JSON.parse(text); } catch {}
    return { status: res.status, data, setCookie: sc };
  }
  get = (p: string, o?: any) => this.call("GET", p, undefined, o);
  post = (p: string, b: unknown = {}, o?: any) => this.call("POST", p, b, o);
  put = (p: string, b: unknown = {}, o?: any) => this.call("PUT", p, b, o);
  patch = (p: string, b: unknown = {}, o?: any) => this.call("PATCH", p, b, o);
  del = (p: string, b: unknown = {}, o?: any) => this.call("DELETE", p, b, o);
  async login(email: string, password: string) { return this.post("/login", { email, password }); }
}

const food = (name: string, price = 5) => ({ name, category: "Ortaggi", unit: "kg", mode: "max", history: [{ date: "2026-06-12", price }] });
const recipe = (name: string, rows: any[] = []) => ({ name, type: "PRIMI", portions: 1, rows });

/* ------------------------------------------------------------------ */
section("Super amministratore");
const max = new Agent();
let r = await max.login("max@example.com", "password-sbagliata");
ok(r.status === 401 && r.data.message === "Credenziali non valide.", "password errata → messaggio generico");
r = await max.login("max@example.com", "password-max-123");
ok(r.status === 200 && r.setCookie?.includes("HttpOnly") && r.setCookie.includes("Secure") && r.setCookie.includes("SameSite=Lax"), "primo accesso crea il super admin, cookie HttpOnly+Secure+SameSite");
r = await max.get("/me");
ok(r.data.user.role === "super_admin", "/me → super_admin");
const n = (await pool.query("SELECT count(*) FROM users WHERE role='super_admin'")).rows[0].count;
ok(Number(n) === 1, "esiste un solo super admin");

/* ------------------------------------------------------------------ */
section("Registrazione e approvazione (test 6)");
const pub = new Agent();
r = await pub.get("/public/tipi");
ok(r.data.tipi.includes("Pizzeria"), "tipi di attività pubblici");
r = await pub.post("/register", { email: "a@a.it", password: "corta", ragione: "Pizzeria A", tipo: "Pizzeria" });
ok(r.status === 400, "password sotto i 10 caratteri rifiutata");
r = await pub.post("/register", { email: "a@a.it", password: "passwordA-123", ragione: "Pizzeria A", tipo: "Pizzeria" });
ok(r.status === 201, "registrazione cliente A");
r = await new Agent().post("/register", { email: "b@b.it", password: "passwordB-123", ragione: "Trattoria B", tipo: "Trattoria" });
ok(r.status === 201, "registrazione cliente B");
r = await new Agent().post("/register", { email: "a@a.it", password: "passwordA-123", ragione: "Doppia", tipo: "Pizzeria" });
ok(r.status === 409, "email già registrata rifiutata");

const A = new Agent(), B = new Agent();
r = await A.login("a@a.it", "passwordA-123");
ok(r.status === 403 && r.data.error === "PENDING" && !r.setCookie, "account non approvato non entra (nessun cookie)");
r = await A.get("/data");
ok(r.status === 401, "senza sessione nessun dato");

r = await max.get("/admin/tenants");
const tA = r.data.tenants.find((t: any) => t.ragione === "Pizzeria A");
const tB = r.data.tenants.find((t: any) => t.ragione === "Trattoria B");
ok(tA.status === "pending" && tA.maxRecipes === 20 && tA.plan === "basic" && tA.canAddFoods && tA.canAddRecipes, "default: pending, basic, 20 ricette, permessi sì");
ok(!JSON.stringify(r.data).includes("pw_hash"), "pannello clienti senza pw_hash");
await max.put("/admin/tenants/" + tA.id, { status: "approved" });
await max.put("/admin/tenants/" + tB.id, { status: "approved" });
r = await A.login("a@a.it", "passwordA-123");
ok(r.status === 200, "dopo l'approvazione A entra");
r = await B.login("b@b.it", "passwordB-123");
ok(r.status === 200, "dopo l'approvazione B entra");

/* ------------------------------------------------------------------ */
section("Isolamento tra clienti (test 1)");
r = await A.get("/data");
ok(r.status === 200 && r.data.tenant.id === tA.id && r.data.canWrite === true, "A legge i propri dati senza indicare l'attività");
ok(r.data.lists.tipologie.includes("PIZZE CLASSICHE"), "A ha gli elenchi predefiniti");
const fA = (await A.post("/foods", food("pomodoro A"))).data.id;
const fB = (await B.post("/foods", food("segreto B", 9))).data.id;
const rB = (await B.post("/recipes", recipe("RICETTA SEGRETA B", [{ foodId: fB, name: "segreto B", qty: 100 }]))).data.id;
ok(fA && fB && rB, "A e B creano i propri dati");

r = await A.get("/data", { tenant: tB.id });
ok(r.status === 403, "A chiede i dati di B con ?tenant= → 403");
r = await A.get("/data", { headers: { "x-tenant-id": tB.id } });
ok(r.status === 403, "A chiede i dati di B con header X-Tenant-Id → 403");
r = await A.get("/data");
ok(!JSON.stringify(r.data).includes("segreto B") && !JSON.stringify(r.data).includes("SEGRETA"), "nei dati di A non compare nulla di B");
r = await A.put("/foods/" + fB, food("rubato"));
ok(r.status === 404, "A modifica un alimento di B → 404");
r = await A.put("/foods/" + fB, food("rubato"), { tenant: tB.id });
ok(r.status === 403, "A modifica un alimento di B indicando ?tenant=B → 403");
r = await A.del("/foods/" + fB);
ok(r.status === 404, "A elimina un alimento di B → 404");
r = await A.put("/recipes/" + rB, recipe("rubata"));
ok(r.status === 404, "A modifica una ricetta di B → 404");
r = await A.patch("/recipes/" + rB, { price: 1 });
ok(r.status === 404, "A cambia il prezzo di una ricetta di B → 404");
r = await A.del("/recipes/" + rB);
ok(r.status === 404, "A elimina una ricetta di B → 404");
r = await A.post("/recipes", recipe("furbata", [{ foodId: fB, name: "x", qty: 1 }]));
ok(r.status === 403, "A usa un alimento di B come ingrediente → 403");
r = await A.post("/recipes", recipe("furbata2", [{ subId: rB, name: "x", qty: 1 }]));
ok(r.status === 403, "A usa una ricetta di B come ingrediente → 403");
r = await A.post("/lists", { kind: "reparti", value: "X" }, { tenant: tB.id });
ok(r.status === 403, "A scrive negli elenchi di B → 403");
r = await A.put("/tenant", { ragione: "Hackerata" }, { tenant: tB.id });
ok(r.status === 403, "A modifica l'anagrafica di B → 403");
r = await A.get("/data", { tenant: "not-a-uuid" });
ok(r.status === 403, "id attività non valido → 403");
r = await B.get("/data");
ok(r.data.foods.some((f: any) => f.name === "segreto B") && r.data.recipes[0].name === "RICETTA SEGRETA B" && r.data.tenant.ragione === "Trattoria B",
  "i dati di B sono intatti");

/* ------------------------------------------------------------------ */
section("Limite ricette (test 2)");
for (let i = 1; i <= 20; i++) {
  r = await A.post("/recipes", recipe("R" + i, [{ foodId: fA, name: "pomodoro A", qty: 10 }]));
  if (r.status !== 201) break;
}
ok(r.status === 201, "A crea 20 ricette");
r = await A.post("/recipes", recipe("R21"));
ok(r.status === 403 && r.data.error === "LIMIT_REACHED" && r.data.message === "Hai raggiunto il limite del piano base. Contatta l'amministratore per ampliarlo.", "la 21ª ricetta è rifiutata con LIMIT_REACHED e il messaggio del brief");
r = await A.post("/recipes", { ...recipe("R1 (copia)"), rows: [{ foodId: fA, qty: 10 }] });
ok(r.status === 403 && r.data.error === "LIMIT_REACHED", "anche duplicare è rifiutato");
const parallel = await Promise.all([1, 2, 3].map((i) => A.post("/recipes", recipe("P" + i))));
ok(parallel.every((x) => x.status === 403), "richieste in parallelo non superano il limite");
r = await A.get("/data");
ok(r.data.recipeCount === 20 && r.data.tenant.maxRecipes === 20, "contatore 20 / 20");
await max.put("/admin/tenants/" + tA.id, { maxRecipes: 25 });
r = await A.post("/recipes", recipe("R21"));
ok(r.status === 201, "dopo che Max alza il limite la creazione funziona");
await max.put("/admin/tenants/" + tA.id, { plan: "pro", maxRecipes: null });
r = await A.post("/recipes", recipe("R22"));
ok(r.status === 201, "piano pro illimitato");
await max.put("/admin/tenants/" + tA.id, { plan: "basic", maxRecipes: 20 });
r = await max.post("/recipes", recipe("fatta da Max"), { tenant: tA.id });
ok(r.status === 201, "il super admin può creare anche oltre il limite");
r = await A.put("/recipes/" + (await A.get("/data")).data.recipes[0].id, recipe("rinominata"));
ok(r.status === 200, "oltre il limite A può ancora modificare le ricette esistenti");

/* ------------------------------------------------------------------ */
section("Permessi per cliente (test 3)");
await max.put("/admin/tenants/" + tB.id, { canAddFoods: false, canAddRecipes: false });
r = await B.post("/foods", food("nuovo"));
ok(r.status === 403 && r.data.error === "FOODS_DISABLED", "can_add_foods = false → creazione alimenti rifiutata");
r = await B.post("/recipes", recipe("nuova"));
ok(r.status === 403 && r.data.error === "RECIPES_DISABLED", "can_add_recipes = false → creazione ricette rifiutata");
r = await B.put("/foods/" + fB, food("segreto B", 10));
ok(r.status === 200, "B può ancora aggiornare i prezzi degli alimenti esistenti");
await max.put("/admin/tenants/" + tB.id, { canAddFoods: true, canAddRecipes: true });
r = await B.post("/foods", food("nuovo"));
ok(r.status === 201, "riabilitato → creazione alimenti di nuovo possibile");

/* ------------------------------------------------------------------ */
section("Visualizzatore (test 4)");
r = await max.post("/admin/viewers", { email: "cuoco@a.it", tenantIds: [tA.id] });
ok(r.status === 201 && r.data.tempPassword?.length === 12, "Max crea un viewer con password provvisoria");
const V = new Agent();
r = await V.login("cuoco@a.it", r.data.tempPassword);
ok(r.status === 200, "il viewer entra");
r = await V.get("/me");
ok(r.data.user.mustChangePw === true && r.data.tenants.length === 1 && r.data.tenants[0].role === "viewer", "viewer: deve cambiare password, vede solo A");
r = await V.get("/data");
ok(r.status === 200 && r.data.canWrite === false, "il viewer legge i dati di A in sola lettura");
const rA = r.data.recipes[0].id;
const writes = [
  await V.post("/foods", food("viewer")), await V.put("/foods/" + fA, food("viewer")), await V.del("/foods/" + fA),
  await V.post("/recipes", recipe("viewer")), await V.put("/recipes/" + rA, recipe("viewer")), await V.patch("/recipes/" + rA, { price: 1 }),
  await V.del("/recipes/" + rA), await V.post("/lists", { kind: "reparti", value: "v" }), await V.del("/lists", { kind: "reparti", value: "Carne" }),
  await V.put("/tenant", { ragione: "viewer" }),
];
ok(writes.every((x) => x.status === 403 && x.data.error === "READ_ONLY"), "POST/PUT/PATCH/DELETE del viewer tutti rifiutati (" + writes.map((x) => x.status).join(",") + ")");
r = await V.get("/data", { tenant: tB.id });
ok(r.status === 403, "il viewer di A non legge B");
r = await max.post("/admin/viewers", { email: "consulente@max.it", tenantIds: [tA.id, tB.id] });
const V2 = new Agent();
await V2.login("consulente@max.it", r.data.tempPassword);
r = await V2.get("/data");
ok(r.status === 400 && r.data.error === "NO_TENANT", "viewer con più attività deve sceglierne una");
ok((await V2.get("/data", { tenant: tB.id })).status === 200 && (await V2.get("/data", { tenant: tA.id })).status === 200, "viewer multi-attività legge A e B");
ok((await V2.post("/foods", food("x"), { tenant: tB.id })).status === 403, "…ma non scrive");

/* ------------------------------------------------------------------ */
section("Area riservata al super admin (test 5)");
const adminRoutes: [string, string, unknown?][] = [
  ["GET", "/admin/tenants"], ["PUT", "/admin/tenants/" + tA.id, { maxRecipes: 999 }], ["DELETE", "/admin/tenants/" + tB.id, {}],
  ["GET", "/admin/users"], ["POST", "/admin/viewers", { email: "x@x.it", tenantIds: [tA.id] }], ["GET", "/admin/export"],
  ["GET", "/admin/export?tenant=" + tA.id], ["POST", "/admin/import", { tenant: tA.id, data: { foods: [], recipes: [] } }],
  ["POST", "/admin/seed", { tenant: tA.id }], ["POST", "/admin/tenants", { ragione: "x" }], ["POST", "/admin/lists", { value: "x" }],
];
for (const [who, ag] of [["cliente", A], ["viewer", V]] as const) {
  const res = [];
  for (const [m, p, b] of adminRoutes) res.push(await ag.call(m, p, b));
  ok(res.every((x) => x.status === 403), who + ": tutte le rotte admin (export, import, backup, clienti) → 403");
}
ok((await pub.get("/admin/export")).status === 401, "anonimo: export → 401");
r = await A.get("/data");
ok(r.data.tenant.maxRecipes === 20, "il tentativo del cliente di alzarsi il limite non ha avuto effetto");
r = await max.get("/admin/export?tenant=" + tA.id);
ok(r.status === 200 && r.data.recipes.length > 20, "Max esporta i dati di un cliente");

/* ------------------------------------------------------------------ */
section("Sospensione, reset password, sessioni");
const A2 = new Agent();
await A2.login("a@a.it", "passwordA-123");
await max.put("/admin/tenants/" + tA.id, { status: "suspended" });
r = await A2.get("/data");
ok(r.status >= 400 && r.status < 500, "attività sospesa: la sessione aperta non legge più i dati");
r = await new Agent().login("a@a.it", "passwordA-123");
ok(r.status === 403 && r.data.error === "SUSPENDED", "attività sospesa: login rifiutato");
await max.put("/admin/tenants/" + tA.id, { status: "approved" });
const uA = (await max.get("/admin/tenants")).data.tenants.find((t: any) => t.id === tA.id).admins[0].id;
r = await max.post("/admin/users/" + uA + "/reset");
const tmp = r.data.tempPassword;
r = await A.get("/data");
ok(r.status === 401, "dopo il reset della password le sessioni aperte decadono");
r = await A.login("a@a.it", tmp);
ok(r.status === 200, "accesso con la password provvisoria");
r = await A.post("/password", { old: tmp, new: "nuovaPassword-A1" });
ok(r.status === 200 && (await A.get("/me")).data.user.mustChangePw === false, "cambio password riuscito");
await max.put("/admin/users/" + uA, { status: "disabled" });
ok((await A.get("/data")).status === 401, "utente disattivato: sessione chiusa");
await max.put("/admin/users/" + uA, { status: "active" });
await A.login("a@a.it", "nuovaPassword-A1");

/* ------------------------------------------------------------------ */
section("Ricette come ingredienti");
const base = (await A.post("/recipes", recipe("IMPASTO", [{ foodId: fA, qty: 100 }]))).status;
ok(base === 403, "(A è al limite, quindi Max lo alza per il test)");
await max.put("/admin/tenants/" + tA.id, { maxRecipes: 100 });
const imp = (await A.post("/recipes", { ...recipe("IMPASTO", [{ foodId: fA, qty: 100 }]), yieldG: 1000 })).data.id;
const piz = (await A.post("/recipes", recipe("PIZZA", [{ subId: imp, name: "IMPASTO", qty: 200 }]))).data.id;
ok(imp && piz, "una ricetta usa un'altra ricetta come ingrediente");
r = await A.put("/recipes/" + imp, recipe("IMPASTO", [{ subId: piz, qty: 1 }]));
ok(r.status === 400 && r.data.error === "CYCLE", "ciclo A→B→A rifiutato");
r = await A.put("/recipes/" + imp, recipe("IMPASTO", [{ subId: imp, qty: 1 }]));
ok(r.status === 400 && r.data.error === "CYCLE", "ricetta dentro se stessa rifiutata");
r = await A.get("/data");
const pz = r.data.recipes.find((x: any) => x.id === piz);
ok(pz.rows[0].subId === imp && pz.rows[0].qty === 200, "la riga salvata punta alla sotto-ricetta");

/* ------------------------------------------------------------------ */
section("Cambio massivo del prezzo da usare");
{
  const fA2 = (await A.post("/foods", { ...food("secondo A"), history: [{ date: "2026-01-01", price: 2 }, { date: "2026-02-01", price: 8 }] })).data.id;
  r = await A.patch("/foods", { mode: "min", ids: [fA, fA2, fB] });
  ok(r.status === 200 && r.data.updated === 2, "A cambia il prezzo da usare dei suoi alimenti (quello di B ignorato)");
  const dA = (await A.get("/data")).data;
  ok(dA.foods.filter((x: any) => [fA, fA2].includes(x.id)).every((x: any) => x.mode === "min"), "i due alimenti di A ora usano il prezzo minimo");
  const dB = (await B.get("/data")).data;
  ok(dB.foods.find((x: any) => x.id === fB).mode === "max", "l'alimento di B non è cambiato");
  ok((await A.patch("/foods", { mode: "boh", ids: [fA] })).status === 400, "prezzo da usare non valido → 400");
  ok((await V.patch("/foods", { mode: "avg", ids: [fA] })).status === 403, "il viewer non può fare il cambio massivo");
}

section("Dati di test, importazione, varie");
r = await max.post("/admin/tenants", { ragione: "Demo", tipo: "Pizzeria", demo: true });
const demo = r.data.id;
r = await max.get("/data", { tenant: demo });
ok(r.data.foods.length === 25 && r.data.recipes.length === 8, "cliente Demo con 25 alimenti e 8 ricette");
const marg = r.data.recipes.find((x: any) => x.name === "MARGHERITA");
const pal = r.data.recipes.find((x: any) => x.name === "PALLINA");
ok(marg.rows[0].subId === pal.id && pal.yieldG === 1625, "MARGHERITA contiene la PALLINA");
const exp = (await max.get("/admin/export?tenant=" + demo)).data;
r = await max.post("/admin/import", { tenant: tB.id, data: exp });
const bd = (await max.get("/data", { tenant: tB.id })).data;
ok(bd.recipes.length === 8 && bd.recipes.find((x: any) => x.name === "MARGHERITA").rows[0].subId === bd.recipes.find((x: any) => x.name === "PALLINA").id,
  "import di un export in un altro cliente, con id ricollegati");
r = await A.post("/lists", { kind: "reparti", value: "X" }, { headers: { origin: "https://evil.example" } });
ok(r.status === 403, "richiesta da un altro sito (Origin diverso) rifiutata");
r = await A.call("POST", "/lists", "kind=reparti", { headers: { "content-type": "text/plain" } });
ok(r.status === 400, "richiesta non JSON rifiutata");
ok(!allBodies.some((b) => b.includes("pw_hash") || b.includes("$2b$") || b.includes("$2a$")), "nessuna risposta contiene hash di password");

section("Limitazione tentativi di login");
const R = new Agent("10.9.9.9");
let last;
for (let i = 0; i < 10; i++) last = await R.login("b@b.it", "sbagliata-" + i);
ok(last!.status === 429, "dopo troppi tentativi → 429");
r = await R.login("b@b.it", "passwordB-123");
ok(r.status === 429, "anche con la password giusta finché dura il blocco");
r = await R.login("nessuno@x.it", "qualcosa-123");
ok(r.status === 401 && r.data.message === "Credenziali non valide.", "email inesistente → stesso messaggio generico");

console.log(`\n${pass} superati, ${fail} falliti`);
await pool.end();
process.exit(fail ? 1 : 0);
