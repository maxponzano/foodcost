/* Test di sicurezza e permessi contro un Postgres vero.
   Uso: TEST_DATABASE_URL=postgres://... npm test   (il database viene svuotato!) */
import pg from "pg";
import { readFileSync, readdirSync } from "node:fs";
import { setPool } from "../netlify/lib/db.mts";
import { handle } from "../netlify/lib/app.mts";

const DB = process.env.TEST_DATABASE_URL;
if (!DB) { console.error("Imposta TEST_DATABASE_URL"); process.exit(1); }
process.env.JWT_SECRET = "test-secret-test-secret-test-secret-1234";
process.env.SUPERADMIN_EMAIL = "max@example.com";
process.env.SUPERADMIN_PASSWORD = "password-max-123";

const pool = new pg.Pool({ connectionString: DB });
await pool.query("DROP SCHEMA public CASCADE; CREATE SCHEMA public;");
for (const d of readdirSync(new URL("../netlify/database/migrations/", import.meta.url)).sort())
    await pool.query(readFileSync(new URL(`../netlify/database/migrations/${d}/migration.sql`, import.meta.url), "utf8"));
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

section("Piatto escluso dalle medie");
{
  const rid = (await A.get("/data")).data.recipes[0].id;
  ok((await A.get("/data")).data.recipes[0].inAvg === true, "di base il piatto conta nella media");
  r = await A.patch("/recipes/" + rid, { inAvg: false });
  ok(r.status === 200 && (await A.get("/data")).data.recipes.find((x: any) => x.id === rid).inAvg === false, "A esclude un piatto dalla media");
  const full = (await A.get("/data")).data.recipes.find((x: any) => x.id === rid);
  await A.put("/recipes/" + rid, { ...full });
  ok((await A.get("/data")).data.recipes.find((x: any) => x.id === rid).inAvg === false, "salvando la ricetta l'esclusione resta");
  ok((await V.patch("/recipes/" + rid, { inAvg: true })).status === 403, "il viewer non può cambiare il flag");
  ok((await B.patch("/recipes/" + rid, { inAvg: true })).status === 404, "B non può cambiare il flag di un piatto di A");
}

section("Vendite mensili");
{
  const dA = (await A.get("/data")).data, r1 = dA.recipes[0].id, r2 = dA.recipes[1].id;
  r = await A.put("/sales", { period: "2026-08", items: [{ recipeId: r1, qty: 40 }, { recipeId: r2, qty: 12 }] });
  ok(r.status === 200, "A inserisce le vendite di agosto");
  await A.put("/sales", { period: "2026-09", items: [{ recipeId: r1, qty: 55 }] });
  let s1 = (await A.get("/data")).data.sales;
  ok(s1[r1]["2026-08"] === 40 && s1[r1]["2026-09"] === 55 && s1[r2]["2026-08"] === 12, "storico per mese salvato");
  await A.put("/sales", { period: "2026-08", items: [{ recipeId: r2, qty: 0 }] });
  s1 = (await A.get("/data")).data.sales;
  ok(!s1[r2] || s1[r2]["2026-08"] === undefined, "quantità 0 cancella il mese");
  ok((await A.put("/sales", { period: "2026-13", items: [] })).status === 400, "mese non valido → 400");
  ok((await A.put("/sales", { period: "2026-08", items: [{ recipeId: rB, qty: 5 }] })).status === 403, "A non può scrivere vendite di un piatto di B");
  ok((await B.get("/data")).data.sales[rB] === undefined, "le vendite di B restano vuote");
  ok((await V.put("/sales", { period: "2026-08", items: [{ recipeId: r1, qty: 1 }] })).status === 403, "il viewer non può inserire vendite");
  ok((await V.get("/data")).data.sales[r1]["2026-09"] === 55, "il viewer legge le vendite");
}

section("Vendite settimanali e azzeramento");
{
  const { isoMonday, isoWeeks, parsePeriod } = await import("../netlify/lib/app.mts");
  ok(isoMonday(2026, 1) === "2025-12-29" && isoMonday(2026, 40) === "2026-09-28" && isoMonday(2021, 1) === "2021-01-04", "lunedì della settimana ISO corretto");
  ok(isoWeeks(2026) === 53 && isoWeeks(2025) === 52 && isoWeeks(2020) === 53, "anni con 52 o 53 settimane");
  ok(parsePeriod("2025-W53") === null && parsePeriod("2026-W53")?.date === "2026-12-28" && parsePeriod("2026-W00") === null, "settimana inesistente rifiutata");
  const dA = (await A.get("/data")).data, r1 = dA.recipes[0].id, r2 = dA.recipes[1].id;
  ok(dA.salesGrain === "M", "di base il cliente inserisce le vendite per mese");
  ok((await V.patch("/tenant", { salesGrain: "W" })).status === 403, "il viewer non può cambiare il modo di inserimento");
  ok((await A.patch("/tenant", { salesGrain: "W" })).status === 403, "il cliente non può cambiare il modo di inserimento");
  ok((await max.patch("/tenant", { salesGrain: "X" }, { tenant: tA.id })).status === 400, "modo non valido → 400");
  ok((await max.put("/admin/tenants/" + tA.id, { salesGrain: "W" })).status === 200 && (await A.get("/data")).data.salesGrain === "W", "il super admin passa A all'inserimento settimanale dal pannello Clienti");
  ok((await max.get("/admin/tenants")).data.tenants.find((t: any) => t.id === tA.id).salesGrain === "W", "il pannello Clienti mostra il modo di inserimento");
  ok((await max.patch("/tenant", { salesGrain: "M" }, { tenant: tA.id })).status === 200 && (await max.patch("/tenant", { salesGrain: "W" }, { tenant: tA.id })).status === 200, "il super admin può cambiarlo anche dalla pagina Vendite");
  ok((await B.get("/data")).data.salesGrain === "M", "il modo di B non cambia");
  r = await A.put("/sales", { period: "2026-W40", items: [{ recipeId: r1, qty: 30 }, { recipeId: r2, qty: 4 }] });
  ok(r.status === 200, "A inserisce le vendite della settimana 40");
  await A.put("/sales", { period: "2026-W41", items: [{ recipeId: r1, qty: 25 }] });
  let s1 = (await A.get("/data")).data.sales;
  ok(s1[r1]["2026-W40"] === 30 && s1[r1]["2026-W41"] === 25 && s1[r1]["2026-09"] === 55, "settimane salvate accanto ai mesi già inseriti");
  ok((await A.put("/sales", { period: "2025-W53", items: [] })).status === 400, "settimana 53 del 2025 non esiste → 400");
  ok((await A.put("/sales", { period: "2026-W40", items: [{ recipeId: rB, qty: 5 }] })).status === 403, "A non può scrivere vendite settimanali di un piatto di B");
  ok((await V.post("/sales/reset", { scope: "all" })).status === 403, "il viewer non può azzerare le vendite");
  ok((await B.post("/sales/reset", { scope: "all" })).status === 200 && (await A.get("/data")).data.sales[r1]["2026-W40"] === 30, "l'azzeramento di B non tocca le vendite di A");
  ok((await A.post("/sales/reset", { period: "2026-13" })).status === 400, "azzeramento di un periodo non valido → 400");
  r = await A.post("/sales/reset", { period: "2026-W40" });
  s1 = (await A.get("/data")).data.sales;
  ok(r.data.deleted === 2 && s1[r1]["2026-W40"] === undefined && s1[r1]["2026-W41"] === 25 && s1[r1]["2026-09"] === 55, "azzera solo la settimana scelta");
  r = await A.post("/sales/reset", { scope: "all" });
  ok(r.status === 200 && Object.keys((await A.get("/data")).data.sales).length === 0, "azzera tutte le vendite del cliente");
  // importazione dalla cassa
  const imp = { period: "2026-W01", rows: [{ name: "Classico 200 gr", recipeId: r1, qty: 21 }, { name: "Classico 100 gr", recipeId: r1, qty: 23 }, { name: "Coca Cola", recipeId: null, qty: 18, ignore: true }, { name: "Tomino", recipeId: null, qty: 1 }, { name: "Pulled", recipeId: r2, qty: 0 }] };
  ok((await A.post("/sales/import", imp)).status === 403, "il cliente non può importare dalla cassa");
  ok((await max.post("/sales/import", { ...imp, period: "2026-13" }, { tenant: tA.id })).status === 400, "periodo non valido → 400");
  ok((await max.post("/sales/import", { ...imp, rows: [{ name: "x", recipeId: rB, qty: 1 }] }, { tenant: tA.id })).status === 403, "non si importa su un piatto di un altro cliente");
  await A.put("/sales", { period: "2026-W01", items: [{ recipeId: r2, qty: 99 }] });
  r = await max.post("/sales/import", imp, { tenant: tA.id });
  let dd = (await max.get("/data", { tenant: tA.id })).data;
  ok(r.status === 200 && dd.sales[r1]["2026-W01"] === 44, "le righe abbinate allo stesso piatto si sommano (21 + 23)");
  ok(!dd.sales[r2] || dd.sales[r2]["2026-W01"] === undefined, "l'importazione sostituisce la settimana");
  ok(dd.salesAliases["classico 100 gr"] === r1 && dd.salesAliases["coca cola"] === "", "abbinamenti e righe ignorate ricordati");
  ok(!("tomino" in dd.salesAliases), "una voce non assegnata non viene ricordata come ignorata");
  await max.post("/sales/import", { period: "2026-W02", rows: [{ name: "Coca Cola", recipeId: null, qty: 3 }] }, { tenant: tA.id });
  ok(!("coca cola" in (await max.get("/data", { tenant: tA.id })).data.salesAliases), "rimettendo una voce su \"da assegnare\" l'abbinamento si cancella");
  ok((await A.get("/data")).data.salesAliases === undefined, "il cliente non riceve gli abbinamenti della cassa");
  r = await max.post("/sales/import", { period: "2026-01", rows: [{ name: "MARGHERITA", recipeId: r1, qty: 144 }] }, { tenant: tA.id });
  dd = (await max.get("/data", { tenant: tA.id })).data;
  ok(r.status === 200 && dd.sales[r1]["2026-01"] === 144 && dd.sales[r1]["2026-W01"] === 44 && dd.salesGrain === "M", "importazione di un mese intero (file Excel mensile): il cliente passa a inserimento per mese");
  await max.patch("/tenant", { salesGrain: "W" }, { tenant: tA.id });
  // voci senza ricetta: creo il piatto con il prezzo proposto dal file
  r = await max.post("/sales/import", { period: "2026-02", rows: [
    { name: "Crispy Ravioli", recipeId: null, qty: 12, create: { name: "CRISPY RAVIOLI", type: "PRIMI", price: 9.5 } },
    { name: "crispy ravioli mix", recipeId: null, qty: 3, create: { name: "crispy ravioli", type: "PRIMI", price: 9 } },
    { name: "Gelato", recipeId: null, qty: 4, create: { name: "GELATO", type: "", price: null } }] }, { tenant: tA.id });
  dd = (await max.get("/data", { tenant: tA.id })).data;
  const cr = dd.recipes.find((x: any) => x.name === "CRISPY RAVIOLI"), ge = dd.recipes.find((x: any) => x.name === "GELATO");
  ok(r.status === 200 && r.data.created === 2 && cr && cr.rows.length === 0 && cr.price === 9.5 && cr.priceCheck === true && cr.type === "PRIMI", "piatto senza ricetta creato con prezzo da confermare");
  ok(dd.sales[cr.id]["2026-02"] === 15 && ge.price === "" && ge.priceCheck === false, "due voci sullo stesso nome si sommano; senza prezzo resta da inserire");
  ok(dd.salesAliases["crispy ravioli"] === cr.id && dd.salesAliases["gelato"] === ge.id, "abbinamento ricordato per i file successivi");
  await max.patch("/recipes/" + cr.id, { price: 10 }, { tenant: tA.id });
  ok((await max.get("/data", { tenant: tA.id })).data.recipes.find((x: any) => x.id === cr.id).priceCheck === false, "scrivendo il prezzo il segnale si toglie");
  await max.patch("/tenant", { salesGrain: "W" }, { tenant: tA.id });
  await max.post("/sales/reset", { scope: "all" }, { tenant: tA.id });
  await A.put("/sales", { period: "2026-W40", items: [{ recipeId: r1, qty: 7 }] });
  await A.put("/sales", { period: "2026-09", items: [{ recipeId: r1, qty: 55 }] });
}

section("Nota da verificare sulla ricetta");
{
  const rid = (await A.get("/data")).data.recipes[0].id;
  ok((await A.patch("/recipes/" + rid, { checkNote: "Chiedere al titolare il fondo bruno" })).status === 200 && (await A.get("/data")).data.recipes.find((x: any) => x.id === rid).checkNote === "Chiedere al titolare il fondo bruno", "nota salvata");
  const full = (await A.get("/data")).data.recipes.find((x: any) => x.id === rid);
  await A.put("/recipes/" + rid, { ...full });
  ok((await A.get("/data")).data.recipes.find((x: any) => x.id === rid).checkNote === "Chiedere al titolare il fondo bruno", "salvando la ricetta la nota resta");
  ok((await V.patch("/recipes/" + rid, { checkNote: "" })).status === 403, "il viewer non può toglierla");
  await A.patch("/recipes/" + rid, { checkNote: "" });
  ok((await A.get("/data")).data.recipes.find((x: any) => x.id === rid).checkNote === "", "verificato: nota tolta");
}

section("Importazione in modalità Aggiorna");
{
  // cliente di prova con i dati demo e qualche vendita
  const tid = (await max.post("/admin/tenants", { ragione: "Merge Test", tipo: "Pizzeria", demo: true })).data.id;
  let d0 = (await max.get("/data", { tenant: tid })).data;
  const marg = d0.recipes.find((x: any) => x.name === "MARGHERITA"), cla = d0.recipes.find((x: any) => x.name === "CLASSICA");
  await max.put("/sales", { period: "2026-07", items: [{ recipeId: marg.id, qty: 300 }] }, { tenant: tid });
  await max.patch("/recipes/" + marg.id, { price: 8.5, inAvg: false, checkNote: "nota mia" }, { tenant: tid });
  const file: any = JSON.parse(JSON.stringify((await max.get("/admin/export?tenant=" + tid)).data));
  delete file.sales;
  const fm = file.recipes.find((x: any) => x.name === "MARGHERITA");
  fm.price = 7; fm.rows.find((x: any) => !x.subId).qty = 150;                       // dose cambiata, prezzo diverso
  file.recipes = file.recipes.filter((x: any) => x.name !== "CLASSICA");             // ricetta tolta dal file
  file.recipes.push({ id: "nuova", name: "DIAVOLA", type: "PIZZE SEMPLICI", portions: 1, price: 8, rows: [{ foodId: file.foods[0].id, name: file.foods[0].name, qty: 50 }] });
  file.foods.push({ id: "nf", name: "nduja", category: "Salumi", unit: "kg", history: [{ date: "2026-10-01", price: 22 }] });
  file.foods.find((x: any) => x.name === "pomodoro").history.push({ date: "2026-10-01", price: 1.6 });
  r = await max.post("/admin/import", { tenant: tid, data: file, mode: "merge", dryRun: true });
  const sm = r.data.summary;
  ok(r.status === 200 && sm.recipesChanged.includes("MARGHERITA") && sm.recipesNew.includes("DIAVOLA") && sm.recipesNotInFile.includes("CLASSICA"), "prova: riepilogo ricette (cambiate, nuove, non nel file)");
  ok(sm.foodsNew.includes("nduja") && sm.foodsPrice.some((x: any) => x.name === "pomodoro" && x.to === 1.6), "prova: alimenti nuovi e prezzi cambiati");
  ok(sm.recipesSame === 6, "prova: le altre ricette risultano uguali (" + sm.recipesSame + ")");
  ok((await max.get("/data", { tenant: tid })).data.recipes.length === 8, "la prova non cambia niente");
  r = await max.post("/admin/import", { tenant: tid, data: file, mode: "merge" });
  const d1 = (await max.get("/data", { tenant: tid })).data, m1 = d1.recipes.find((x: any) => x.name === "MARGHERITA");
  ok(r.status === 200 && m1.id === marg.id && d1.sales[marg.id]["2026-07"] === 300, "la ricetta aggiornata resta la stessa: vendite conservate");
  ok(m1.price === 8.5 && m1.inAvg === false && m1.checkNote === "nota mia", "prezzo di vendita, flag e nota dell'app restano");
  ok(m1.rows.find((x: any) => !x.subId).qty === 150 && m1.rows[0].subId, "ingredienti aggiornati, sotto-ricetta ancora collegata");
  ok(d1.recipes.some((x: any) => x.id === cla.id) && d1.recipes.some((x: any) => x.name === "DIAVOLA") && d1.recipes.length === 9, "la ricetta non nel file resta, quella nuova si aggiunge");
  const pom = d1.foods.find((x: any) => x.name === "pomodoro");
  ok(pom.history.length === 2 && pom.history[1].price === 1.6 && d1.foods.some((x: any) => x.name === "nduja"), "nuovo prezzo aggiunto allo storico, nuovo alimento aggiunto");
  r = await max.post("/admin/import", { tenant: tid, data: file, mode: "merge", dryRun: true });
  ok(r.data.summary.recipesChanged.length === 0 && r.data.summary.foodsPrice.length === 0 && r.data.summary.foodsNew.length === 0, "rifacendo lo stesso aggiornamento non cambia più niente");
  ok((await A.post("/admin/import", { tenant: tid, data: file, mode: "merge" })).status === 403, "solo il super admin aggiorna");
  await max.del("/admin/tenants/" + tid);
}

section("Persona autorizzata aggiunta a un cliente esistente");
{
  ok((await A.post("/admin/tenants/" + tB.id + "/admins", { name: "X", email: "x@x.it" })).status === 403, "solo il super admin aggiunge persone");
  ok((await max.post("/admin/tenants/" + tB.id + "/admins", { name: "Mario", email: "nonvalida" })).status === 400, "email non valida → 400");
  r = await max.post("/admin/tenants/" + tB.id + "/admins", { name: "Mario Rossi", email: "Mario.Rossi@Trattoria.it" });
  ok(r.status === 201 && r.data.tempPassword, "persona aggiunta con password provvisoria");
  const pw2 = r.data.tempPassword, uid2 = r.data.id;
  ok((await max.post("/admin/tenants/" + tB.id + "/admins", { name: "Altro", email: "mario.rossi@trattoria.it" })).status === 409, "email già usata → 409");
  const tb = (await max.get("/admin/tenants")).data.tenants.find((t: any) => t.id === tB.id);
  ok(tb.admins.some((a: any) => a.name === "Mario Rossi" && a.email === "mario.rossi@trattoria.it"), "nome ed email visibili nella scheda cliente");
  const M = new Agent();
  await M.post("/login", { email: "mario.rossi@trattoria.it", password: pw2 });
  const md = (await M.get("/data")).data;
  ok(md && md.tenant && md.tenant.id === tB.id && md.canWrite === true, "la persona entra e può lavorare sui dati del cliente");
  ok((await M.get("/data", { tenant: tA.id })).status === 403 || (await M.get("/data", { tenant: tA.id })).data.tenant.id !== tA.id, "ma non vede gli altri clienti");
  ok((await max.del("/admin/users/" + uid2)).status === 200 && (await max.get("/admin/tenants")).data.tenants.find((t: any) => t.id === tB.id).admins.every((a: any) => a.id !== uid2), "il super admin può togliere la persona");
}

section("Dati di test, importazione, varie");
r = await max.post("/admin/tenants", { ragione: "Demo", tipo: "Pizzeria", demo: true });
const demo = r.data.id;
r = await max.get("/data", { tenant: demo });
ok(r.data.foods.length === 25 && r.data.recipes.length === 8, "cliente Demo con 25 alimenti e 8 ricette");
ok(Object.keys(r.data.sales).length === 7, "i dati di test hanno le vendite (7 piatti venduti)");
const marg = r.data.recipes.find((x: any) => x.name === "MARGHERITA");
const pal = r.data.recipes.find((x: any) => x.name === "PALLINA");
ok(marg.rows[0].subId === pal.id && pal.yieldG === 1625, "MARGHERITA contiene la PALLINA");
const exp = (await max.get("/admin/export?tenant=" + demo)).data;
r = await max.post("/admin/import", { tenant: tB.id, data: exp });
const bd = (await max.get("/data", { tenant: tB.id })).data;
ok(bd.recipes.length === 8 && bd.recipes.find((x: any) => x.name === "MARGHERITA").rows[0].subId === bd.recipes.find((x: any) => x.name === "PALLINA").id,
  "import di un export in un altro cliente, con id ricollegati");
ok(bd.sales[bd.recipes.find((x: any) => x.name === "MARGHERITA").id] && Object.values(bd.sales[bd.recipes.find((x: any) => x.name === "MARGHERITA").id])[0] === 220, "l'import porta anche le vendite");
{
  const ea = (await max.get("/admin/export?tenant=" + tA.id)).data;
  await max.post("/admin/import", { tenant: tB.id, data: ea });
  const b2 = (await max.get("/data", { tenant: tB.id })).data, s2 = Object.values(b2.sales) as any[];
  ok(b2.salesGrain === "W" && s2.some((x) => x["2026-W40"] === 7 && x["2026-09"] === 55), "export/import porta settimane, mesi e modo di inserimento");
}
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
