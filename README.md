# Menù Lab

Food cost e menu engineering per la ristorazione (multi-cliente).

App web per food cost e menu engineering: alimenti, ricette, marginalità e menu engineering, con login e dati separati per ogni cliente.

## Com'è fatta
- `public/index.html`: l'app (una sola pagina). I calcoli si fanno nel browser, i dati stanno sul server.
- `netlify/functions/api.mts`: l'API su `/api/*` (Netlify Functions).
- `netlify/lib/`: logica del server (`app.mts` rotte e permessi, `auth.mts` login e sessioni, `db.mts` database, `seed.mts` dati di test).
- `netlify/database/migrations/`: lo schema del database (Netlify Database, Postgres), che Netlify applica da solo a ogni pubblicazione.

## Livelli di accesso
- **Super admin**: vede tutti i clienti, approva le registrazioni, decide piano, limite ricette e permessi, crea i visualizzatori, esporta e importa i backup.
- **Amministratore dell'attività**: gestisce solo i dati della propria attività, entro i permessi decisi dal super admin. Non può esportare.
- **Visualizzatore**: sola lettura, anche su più attività.

Permessi, limite ricette e isolamento tra clienti sono controllati sempre dal server.

## Variabili d'ambiente (Netlify → Project configuration → Environment variables)
| Nome | A cosa serve |
|---|---|
| `JWT_SECRET` | Segreto per firmare le sessioni (almeno 32 caratteri casuali). Da impostare come *secret*. |
| `SUPERADMIN_EMAIL` | Email del super admin. |
| `SUPERADMIN_PASSWORD` | Password del primo accesso del super admin (almeno 10 caratteri). Dopo il primo accesso si può cancellare. |

Il database si crea da solo alla prima pubblicazione (pacchetto `@netlify/database`).

## Test
Servono Node 22 e un Postgres di prova (il database indicato viene **svuotato**):

```bash
npm install
TEST_DATABASE_URL=postgres://utente@localhost:5432/foodcost_test npm test
```

Per provare l'app in locale senza Netlify:

```bash
RESET_DB=1 TEST_DATABASE_URL=postgres://... JWT_SECRET=un-segreto-lungo-almeno-32-caratteri \
SUPERADMIN_EMAIL=tu@esempio.it SUPERADMIN_PASSWORD=una-password-lunga npm run dev
# poi apri http://localhost:8888
```
