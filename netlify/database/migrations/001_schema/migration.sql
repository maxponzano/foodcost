-- Food Cost multi-cliente: schema iniziale

CREATE TABLE users (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email         TEXT NOT NULL UNIQUE,
  pw_hash       TEXT NOT NULL,
  role          TEXT NOT NULL CHECK (role IN ('super_admin','client_admin','viewer')),
  status        TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','active','disabled')),
  must_change_pw BOOLEAN NOT NULL DEFAULT FALSE,
  session_ver   INTEGER NOT NULL DEFAULT 0,      -- incrementato per invalidare le sessioni aperte
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE tenants (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  ragione_sociale TEXT NOT NULL,
  tipo_attivita   TEXT NOT NULL DEFAULT '',
  plan            TEXT NOT NULL DEFAULT 'basic' CHECK (plan IN ('basic','pro')),
  max_recipes     INTEGER DEFAULT 20 CHECK (max_recipes IS NULL OR max_recipes >= 0), -- NULL = illimitato
  can_add_foods   BOOLEAN NOT NULL DEFAULT TRUE,
  can_add_recipes BOOLEAN NOT NULL DEFAULT TRUE,
  status          TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','suspended')),
  iva             NUMERIC(5,2) NOT NULL DEFAULT 10,
  fc_target       NUMERIC(5,2) NOT NULL DEFAULT 30,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE memberships (
  user_id   UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  role      TEXT NOT NULL CHECK (role IN ('client_admin','viewer')),
  PRIMARY KEY (user_id, tenant_id)
);
CREATE INDEX memberships_tenant_idx ON memberships(tenant_id);

-- tenant_id NULL = elenco globale gestito dal super amministratore (tipi di attività)
CREATE TABLE lists (
  id        BIGSERIAL PRIMARY KEY,
  tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
  kind      TEXT NOT NULL CHECK (kind IN ('reparti','fornitori','tipologie','tipiAttivita')),
  value     TEXT NOT NULL
);
CREATE UNIQUE INDEX lists_uniq ON lists (COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid), kind, value);

CREATE TABLE foods (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id  UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name       TEXT NOT NULL,
  category   TEXT NOT NULL DEFAULT '',
  supplier   TEXT NOT NULL DEFAULT '',
  unit       TEXT NOT NULL DEFAULT 'kg' CHECK (unit IN ('kg','lt','pz','conf')),
  pack_qty   NUMERIC(12,3),
  pack_unit  TEXT NOT NULL DEFAULT 'g' CHECK (pack_unit IN ('g','ml','pz')),
  price_mode TEXT NOT NULL DEFAULT 'max' CHECK (price_mode IN ('min','avg','max','last')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX foods_tenant_idx ON foods(tenant_id);
CREATE UNIQUE INDEX foods_name_uniq ON foods (tenant_id, lower(name));

CREATE TABLE food_prices (
  id      BIGSERIAL PRIMARY KEY,
  food_id UUID NOT NULL REFERENCES foods(id) ON DELETE CASCADE,
  date    DATE NOT NULL,
  price   NUMERIC(12,4) NOT NULL CHECK (price > 0)
);
CREATE INDEX food_prices_food_idx ON food_prices(food_id);

CREATE TABLE recipes (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name         TEXT NOT NULL,
  type         TEXT NOT NULL DEFAULT '',
  portions     NUMERIC(10,3) NOT NULL DEFAULT 1,
  yield_g      NUMERIC(12,3),           -- resa totale in grammi (facoltativa, per usarla come ingrediente)
  price        NUMERIC(10,2),
  sold         NUMERIC(12,2),
  prep_time    NUMERIC(8,2),
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX recipes_tenant_idx ON recipes(tenant_id);

-- Ogni riga è un alimento (food_id) oppure un'altra ricetta usata come ingrediente (sub_recipe_id)
CREATE TABLE recipe_rows (
  id            BIGSERIAL PRIMARY KEY,
  recipe_id     UUID NOT NULL REFERENCES recipes(id) ON DELETE CASCADE,
  food_id       UUID REFERENCES foods(id) ON DELETE SET NULL,
  sub_recipe_id UUID REFERENCES recipes(id) ON DELETE SET NULL,
  label         TEXT NOT NULL DEFAULT '',  -- nome scritto dall'utente (resta se l'alimento viene eliminato)
  qty           NUMERIC(12,3),
  waste_pct     NUMERIC(5,2),
  position      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX recipe_rows_recipe_idx ON recipe_rows(recipe_id);
CREATE INDEX recipe_rows_sub_idx ON recipe_rows(sub_recipe_id);

CREATE TABLE login_attempts (
  key        TEXT PRIMARY KEY,
  count      INTEGER NOT NULL DEFAULT 0,
  first_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO lists (tenant_id, kind, value)
SELECT NULL, 'tipiAttivita', v FROM unnest(ARRAY['Ristorante','Pizzeria','Ristorante-pizzeria','Pizzeria al taglio','Trattoria','Pub','Bar','Gelateria','Pasticceria','Panificio','Hotel / ristorante','Catering','Altro']) AS v;
