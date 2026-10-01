-- Vendite mensili per piatto (storico). Il mese è salvato come primo giorno del mese.
CREATE TABLE sales (
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  recipe_id UUID NOT NULL REFERENCES recipes(id) ON DELETE CASCADE,
  period    DATE NOT NULL CHECK (EXTRACT(DAY FROM period) = 1),
  qty       NUMERIC(12,2) NOT NULL CHECK (qty >= 0),
  source    TEXT NOT NULL DEFAULT 'manuale',   -- in futuro: 'cassa' per gli import dal registratore
  PRIMARY KEY (recipe_id, period)
);
CREATE INDEX sales_tenant_period_idx ON sales(tenant_id, period);

-- Il "venduto" già inserito diventa il primo periodo: settembre 2026
INSERT INTO sales (tenant_id, recipe_id, period, qty)
SELECT tenant_id, id, DATE '2026-09-01', sold FROM recipes WHERE sold > 0;
