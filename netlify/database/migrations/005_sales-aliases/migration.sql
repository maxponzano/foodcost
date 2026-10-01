-- abbinamenti nome in cassa → ricetta, ricordati per le importazioni successive (recipe_id NULL = da ignorare)
CREATE TABLE sales_aliases (
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  cash_name TEXT NOT NULL,
  recipe_id UUID REFERENCES recipes(id) ON DELETE CASCADE,
  PRIMARY KEY (tenant_id, cash_name)
);
