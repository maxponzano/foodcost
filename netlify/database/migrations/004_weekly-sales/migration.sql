-- vendite settimanali (settimane ISO: period = lunedì della settimana) accanto a quelle mensili (period = giorno 1)
ALTER TABLE tenants ADD COLUMN sales_grain CHAR(1) NOT NULL DEFAULT 'M' CHECK (sales_grain IN ('M','W'));

ALTER TABLE sales ADD COLUMN grain CHAR(1) NOT NULL DEFAULT 'M' CHECK (grain IN ('M','W'));
ALTER TABLE sales DROP CONSTRAINT IF EXISTS sales_period_check;
ALTER TABLE sales ADD CONSTRAINT sales_period_grain_check CHECK (
  (grain = 'M' AND EXTRACT(DAY FROM period) = 1) OR (grain = 'W' AND EXTRACT(ISODOW FROM period) = 1));
ALTER TABLE sales DROP CONSTRAINT sales_pkey;
ALTER TABLE sales ADD PRIMARY KEY (recipe_id, grain, period);
