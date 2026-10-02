-- prezzo di vendita proposto dall'import della cassa, da confermare
ALTER TABLE recipes ADD COLUMN price_check BOOLEAN NOT NULL DEFAULT FALSE;
