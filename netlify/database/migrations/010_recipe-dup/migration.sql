-- Permesso facoltativo di duplicare ricette (spento di default, lo abilita il super admin)
ALTER TABLE tenants ADD COLUMN can_dup_recipes BOOLEAN NOT NULL DEFAULT false;
