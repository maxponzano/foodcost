-- Diritti per persona autorizzata (prima erano per locale): si parte dalle spunte attuali del locale
ALTER TABLE memberships
  ADD COLUMN can_add_foods   BOOLEAN NOT NULL DEFAULT true,
  ADD COLUMN can_add_recipes BOOLEAN NOT NULL DEFAULT true,
  ADD COLUMN can_dup_recipes BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN can_edit        BOOLEAN NOT NULL DEFAULT true,
  ADD COLUMN can_sales       BOOLEAN NOT NULL DEFAULT true;
UPDATE memberships m SET can_add_foods=t.can_add_foods, can_add_recipes=t.can_add_recipes, can_dup_recipes=t.can_dup_recipes
  FROM tenants t WHERE t.id=m.tenant_id;
