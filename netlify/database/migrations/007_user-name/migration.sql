-- nome e cognome della persona (facoltativo)
ALTER TABLE users ADD COLUMN full_name TEXT NOT NULL DEFAULT '';
