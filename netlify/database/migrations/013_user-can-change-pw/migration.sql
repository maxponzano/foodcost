-- Se false la persona non può cambiarsi la password (la gestisce il super admin, es. utente demo)
ALTER TABLE users ADD COLUMN can_change_pw BOOLEAN NOT NULL DEFAULT true;
