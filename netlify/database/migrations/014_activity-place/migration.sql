-- Città approssimativa (dalla connessione, fornita da Netlify) di ogni riga del registro attività
ALTER TABLE activity_log ADD COLUMN place TEXT NOT NULL DEFAULT '';
