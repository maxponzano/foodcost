-- Un piatto può essere escluso dal calcolo delle medie di categoria (Marginalità)
ALTER TABLE recipes ADD COLUMN in_avg BOOLEAN NOT NULL DEFAULT TRUE;
