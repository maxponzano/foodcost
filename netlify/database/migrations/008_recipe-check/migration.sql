-- nota "da verificare" sulla ricetta (vuota = niente da verificare)
ALTER TABLE recipes ADD COLUMN check_note TEXT NOT NULL DEFAULT '';
