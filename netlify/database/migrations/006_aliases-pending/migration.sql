-- finora le voci non abbinate venivano salvate come "da ignorare" senza che nessuno l'avesse deciso:
-- le tolgo, così alla prossima importazione tornano "da assegnare". Da ora si salva come ignorata solo una scelta esplicita.
DELETE FROM sales_aliases WHERE recipe_id IS NULL;
