/* Dati di test presi dal file Excel (prezzi del 12/06/2026, quantità delle ricette).
   Prezzi di vendita, venduto e tempi sono valori di prova.
   Formato uguale al backup dell'app, così passa dalla stessa importazione. */

export const DEFAULT_LISTS = {
  reparti: ["Crostacei","Carne","Cereali","Condimenti","Farine","Formaggi","Frutta","Latte e derivati","Legumi","Olii da condimento","Ortaggi","Pesci","Salumi","Tuberi","Uova","Verdure","Pasta","Spezie","Vini","Dolci"],
  tipologie: ["INSALATONE","ANTIPASTI","PRIMI","SECONDI","CONTORNI","DOLCI","PIZZE BASILICO","PIZZE CLASSICHE","FOCACCE","PIZZE SEMPLICI","I NS FRITTI","PREPARATI","FUORI MENU"],
};

export function demoData() {
  const F: [string, string, number][] = [
    ["pomodorini","Ortaggi",3.59],["mozzarella cucina","Formaggi",6.5],["carote","Ortaggi",1.39],["mais","Verdure",4.23],["tonno","Pesci",6.85],["insalata","Verdure",11.47],
    ["bresaola","Salumi",26.08],["rucola","Verdure",7.92],["grana a scaglie","Formaggi",13.5],["mandilli","Pasta",3.39],["pesto","Condimenti",20.83],["pollo","Carne",10.9],
    ["melanzane","Ortaggi",2.2],["zucchine","Ortaggi",1.28],["peperoni","Ortaggi",2.49],["mozzarella di bufala","Formaggi",9.9],["burrata","Formaggi",12.49],["prosciutto crudo","Salumi",17.89],
    ["farina","Farine",0.91],["lievito","Farine",8.8],["acqua","Condimenti",0.0025],["olio extravergine","Olii da condimento",5.19],["sale fino","Spezie",0.3],
    ["mozzarella julienne","Formaggi",9.22],["pomodoro","Ortaggi",1.35],
  ];
  const foods = F.map((x, i) => ({
    id: "f" + i, name: x[0], category: x[1], supplier: "", unit: "kg", mode: "max", packQty: "", packUnit: "g",
    history: [{ date: "2026-06-12", price: x[2] }],
  }));
  const fid = (n: string) => foods.find((f) => f.name === n)!.id;
  let rn = 0;
  const R = (name: string, type: string, ing: [string, number][], extra: Record<string, unknown> = {}) => ({
    id: "r" + rn++, name, type, portions: 1, price: "", sold: "", time: "", yieldG: "",
    rows: ing.map((i) => ({ foodId: fid(i[0]), subId: "", name: i[0], qty: i[1], waste: "" })),
    ...extra,
  });
  const recipes = [
    R("CLASSICA","INSALATONE",[["pomodorini",50],["mozzarella cucina",50],["carote",10],["mais",25],["tonno",40],["insalata",40]],{price:10,sold:106,time:8}),
    R("BRESAOLA RUCOLA E GRANA","ANTIPASTI",[["bresaola",100],["rucola",25],["grana a scaglie",20]],{price:12,sold:60,time:5}),
    R("CRUDO E BUFALA","ANTIPASTI",[["prosciutto crudo",100],["mozzarella di bufala",125]],{price:13,sold:45,time:4}),
    R("MANDILLI AL PESTO","PRIMI",[["mandilli",150],["pesto",70]],{price:11,sold:90,time:10}),
    R("FILETTO DI POLLO","SECONDI",[["pollo",200],["rucola",20],["grana a scaglie",40],["pomodorini",40]],{price:14,sold:40,time:15}),
    R("VERDURE GRIGLIATE","CONTORNI",[["melanzane",75],["zucchine",50],["peperoni",100]],{price:6,sold:70,time:12}),
    R("PALLINA","PREPARATI",[["farina",1000],["lievito",0.5],["acqua",500],["olio extravergine",100],["sale fino",25]],{yieldG:1625}),
  ];
  const pallina = recipes[recipes.length - 1];
  const margherita = R("MARGHERITA","PIZZE SEMPLICI",[["mozzarella julienne",120],["pomodoro",100]],{price:7,sold:220,time:6});
  margherita.rows.unshift({ foodId: "", subId: pallina.id, name: "PALLINA", qty: 200, waste: "" });
  recipes.push(margherita);
  return { iva: 10, fcTarget: 30, lists: { ...DEFAULT_LISTS, fornitori: [] as string[] }, foods, recipes };
}
