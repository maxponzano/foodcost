import type { Config, Context } from "@netlify/functions";
import { handle, geoText } from "../lib/app.mts";

export default async (req: Request, context: Context) => handle(req, context?.ip || "", geoText(context?.geo));

export const config: Config = {
  path: "/api/*",
};
