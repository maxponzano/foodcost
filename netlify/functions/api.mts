import type { Config, Context } from "@netlify/functions";
import { handle } from "../lib/app.mts";

export default async (req: Request, context: Context) => handle(req, context?.ip || "");

export const config: Config = {
  path: "/api/*",
};
