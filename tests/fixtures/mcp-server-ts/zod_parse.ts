import { exec } from "node:child_process";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { z as z3 } from "zod/v3"; // type: zod zod/v3
import * as z4 from "zod/v4"; // type: zod zod/v4

import { SharedSchema } from "./helpers";

// Low-level handlers receive the raw arguments and validate them with a zod schema first. CodeQL
// does not know zod, so without the summaries the taint ends at the parse call.
const RunSchema = z.object({ command: z.string() });
const StrictSchema = z.object({ command: z.string().min(1) }).strict();
const LegacySchema = z3.object({ command: z3.string() });
const NextSchema = z4.object({ command: z4.string() });

const server = new Server({ name: "fixture", version: "1.0.0" }, { capabilities: { tools: {} } });
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  // summary: zod Fuzzy.Member[parse] Argument[0] ReturnValue
  if (name === "parse") {
    const parsed = RunSchema.parse(args);
    exec(parsed.command); // expect: js/command-line-injection
  }
  if (name === "shared") {
    const parsed = SharedSchema.parse(args);
    exec(parsed.command); // expect: js/command-line-injection
  }
  if (name === "legacy") {
    exec(LegacySchema.parse(args).command); // expect: js/command-line-injection
  }
  if (name === "next") {
    exec(NextSchema.parse(args).command); // expect: js/command-line-injection
  }
  // summary: zod Fuzzy.Member[safeParse] Argument[0] ReturnValue.Member[data]
  if (name === "safeParse") {
    const parsed = StrictSchema.safeParse(args);
    if (!parsed.success) throw new Error("invalid arguments");
    exec(parsed.data.command); // expect: js/command-line-injection
  }
  // summary: zod Fuzzy.Member[parseAsync] Argument[0] ReturnValue.Awaited
  if (name === "parseAsync") {
    const parsed = await RunSchema.parseAsync(args);
    exec(parsed.command); // expect: js/command-line-injection
  }
  // summary: zod Fuzzy.Member[safeParseAsync] Argument[0] ReturnValue.Awaited.Member[data]
  if (name === "safeParseAsync") {
    const parsed = await RunSchema.safeParseAsync(args);
    if (parsed.success) exec(parsed.data.command); // expect: js/command-line-injection
  }
  return { content: [] };
});
