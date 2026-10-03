import { execSync } from "node:child_process";
import { z } from "zod";

export function runShell(cmd: string): string {
  return execSync(cmd, { encoding: "utf8" }); // expect: js/command-line-injection
}

// a schema that handlers in another module parse their arguments with
export const SharedSchema = z.object({ command: z.string() });
