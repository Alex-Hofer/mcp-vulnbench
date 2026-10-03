import { execSync } from "node:child_process";

export function runShell(cmd: string): string {
  return execSync(cmd, { encoding: "utf8" }); // expect: js/command-line-injection
}
