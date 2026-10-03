// Toy MCP server, fixed version (test fixture of mcp-vulnbench).
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const NOTES_DIR = "/srv/notes";
const HOST_RE = /^[A-Za-z0-9.-]+$/;
const server = new McpServer({ name: "toy-server-ts", version: "1.0.1" });

function pingHost(host: string): string {
  if (!HOST_RE.test(host)) {
    throw new Error("invalid host");
  }
  return execFileSync("ping", ["-c", "1", host], { encoding: "utf8" });
}

server.tool("ping", { host: z.string() }, async ({ host }) => {
  return { content: [{ type: "text", text: pingHost(host) }] };
});

server.tool("read_note", { name: z.string() }, async ({ name }) => {
  const target = path.resolve(NOTES_DIR, name);
  if (!target.startsWith(NOTES_DIR + path.sep)) {
    throw new Error("outside the notes folder");
  }
  const text = readFileSync(target, "utf8");
  return { content: [{ type: "text", text }] };
});

await server.connect(new StdioServerTransport());
