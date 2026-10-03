// Toy MCP server with two deliberately vulnerable tools (test fixture of mcp-vulnbench).
import { execSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const NOTES_DIR = "/srv/notes";
const server = new McpServer({ name: "toy-server-ts", version: "1.0.0" });

function pingHost(host: string): string {
  return execSync(`ping -c 1 ${host}`, { encoding: "utf8" });
}

server.tool("ping", { host: z.string() }, async ({ host }) => {
  return { content: [{ type: "text", text: pingHost(host) }] };
});

server.tool("read_note", { name: z.string() }, async ({ name }) => {
  const text = readFileSync(`${NOTES_DIR}/${name}`, "utf8");
  return { content: [{ type: "text", text }] };
});

await server.connect(new StdioServerTransport());
