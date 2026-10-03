import { exec, execSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { McpServer, ResourceTemplate } from "@modelcontextprotocol/sdk/server/mcp.js"; // type: @modelcontextprotocol/sdk.McpServer '@modelcontextprotocol/sdk/server/mcp.js' Member[McpServer].Instance
import { z } from "zod";

import { runShell } from "./helpers";

const server = new McpServer({ name: "fixture", version: "1.0.0" });

// model: @modelcontextprotocol/sdk.McpServer Member[tool,registerTool,prompt,registerPrompt].Argument[1..].Parameter[0]
server.tool("run", { command: z.string() }, async ({ command }) => {
  exec(command); // expect: js/command-line-injection
  return { content: [] };
});

server.tool("read", "Read a file", { path: z.string() }, async (args) => {
  const text = readFileSync(args.path, "utf8"); // expect: js/path-injection
  return { content: [{ type: "text", text }] };
});

server.registerTool("fetch", { inputSchema: { url: z.string() } }, async ({ url }) => {
  const response = await fetch(url); // expect: js/request-forgery
  return { content: [{ type: "text", text: await response.text() }] };
});

server.tool("shell", { cmd: z.string() }, async ({ cmd }) => {
  return { content: [{ type: "text", text: runShell(cmd) }] };
});

async function removeHandler({ target }: { target: string }) {
  execSync("rm -rf " + target); // expect: js/command-line-injection
  return { content: [] };
}
server.tool("remove", { target: z.string() }, removeHandler);

server.prompt("summarize", { expression: z.string() }, ({ expression }) => {
  const value = eval(expression); // expect: js/code-injection
  return { messages: [{ role: "user", content: { type: "text", text: String(value) } }] };
});

server.registerPrompt("explain", { argsSchema: { file: z.string() } }, ({ file }) => {
  const text = readFileSync(file, "utf8"); // expect: js/path-injection
  return { messages: [{ role: "user", content: { type: "text", text } }] };
});

// model: @modelcontextprotocol/sdk.McpServer Member[resource,registerResource].Argument[1..].Parameter[0,1]
server.resource("note", new ResourceTemplate("note://{name}", { list: undefined }), async (uri, { name }) => {
  const text = readFileSync(`/notes/${name}`, "utf8"); // expect: js/path-injection
  return { contents: [{ uri: uri.href, text }] };
});

server.registerResource("page", new ResourceTemplate("page://{host}", { list: undefined }), {}, async (uri, variables) => {
  const response = await fetch(`http://${variables.host}/`); // expect: js/request-forgery
  return { contents: [{ uri: uri.href, text: await response.text() }] };
});

// model: @modelcontextprotocol/sdk.McpServer Member[tool,registerTool,prompt,registerPrompt].Argument[1..].Parameter[1,2].Member[requestInfo].Member[headers]
server.tool("forward", { id: z.string() }, async (_args, extra) => {
  const target = extra.requestInfo?.headers["x-target"] as string;
  const response = await fetch(target); // expect: js/request-forgery
  return { content: [{ type: "text", text: await response.text() }] };
});

// model: @modelcontextprotocol/sdk.McpServer Member[tool,registerTool,prompt,registerPrompt].Argument[1..].Parameter[1,2].Member[authInfo].Member[token]
server.tool("session", { id: z.string() }, async (_args, extra) => {
  const text = readFileSync(`/sessions/${extra.authInfo?.token}`, "utf8"); // expect: js/path-injection
  return { content: [{ type: "text", text }] };
});

export function notRegistered(command: string) {
  exec(command); // not a handler: no alert
}
