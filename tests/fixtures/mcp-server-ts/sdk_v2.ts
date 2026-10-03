import { exec } from "node:child_process";
import { readFileSync } from "node:fs";
import { McpServer, ResourceTemplate, Server } from "@modelcontextprotocol/server"; // type: @modelcontextprotocol/sdk.McpServer @modelcontextprotocol/server Member[McpServer].Instance
import * as z from "zod/v4";

const server = new McpServer({ name: "fixture", version: "2.0.0" });

server.registerTool("run", { inputSchema: z.object({ command: z.string() }) }, async ({ command }) => {
  exec(command); // expect: js/command-line-injection
  return { content: [] };
});

server.registerResource("note", new ResourceTemplate("note://{name}", { list: undefined }), {}, async (uri, { name }) => {
  const text = readFileSync(`/notes/${name}`, "utf8"); // expect: js/path-injection
  return { contents: [{ uri: uri.href, text }] };
});

server.registerPrompt("page", { argsSchema: z.object({ url: z.string() }) }, async ({ url }) => {
  const response = await fetch(url); // expect: js/request-forgery
  return { messages: [{ role: "user", content: { type: "text", text: await response.text() } }] };
});

// model: @modelcontextprotocol/sdk.McpServer Member[tool,registerTool,prompt,registerPrompt].Argument[1..].Parameter[1,2].Member[http].Member[req].Member[headers].Member[get].ReturnValue
server.registerTool("forward", { inputSchema: z.object({ id: z.string() }) }, async (_args, ctx) => {
  const response = await fetch(ctx.http?.req?.headers.get("x-target") as string); // expect: js/request-forgery
  return { content: [{ type: "text", text: await response.text() }] };
});

// model: @modelcontextprotocol/sdk.McpServer Member[tool,registerTool,prompt,registerPrompt].Argument[1..].Parameter[1,2].Member[http].Member[authInfo].Member[token]
server.registerTool("session", { inputSchema: z.object({ id: z.string() }) }, async (_args, ctx) => {
  const text = readFileSync(`/sessions/${ctx.http?.authInfo?.token}`, "utf8"); // expect: js/path-injection
  return { content: [{ type: "text", text }] };
});

const low = new Server({ name: "fixture", version: "2.0.0" }); // type: @modelcontextprotocol/sdk.Server @modelcontextprotocol/server Member[Server].Instance
low.setRequestHandler("tools/call", async (request) => {
  exec(String(request.params.arguments?.command)); // expect: js/command-line-injection
  return { content: [] };
});

// model: @modelcontextprotocol/sdk.Server Member[setRequestHandler].Argument[2].Parameter[0]
low.setRequestHandler("acme/run", { params: z.object({ command: z.string() }) }, async ({ command }) => {
  exec(command); // expect: js/command-line-injection
  return {};
});
