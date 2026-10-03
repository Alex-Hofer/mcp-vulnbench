import { exec } from "node:child_process";
import { readFileSync } from "node:fs";
import { Server } from "@modelcontextprotocol/sdk/server/index.js"; // type: @modelcontextprotocol/sdk.Server '@modelcontextprotocol/sdk/server/index.js' Member[Server].Instance
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { CallToolRequestSchema, GetPromptRequestSchema, ReadResourceRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const server = new Server({ name: "fixture", version: "1.0.0" }, { capabilities: { tools: {} } });

// model: @modelcontextprotocol/sdk.Server Member[setRequestHandler].Argument[1].Parameter[0].Member[params]
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  if (name === "exec") {
    exec(String(args?.command)); // expect: js/command-line-injection
  }
  return { content: [] };
});

server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
  const text = readFileSync(request.params.uri.replace("file://", ""), "utf8"); // expect: js/path-injection
  return { contents: [{ uri: request.params.uri, text }] };
});

server.setRequestHandler(GetPromptRequestSchema, async (request) => {
  const response = await fetch(String(request.params.arguments?.url)); // expect: js/request-forgery
  return { messages: [{ role: "user", content: { type: "text", text: await response.text() } }] };
});

// the low-level server inside the high-level one
const high = new McpServer({ name: "fixture", version: "1.0.0" });
high.server.setRequestHandler(CallToolRequestSchema, async (request) => { // type: @modelcontextprotocol/sdk.Server @modelcontextprotocol/sdk.McpServer Member[server]
  exec(String(request.params.arguments?.command)); // expect: js/command-line-injection
  return { content: [] };
});
