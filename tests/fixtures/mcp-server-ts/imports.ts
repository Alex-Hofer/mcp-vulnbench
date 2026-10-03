import { exec } from "node:child_process";
import { McpServer as NoSuffix } from "@modelcontextprotocol/sdk/server/mcp"; // type: @modelcontextprotocol/sdk.McpServer @modelcontextprotocol/sdk/server/mcp Member[McpServer].Instance
import { Server as NoSuffixServer } from "@modelcontextprotocol/sdk/server/index"; // type: @modelcontextprotocol/sdk.Server @modelcontextprotocol/sdk/server/index Member[Server].Instance
import { McpServer as Typed } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const { McpServer: Required } = require("@modelcontextprotocol/sdk/server/mcp.js");

new NoSuffix({ name: "a", version: "1" }).tool("a", { command: z.string() }, async ({ command }) => {
  exec(command); // expect: js/command-line-injection
  return { content: [] };
});

new Required({ name: "b", version: "1" }).tool("b", { command: z.string() }, async ({ command }: { command: string }) => {
  exec(command); // expect: js/command-line-injection
  return { content: [] };
});

new NoSuffixServer({ name: "c", version: "1" }).setRequestHandler({}, async (request: any) => {
  exec(request.params.arguments.command); // expect: js/command-line-injection
  return { content: [] };
});

// a server that arrives as a typed parameter
export function registerTools(server: Typed) { // type: @modelcontextprotocol/sdk.McpServer '@modelcontextprotocol/sdk/server/mcp.js'.McpServer
  server.tool("d", { command: z.string() }, async ({ command }) => {
    exec(command); // expect: js/command-line-injection
    return { content: [] };
  });
}
