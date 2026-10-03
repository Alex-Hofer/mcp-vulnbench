import { exec } from "node:child_process";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";

const server = new McpServer({ name: "fixture", version: "1.0.0" });

// a project wrapper around the handler, as servers use for logging or error handling
function logged<T extends (...args: any[]) => any>(handler: T): T {
  return (async (...args: any[]) => handler(...args)) as T;
}

server.tool(
  "wrapped",
  { command: z.string() },
  logged(async ({ command }: { command: string }) => {
    exec(command); // expect: js/command-line-injection
    return { content: [] };
  }),
);

// handlers as methods of a class, bound when they are registered
class Tools {
  constructor(private readonly prefix: string) {}

  async run({ command }: { command: string }) {
    exec(this.prefix + command); // expect: js/command-line-injection
    return { content: [] };
  }

  register(target: McpServer) {
    target.tool("method", { command: z.string() }, (args) => this.run(args));
  }
}
new Tools("sh -c ").register(server);

// handlers looked up by tool name
const handlers: Record<string, (args: any) => unknown> = {
  run: (args) => {
    exec(args.command); // expect: js/command-line-injection
    return { content: [] };
  },
};
const mapped = new Server({ name: "fixture", version: "1.0.0" }, { capabilities: { tools: {} } });
mapped.setRequestHandler(CallToolRequestSchema, async (request) => {
  return handlers[request.params.name](request.params.arguments) as any;
});

// the usual dispatcher of low-level servers: a switch over the tool name
function handleRun(args: Record<string, unknown> | undefined) {
  exec(String(args?.command)); // expect: js/command-line-injection
  return { content: [] };
}
const low = new Server({ name: "fixture", version: "1.0.0" }, { capabilities: { tools: {} } });
low.setRequestHandler(CallToolRequestSchema, async (request) => {
  switch (request.params.name) {
    case "run":
      return handleRun(request.params.arguments);
    default:
      throw new Error("unknown tool");
  }
});
