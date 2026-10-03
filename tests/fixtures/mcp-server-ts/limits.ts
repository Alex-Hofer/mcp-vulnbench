import { exec } from "node:child_process";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "fixture", version: "1.0.0" });

// tools kept in a table and registered in a loop: the handler reaches tool() through an array
const tools = [
  {
    name: "table",
    schema: { command: z.string() },
    handler: async ({ command }: { command: string }) => {
      exec(command); // known-miss: js/command-line-injection
      return { content: [] };
    },
  },
];
for (const tool of tools) {
  server.tool(tool.name, tool.schema, tool.handler);
}

// a method handed over with bind()
class Tools {
  async run({ command }: { command: string }) {
    exec(command); // known-miss: js/command-line-injection
    return { content: [] };
  }

  register(target: McpServer) {
    target.tool("bound", { command: z.string() }, this.run.bind(this));
  }
}
new Tools().register(server);
