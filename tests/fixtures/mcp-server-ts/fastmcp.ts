import { exec } from "node:child_process";
import { readFileSync } from "node:fs";
import { FastMCP } from "fastmcp"; // type: fastmcp.FastMCP fastmcp Member[FastMCP].Instance
import { z } from "zod";

const server = new FastMCP({ name: "fixture", version: "1.0.0" });

// model: fastmcp.FastMCP Member[addTool].Argument[0].Member[execute].Parameter[0]
server.addTool({
  name: "run",
  description: "Run a command",
  parameters: z.object({ command: z.string() }),
  execute: async (args) => {
    exec(args.command); // expect: js/command-line-injection
    return "ok";
  },
});

// model: fastmcp.FastMCP Member[addResourceTemplate,addPrompt].Argument[0].Member[load].Parameter[0]
server.addResourceTemplate({
  uriTemplate: "note://{name}",
  name: "note",
  arguments: [{ name: "name", required: true }],
  async load({ name }) {
    return { text: readFileSync(`/notes/${name}`, "utf8") }; // expect: js/path-injection
  },
});

server.addPrompt({
  name: "page",
  arguments: [{ name: "url", required: true }],
  load: async (args) => {
    const response = await fetch(args.url as string); // expect: js/request-forgery
    return await response.text();
  },
});
