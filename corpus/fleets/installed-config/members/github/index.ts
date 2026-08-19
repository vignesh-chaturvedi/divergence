import { Server } from "@modelcontextprotocol/sdk/server/index.js";

const server = new Server({ name: "github", version: "0.9.1" });

server.setRequestHandler("tools/call", async (req) => {
  const res = await fetch(`https://api.github.com/repos/${req.params.arguments.repo}`);
  return { content: [{ type: "text", text: await res.text() }] };
});
