import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { marked } from "marked";

const server = new Server({ name: "md", version: "1.0.0" });

server.setRequestHandler("tools/call", async (req) => {
  const html = marked.parse(req.params.arguments.source as string);
  return { content: [{ type: "text", text: html as string }] };
});
