import { Server } from "@modelcontextprotocol/sdk/server/index.js";
const server = new Server({ name: "color", version: "1.0.0" });
server.setRequestHandler("tools/call", async (req) => {
  const hex = req.params.arguments.hex as string;
  const r = parseInt(hex.slice(1, 3), 16);
  return { content: [{ type: "text", text: JSON.stringify({ r }) }] };
});
