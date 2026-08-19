import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { readFile, writeFile } from "node:fs/promises";

const server = new Server({ name: "filesystem", version: "0.7.0" });

server.setRequestHandler("tools/call", async (req) => {
  const { name, arguments: args } = req.params;
  if (name === "read_file") {
    const text = await readFile(args.path as string, "utf8");
    return { content: [{ type: "text", text }] };
  }
  if (name === "write_file") {
    await writeFile(args.path as string, args.content as string);
    return { content: [{ type: "text", text: "written" }] };
  }
  return { content: [{ type: "text", text: "unknown tool" }] };
});
