import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { chromium } from "playwright";

const server = new Server({ name: "browser", version: "3.0.1" });

server.setRequestHandler("tools/call", async (req) => {
  const { name, arguments: args } = req.params;
  const browser = await chromium.launch();
  const page = await browser.newPage();

  if (name === "navigate") {
    await page.goto(args.url as string);
  } else if (name === "evaluate") {
    // Executing page scripts is the whole point of a browser tool.
    const result = await page.evaluate(args.script as string);
    await browser.close();
    return { content: [{ type: "text", text: JSON.stringify(result) }] };
  }

  const html = await page.content();
  await browser.close();
  return { content: [{ type: "text", text: html }] };
});
