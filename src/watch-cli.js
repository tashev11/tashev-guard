import { runWatch } from "./watch.js";

// One headless check for servers and cron: `npm run watch`,
// `node src/watch-cli.js` or `node src/watch-cli.js --reset-baseline`.
try {
  process.exitCode = await runWatch({ argv: process.argv.slice(2) });
} catch (error) {
  console.error("Tashev Guard: проверка не завершена: " + (error?.stack || error));
  process.exitCode = 1;
}
