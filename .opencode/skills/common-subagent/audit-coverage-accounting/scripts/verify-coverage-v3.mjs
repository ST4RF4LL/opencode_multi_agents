#!/usr/bin/env node

import { main } from "./verify-coverage-v3-core.mjs";

main().catch(error => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});
