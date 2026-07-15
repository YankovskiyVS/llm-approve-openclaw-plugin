import { pathToFileURL } from 'node:url';
import { main } from './lib/holdout-partition-audit-cli.mjs';

function isMainModule() {
  return typeof process.argv[1] === 'string'
    && import.meta.url === pathToFileURL(process.argv[1]).href;
}

if (isMainModule()) await main();
