/**
 * Link the engine into this package's node_modules so `tsc` resolves
 * `@guard/core` the way a published consumer resolves it — through node_modules,
 * as an external library. That matters: a path-mapped import would pull the
 * engine's sources into this package's compilation and emit a second copy of
 * them into dist/.
 *
 * `@guard/core` is an npm alias for `@sentinelreign/guard-core` (see the
 * `dependencies` block), so the emitted specifier is identical here and after
 * `npm install @sentinelreign/guard`.
 */
import { mkdirSync, symlinkSync, existsSync, rmSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const pkgRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const linkDir = resolve(pkgRoot, 'node_modules/@guard');
const link = resolve(linkDir, 'core');

mkdirSync(linkDir, { recursive: true });
if (existsSync(link)) rmSync(link, { recursive: true, force: true });
symlinkSync(resolve(pkgRoot, '../guard-core'), link, 'junction');
