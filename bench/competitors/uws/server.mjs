// uWebSockets.js (pinned by commit: tag v20.71.0). One process per CPU, each with its own
// listener on the shared port (uWS listens with SO_REUSEPORT on Linux), as uWS's docs suggest
// for multi-core use; Node's cluster module is not used.
// The package's ESM wrapper imports ./index.js, which this release does not ship; load the
// CommonJS entry (uws.js) instead.
import { createRequire } from 'node:module';
const uWS = createRequire(import.meta.url)('uWebSockets.js');
import { availableParallelism } from 'node:os';
import { fork } from 'node:child_process';

const port = Number(process.env.PORT || 8080);
if (process.env.UWS_WORKER === undefined) {
  const n = availableParallelism();
  for (let i = 0; i < n; i++) fork(new URL(import.meta.url).pathname, { env: { ...process.env, UWS_WORKER: String(i) } });
} else {
  uWS.App()
    .get('/*', (res) => { res.cork(() => res.writeHeader('Content-Type', 'text/plain').end('Hello, World!')); })
    .post('/echo', (res) => {
      const chunks = [];
      res.onAborted(() => {});
      res.onData((ab, last) => {
        chunks.push(Buffer.from(ab.slice(0)));
        if (last) res.cork(() => res.writeHeader('Content-Type', 'application/json').end(Buffer.concat(chunks)));
      });
    })
    .listen(port, (ok) => { if (!ok) { console.error('listen failed'); process.exit(1); } });
}
