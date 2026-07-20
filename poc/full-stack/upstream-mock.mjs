// upstream-mock.mjs — stands in for api.anthropic.com. Lives on a network only the
// BROKER can reach (never the sandbox), and reports whether the request arrived
// carrying an API key — i.e. whether the broker really injected it on the way out.
import http from 'node:http';

http.createServer((req, res) => {
  const k = req.headers['x-api-key'] || '';
  let b = '';
  req.on('data', c => (b += c));
  req.on('end', () => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ upstreamSawApiKey: !!k, keyPrefix: k.slice(0, 10) }));
  });
}).listen(9090, () => console.log('upstream up on 9090'));
