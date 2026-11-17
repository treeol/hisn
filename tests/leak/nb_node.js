// Node event-loop case (L117). Args: LISTENER_URL BLACKHOLE_URL
//
// A setInterval ticks every 10 ms. One HTTP request goes to the
// blackhole (its connect never completes) and one to the listener.
// For WINDOW_MS the script records the largest gap between two ticks.
// PASS (exit 0, one line starting with NODE-OK): the listener request
// completed with status 200 and the expected body, the blackhole
// request is still pending at the end of the window, and no gap between
// ticks is above 100 ms. Otherwise one line starting with FAIL:.
'use strict';
const http = require('http');
const {performance} = require('perf_hooks');

const [listenerUrl, blackholeUrl] = process.argv.slice(2);
const WINDOW_MS = 2000;
const MAX_GAP_MS = 100;

let ticks = 0;
let maxGap = 0;
let last = performance.now();
const ticker = setInterval(() => {
  const now = performance.now();
  maxGap = Math.max(maxGap, now - last);
  last = now;
  ticks += 1;
}, 10);

let blackholeState = 'pending';
const blackhole = http.get(blackholeUrl, (res) => {
  blackholeState = 'answered ' + res.statusCode;
  res.resume();
});
blackhole.on('error', (e) => {
  if (blackholeState === 'pending') blackholeState = 'error ' + e.code;
});

let listener = 'no answer';
let listenerMs = -1;
const started = performance.now();
http.get(listenerUrl, (res) => {
  let body = '';
  res.setEncoding('utf8');
  res.on('data', (chunk) => { body += chunk; });
  res.on('end', () => {
    listener = res.statusCode + ' ' + body;
    listenerMs = performance.now() - started;
  });
}).on('error', (e) => { listener = 'error ' + e.code; });

setTimeout(() => {
  clearInterval(ticker);
  const pending = blackholeState;
  blackhole.destroy();
  const detail = 'listener=[' + listener + '] after ' + listenerMs.toFixed(1) +
      ' ms, blackhole=' + pending + ', ticks=' + ticks + ' in ' + WINDOW_MS +
      ' ms, max-gap-ms=' + maxGap.toFixed(1) + ', node ' + process.version;
  const ok = listener === '200 HERMETIC-OK' && pending === 'pending' &&
      maxGap <= MAX_GAP_MS && ticks >= WINDOW_MS / 10 / 2;
  console.log((ok ? 'NODE-OK ' : 'FAIL: node event loop: ') + detail);
  process.exit(ok ? 0 : 1);
}, WINDOW_MS);
