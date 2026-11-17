// Event-loop test (L117): while a Node HTTP request to the blackhole is
// pending (connect stays pending), a setInterval ticks every 10 ms and a
// request to the listener completes. PASS only if the interval never
// stalls (no gap over 100 ms) while the blackhole request is pending.
// Args: LISTEN_URL BLACKHOLE_URL
const [listenUrl, blackholeUrl] = process.argv.slice(2);
let maxGap = 0;
let last = Date.now();
let done = false;
const ticker = setInterval(() => {
  const now = Date.now();
  const gap = now - last;
  if (gap > maxGap) maxGap = gap;
  last = now;
}, 10);
let listenOk = false;
let blackholeEnded = false;
const finish = () => {
  if (!done || blackholeEnded) return;
  blackholeEnded = true;
  clearInterval(ticker);
  if (listenOk && maxGap <= 100) {
    console.log('NODE-OK max-gap-ms ' + maxGap);
    process.exit(0);
  }
  console.log('FAIL: node listener=' + listenOk + ' max-gap=' + maxGap);
  process.exit(1);
};
fetch(listenUrl).then((res) => {
  if (res.status === 200 && res.ok) listenOk = true;
}).catch(() => {}).finally(() => { done = true; setTimeout(finish, 50); });
fetch(blackholeUrl).then(() => {}).catch(() => {}).finally(() => { setTimeout(finish, 2000); });
setTimeout(finish, 15000);
