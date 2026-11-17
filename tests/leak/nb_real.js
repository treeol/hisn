// Real-network step (L118): node fetch("https://github.com") through the
// open-mode interception. Args: URL
const url = process.argv[2];
fetch(url).then((res) => {
  if (res.status >= 200 && res.status < 400) {
    console.log('NODE-REAL-OK ' + res.status);
    process.exit(0);
  }
  console.log('FAIL: node fetch status ' + res.status);
  process.exit(1);
}).catch((e) => {
  console.log('FAIL: node fetch ' + (e && e.message));
  process.exit(1);
});
