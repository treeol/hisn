// Real-network step (L118): fetch(URL) through the open-mode
// interception. Arg: URL. Prints one line, NODE-REAL-OK or FAIL:.
'use strict';
const url = process.argv[2];
if (typeof fetch !== 'function') {
  console.log('FAIL: node fetch: this node (' + process.version +
      ') has no fetch()');
  process.exit(1);
}
fetch(url, {redirect: 'manual'}).then((res) => {
  if (res.status >= 200 && res.status < 400) {
    console.log('NODE-REAL-OK fetch(' + url + ') status ' + res.status +
        ', node ' + process.version);
    process.exit(0);
  }
  console.log('FAIL: node fetch(' + url + '): status ' + res.status);
  process.exit(1);
}).catch((e) => {
  const cause = e && e.cause ? ' (' + (e.cause.code || e.cause.message) + ')' :
      '';
  console.log('FAIL: node fetch(' + url + '): ' + (e && e.message) + cause);
  process.exit(1);
});
