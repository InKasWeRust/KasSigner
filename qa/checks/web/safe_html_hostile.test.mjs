import assert from 'node:assert/strict';
import { escapeMarkupAsLiteral } from '../../../apps/kassee-web/web/js/core/security/safe_html.js';
for (const hostile of [
  '<img src=x onerror=alert(1)>',
  '<style>body{display:none}</style>',
  '<b>fake balance</b>',
]) {
  const rendered = escapeMarkupAsLiteral(hostile);
  assert.ok(rendered.includes('&lt;'), `opening tag must be literal: ${hostile}`);
  assert.ok(rendered.includes('&gt;'), `closing delimiter must be literal: ${hostile}`);
  assert.ok(!/<(?:img|style|b)\b/i.test(rendered), `hostile markup must not remain parseable: ${rendered}`);
}
console.log('PASS: hostile img/style/b values are encoded as literal text rather than DOM markup');
