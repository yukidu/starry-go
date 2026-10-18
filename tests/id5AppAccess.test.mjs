import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
const read=path=>readFileSync(new URL('../'+path,import.meta.url),'utf8');
const policy=read('src/centralAppAccess.ts');
const sso=read('src/starrySso.ts');
const wrapper=read('src/ecosystemSso.ts');
test('central D1 grants override legacy and new members need approval',()=>{
  assert.match(policy,/starry_app_access_decisions/);
  assert.match(policy,/row\.decision==='deny'/);
  assert.match(policy,/row\.decision==='allow'/);
  assert.match(policy,/STARRY_APP_GRANT_CUTOFF/);
  assert.match(policy,/row\.membershipStatus && row\.membershipStatus!=='active'/);
});
test('Go checks fresh and existing member sessions without blocking public shortlinks',()=>{
  assert.match(sso,/checkCentralAppEntitlement\(env\.STARRY_ID_DB,member\.id,APP_ID\)/);
  assert.match(wrapper,/getUserFromRequest\(request,env\)/);
  assert.match(wrapper,/url\.pathname==='\/' \|\| url\.pathname\.startsWith\('\/api\/'\)/);
  assert.match(wrapper,/APP_ACCESS_DENIED/);
  assert.match(wrapper,/您沒有使用權限/);
  assert.doesNotMatch(wrapper,/path\.startsWith\('\/s\/'\)/);
});
