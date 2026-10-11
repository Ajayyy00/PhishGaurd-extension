const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const path=require('node:path');
const {webcrypto}=require('node:crypto');
function environment(){
  let now=0;
  const data={},session={};const id='a'.repeat(32);
  const event={addListener(){}};
  const storage=(values)=>({async get(keys){return Object.fromEntries(keys.filter(k=>k in values).map(k=>[k,values[k]]));},async set(items){Object.assign(values,items);},async setAccessLevel(){}});
  const chrome={runtime:{id,getURL:p=>'chrome-extension://'+id+'/'+p,onInstalled:event,onMessage:event},storage:{local:storage(data),session:storage(session)},webNavigation:{onBeforeNavigate:event,onHistoryStateUpdated:event},tabs:{onRemoved:event,async get(){return {url:'https://example.com/'};}}};
  // Minimal asynchronous store double; real IndexedDB isolation is checked in Chromium.
  const indexedDB={open(){const request={};setTimeout(()=>{request.result={transaction(){const item={result:undefined};const tx={objectStore(){return {get(){setTimeout(()=>tx.oncomplete(),0);return item;},put(v){item.result=v;setTimeout(()=>tx.oncomplete(),0);return item;}};}};return tx;},close(){}};request.onsuccess();},0);return request;}};
  const context=vm.createContext({chrome,indexedDB,console,URL,URLSearchParams,crypto:webcrypto,AbortController,setTimeout,clearTimeout,Date:{now:()=>now},fetch:async()=>{throw new Error('offline');},importScripts(){}});
  vm.runInContext(fs.readFileSync(path.join(__dirname,'../extension/shared/risk.js'),'utf8'),context);
  vm.runInContext(fs.readFileSync(path.join(__dirname,'../extension/background/background.js'),'utf8'),context);
  return {run:code=>vm.runInContext(code,context),data,session,tick:ms=>now+=ms};
}
test('Canonical JavaScript risk boundaries and HTML escaping',()=>{
  const {run}=environment();
  for(const [score,level] of [[0,'safe'],[30,'safe'],[31,'suspicious'],[70,'suspicious'],[71,'dangerous'],[100,'dangerous']])assert.equal(run(`PhishGuardRisk.level(${score})`),level);
  assert.equal(run('PhishGuardRisk.level(0,true)'),'unknown');
  for(const invalid of ['NaN','Infinity','-1','101','null','true'])assert.equal(run(`PhishGuardRisk.validScore(${invalid})`),false);
  assert.equal(run('PhishGuardRisk.escapeHtml("<img> & \\\"x\\\"")'),'&lt;img&gt; &amp; &quot;x&quot;');
  assert.equal(run('PhishGuardRisk.httpUrl("javascript:alert(1)")'),null);
});
test('Bounded URL cache, LRU, exact TTL and full-stage isolation',()=>{
  const {run,tick}=environment();
  run('cacheAnalysis("a",{value:1});cacheAnalysis("b",{value:2})');
  assert.equal(run('getCachedAnalysis("a").value'),1);
  run('for(let i=0;i<99;i++)cacheAnalysis("u"+i,{value:i})');
  assert.equal(run('urlCache.size'),100);assert.equal(run('getCachedAnalysis("b")'),null);
  tick(300000);assert.equal(run('getCachedAnalysis("a")'),null);
  assert.equal(run('state.analysisCache.size'),0);
});
test('Untrusted settings/bypass and token disclosure are rejected',async()=>{
  const {run,data}=environment();await run('ready');
  data.apiToken='private-token';
  assert.equal((await run('getSettings()')).apiToken,undefined);
  assert.equal((await run('handleMessage({type:"UPDATE_SETTINGS",settings:{enabled:false}},{id:chrome.runtime.id,url:"https://example.com/",tab:{id:1}})')).error,'Not authorized');
  assert.equal((await run('handleMessage({type:"BYPASS_WARNING",url:"https://other.test/"},{id:chrome.runtime.id,url:"https://example.com/",tab:{id:1}})')).error,'Invalid bypass target');
  for(const endpoint of ['https://attacker.example/api/analyze','http://127.0.0.1.evil.test/api/analyze','http://a@127.0.0.1/api/analyze','http://localhost/api/analyze?secret=x'])assert.equal(run(`validEndpoint(${JSON.stringify(endpoint)})`),false);
});
test('Temporary bypass expires, and offline fallback is never ML-safe',async()=>{
  const {run,tick}=environment();await run('ready');
  await run('handleBypassWarning("https://example.com/")');assert(run('isBypassed("https://example.com/")'));
  tick(30*60000);assert.equal(run('isBypassed("https://example.com/")'),false);
  const a=await run('analyzeUrlQuick("https://example.com/")');assert(a.degraded);assert.equal(a.riskLevel,'unknown');assert.equal(a.nlpRisk,null);
  assert.equal(run('urlCache.size'),0);
});
test('Malformed API detector scores cannot render as successful ML',()=>{
  const {run}=environment();
  assert.throws(()=>run('normalizeResult("https://a",{url:"https://a",final_score:0,url_risk:0,nlp_risk:"0",dom_risk:null,detectors:{},analysis_stage:"full",explanations:[]})'),/Malformed/);
});
test('Degraded tab result expires quickly so recovery is retried',async()=>{
  const {run,tick}=environment();await run('ready');
  run('state.analysisCache.set(1,{url:"https://example.com/",timestamp:0,degraded:true})');
  assert.equal((await run('handleGetCurrentAnalysis(1)')).degraded,true);
  tick(5000);assert((await run('handleGetCurrentAnalysis(1)')).error);
});
test('Warning distinguishes URL-only from combined scores and labels fallback',()=>{
  const {run}=environment();
  const url=new URL(run('buildWarningUrl("https://example.com/",{urlRisk:90,finalScore:90,riskLevel:"dangerous",analysisStage:"url_only"})'));
  assert.equal(url.searchParams.get('basis'),'url');
  const full=new URL(run('buildWarningUrl("https://example.com/",{urlRisk:20,finalScore:80,riskLevel:"dangerous",analysisStage:"full"})'));
  assert.equal(full.searchParams.get('basis'),'combined');assert.equal(full.searchParams.get('score'),'80');
  const fallback=new URL(run('buildWarningUrl("https://example.com/",{urlRisk:85,finalScore:85,riskLevel:"dangerous",analysisStage:"url_only",degraded:true})'));
  assert(fallback.searchParams.get('reasons').includes('Reduced protection'));
});
