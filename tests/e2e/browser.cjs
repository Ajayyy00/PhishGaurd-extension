/* Actual unpacked MV3 extension, real Flask process and saved models.
 * Run: node tests/e2e/browser.cjs
 * Set PLAYWRIGHT_MODULE and CHROME_PATH if not installed in the default locations.
 * Tokens are generated in memory; profiles live outside the repository.
 */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const http = require('node:http');
const {spawn} = require('node:child_process');
const {randomBytes} = require('node:crypto');
const {chromium} = require(process.env.PLAYWRIGHT_MODULE || path.join(os.homedir(), '.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright'));
const root = path.resolve(__dirname,'../..');
const artifacts = path.join(__dirname,'artifacts');
fs.mkdirSync(artifacts,{recursive:true});
const token = randomBytes(32).toString('base64url');
const profile = fs.mkdtempSync(path.join(os.tmpdir(),'phishguard-phase1-e2e-'));
const executablePath = process.env.CHROME_PATH || path.join(os.tmpdir(),'phishguard-phase1-browser/chrome-win64/chrome.exe');
const localPython = path.join(os.homedir(),'.pyenv/pyenv-win/versions/3.11.0/python.exe');
const python = process.env.PYTHON || (fs.existsSync(localPython) ? localPython : 'python');
const extension = path.join(root,'extension');
const safeBase = 'http://fixture.github.com:8765';
const dangerBase = 'http://verify-paypal-account.xyz:8765';
const summary = {checks:[], observations:[], pageErrors:[], workerErrors:[], console:[], requests:[]};
let context,worker,backend,origin,options,fixtureServer,faultServer,fault='malformed';
let backendLog = '';
const benign = '<h1>Community Library</h1><p>Our community library provides books, reading rooms and friendly weekend events for local families.</p><button id="interact" onclick="this.textContent=\'Clicked\'">Browse books</button><main id="dynamic"></main>';
const phishing = '<h1>PayPal account verification — local simulation</h1><p>Urgent! Verify your account immediately. Your account will be closed within 24 hours. Enter your password. Confirm your identity. Claim your prize now.</p><form onsubmit="event.preventDefault()"><label>Dummy email<input type="email" name="email"></label><label>Dummy password<input type="password" name="password"></label><input name="username"><button>Demonstration only</button></form><p>No data is submitted or collected.</p>';
const sleep = ms => new Promise(r=>setTimeout(r,ms));
function clean(text) { return String(text).split(token).join('[REDACTED]').replace(/Bearer [A-Za-z0-9_-]+/g,'Bearer [REDACTED]'); }
async function until(fn,timeout=30000) {
  const end=Date.now()+timeout; let last;
  while(Date.now()<end) { try { const value=await fn(); if(value)return value; }catch(error){last=error;} await sleep(200); }
  throw new Error(`Condition timed out${last?': '+last.message:''}`);
}
async function check(name,fn) {
  const start=Date.now();
  try { const detail=await fn(); summary.checks.push({name,status:'VERIFIED',ms:Date.now()-start,detail}); console.log('PASS '+name); }
  catch(error) { summary.checks.push({name,status:'FAILED',ms:Date.now()-start,error:clean(error.stack)}); console.log('FAIL '+name+': '+error.message); }
  save();
}
function save(){fs.writeFileSync(path.join(artifacts,'browser-results.json'),JSON.stringify(summary,null,2));}
async function startBackend() {
  console.log('Starting real backend');
  backend=spawn(python,['-X','utf8','-u','tests/e2e/serve_backend.py'],{cwd:root,windowsHide:true,env:{...process.env,PHISHGUARD_API_TOKEN:token,PHISHGUARD_EXTENSION_ORIGINS:origin,PORT:'5057',FLASK_ENV:'production'}});
  const log=d=>{backendLog+=clean(d);fs.writeFileSync(path.join(artifacts,'backend-browser.log'),backendLog);};
  backend.stdout.on('data',log); backend.stderr.on('data',log);
  backend.on('error',e=>console.error('Backend launch failed: '+e.message));
  await until(async()=>{const r=await fetch('http://127.0.0.1:5057/health',{signal:AbortSignal.timeout(2000)});return r.ok;},90000);
}
async function stopBackend(){if(backend && backend.exitCode===null && backend.signalCode===null){backend.kill();await until(()=>backend.exitCode!==null||backend.signalCode!==null,20000);} }
async function launch() {
  console.log('Launching isolated Chromium');
  context=await chromium.launchPersistentContext(profile,{executablePath,headless:true,ignoreDefaultArgs:['--disable-extensions'],viewport:{width:1200,height:850},args:[`--disable-extensions-except=${extension}`,`--load-extension=${extension}`,'--no-proxy-server','--host-resolver-rules=MAP fixture.github.com 127.0.0.1, MAP verify-paypal-account.xyz 127.0.0.1, MAP xn--r8jz45g.test 127.0.0.1']});
  context.setDefaultTimeout(15000);
  console.log('Chromium started; workers='+context.serviceWorkers().length);
  const attach=p=>{
    p.on('pageerror',e=>summary.pageErrors.push(clean(e.message)));
    p.on('console',m=>{if(m.type()==='error'||m.text().includes('PhishGuard'))summary.console.push({type:m.type(),text:clean(m.text()).slice(0,400)});});
  };
  context.on('page',attach);context.pages().forEach(attach);
  context.on('response',r=>{if(r.url().startsWith('http://127.0.0.1:5057/'))summary.requests.push({path:new URL(r.url()).pathname,status:r.status(),method:r.request().method()});});
  worker=context.serviceWorkers()[0]||await context.waitForEvent('serviceworker');
  console.log('Extension worker started: '+worker.url());
  origin=new URL(worker.url()).protocol+'//'+new URL(worker.url()).host;
  options=await context.newPage();await options.goto(origin+'/options/options.html');
  const diagnostics=await context.newCDPSession(options);
  diagnostics.on('ServiceWorker.workerErrorReported',event=>summary.workerErrors.push(clean(event.errorMessage.errorMessage)));
  await diagnostics.send('ServiceWorker.enable');
  console.log('Connection options loaded');
}
const msg=(message)=>options.evaluate(message=>chrome.runtime.sendMessage(message),message);
async function settings(apiEndpoint='http://127.0.0.1:5057/api/analyze') {assert.deepEqual(await msg({type:'UPDATE_SETTINGS',settings:{apiEndpoint}}),{success:true});}
async function tabId(page){return worker.evaluate(async url=>(await chrome.tabs.query({})).find(t=>t.url===url)?.id,page.url());}
async function analysis(page,stage,timeout=35000) {
  return until(async()=>{const id=await tabId(page);const value=await msg({type:'GET_CURRENT_ANALYSIS',tabId:id});return value?.url===page.url()&&(!stage||value.analysisStage===stage)?value:false;},timeout);
}
async function go(page,url) {try{await page.goto(url,{waitUntil:'domcontentloaded',timeout:20000});}catch(e){if(!/interrupted|ERR_ABORTED/.test(e.message))throw e;}}
async function rescan(page){return worker.evaluate(async id=>chrome.tabs.sendMessage(id,{type:'RESCAN_PAGE',forceRefresh:true}),await tabId(page));}
async function screenshot(page,name){await page.screenshot({path:path.join(artifacts,name+'.png'),fullPage:true});}
let lastPopup;
async function nativePopup(cdp,targetId) {
  const {sessionId}=await cdp.send('Target.attachToTarget',{targetId,flatten:false});
  let next=0;let closed=false;const pending=new Map();
  cdp.on('Target.receivedMessageFromTarget',event=>{
    if(event.sessionId!==sessionId)return;
    const message=JSON.parse(event.message),handler=pending.get(message.id);
    if(handler){pending.delete(message.id);message.error?handler.reject(new Error(message.error.message)):handler.resolve(message.result);}
  });
  const send=(method,params={})=>new Promise((resolve,reject)=>{
    const id=++next;pending.set(id,{resolve,reject});
    cdp.send('Target.sendMessageToTarget',{sessionId,message:JSON.stringify({id,method,params})}).catch(reject);
  });
  const evaluate=async(fn,arg)=>{
    const answer=await send('Runtime.evaluate',{expression:`(${fn.toString()})(${JSON.stringify(arg)??'undefined'})`,awaitPromise:true,returnByValue:true});
    if(answer.exceptionDetails)throw new Error(answer.exceptionDetails.exception?.description||'Popup evaluation failed');
    return answer.result.value;
  };
  const panel={evaluate,locator(selector){return {
    textContent:()=>evaluate(s=>document.querySelector(s)?.textContent,selector),
    count:()=>evaluate(s=>document.querySelectorAll(s).length,selector),
    isChecked:()=>evaluate(s=>document.querySelector(s)?.checked,selector),
    click:async()=>{
      const point=await evaluate(s=>{const el=document.querySelector(s);el.scrollIntoView();const r=el.getBoundingClientRect();return {x:r.x+r.width/2,y:r.y+r.height/2};},selector);
      await send('Input.dispatchMouseEvent',{type:'mousePressed',...point,button:'left',clickCount:1});
      await send('Input.dispatchMouseEvent',{type:'mouseReleased',...point,button:'left',clickCount:1});
    },
  };},async screenshot({path:filename}){await evaluate(()=>window.scrollTo(0,0));const r=await send('Page.captureScreenshot',{format:'png',captureBeyondViewport:false});fs.writeFileSync(filename,Buffer.from(r.data,'base64'));},async close(){if(closed)return;closed=true;await send('Runtime.evaluate',{expression:'setTimeout(() => window.close(), 0)'}).catch(()=>{});await sleep(300);await cdp.detach().catch(()=>{});}};
  await until(()=>evaluate(()=>document.readyState==='complete'));
  return panel;
}
async function popup(page) {
  if(lastPopup)await lastPopup.close().catch(()=>{});
  await page.bringToFront();
  const existing=context.pages().find(p=>p.url()===origin+'/popup/popup.html');
  if(existing)await existing.close();
  await until(async()=>{
    try {
      await worker.evaluate(async url=>{
        const tab=(await chrome.tabs.query({})).find(t=>t.url===url);
        await chrome.windows.update(tab.windowId,{focused:true});
        await chrome.action.openPopup({windowId:tab.windowId});
      },page.url());
      return true;
    } catch(error) { if(!error.message.includes('Failed to open popup'))throw error; return false; }
  },5000);
  const cdp=await context.browser().newBrowserCDPSession();
  const native=await until(async()=>(await cdp.send('Target.getTargets')).targetInfos.find(t=>t.url===origin+'/popup/popup.html'),5000);
  if(native){
    summary.popupTargets=[{type:native.type,url:native.url}];summary.popupMode='Native action popup inspected with Chrome DevTools Protocol; real mouse events';
    lastPopup=await nativePopup(cdp,native.targetId);return lastPopup;
  }

}

(async()=>{
  fixtureServer=http.createServer((req,res)=>{
    if(req.url.startsWith('/redirect')){res.writeHead(302,{Location:'/benign?redirected=1'});res.end();return;}
    const p=new URL(req.url,'http://local').pathname;
    let body=p==='/login'?phishing:p==='/empty'?'':p==='/long'?'<p>'+('Community reading and gardening activities. '.repeat(4000))+'</p>':benign;
    res.writeHead(200,{'Content-Type':'text/html; charset=utf-8'});res.end('<!doctype html><html><head><meta charset="utf-8"><title>'+ (p==='/login'?'PayPal simulation':'Community Library')+'</title><style>body{font:20px system-ui;max-width:820px;margin:60px auto;line-height:1.6}input,button{display:block;padding:12px;margin:12px 0}label{display:block}</style></head><body>'+body+'</body></html>');
  }).listen(8765,'127.0.0.1');
  faultServer=http.createServer((req,res)=>{if(fault==='timeout')return;res.writeHead(200,{'Content-Type':'application/json'});res.end(JSON.stringify({final_score:'<img src=x onerror=alert(1)>'}));}).listen(5058,'127.0.0.1');
  await launch();
  summary.browser={executable:path.basename(executablePath),version:await worker.evaluate(()=>navigator.userAgent),mode:'headless persistent MV3',extensionOrigin:origin,profile:'temporary isolated profile outside repository'};
  await startBackend();
  await check('Real extension service worker, options pairing and authenticated backend',async()=>{
    await options.locator('#endpoint').fill('http://127.0.0.1:5057/api/analyze');await options.locator('#token').fill(token);
    await options.getByRole('button',{name:'Save connection'}).click();await until(async()=>(await options.locator('#status').textContent()).includes('saved'));
    await options.locator('#test-connection').click();await until(async()=>(await options.locator('#status').textContent()).includes('Connected and authenticated'));
    assert.equal((await msg({type:'GET_SETTINGS'})).apiToken,undefined);
    const response=await fetch('http://127.0.0.1:5057/api/status');assert.equal(response.status,401);
    return {serviceWorker:worker.url(),status:(await msg({type:'TEST_CONNECTION'})).models};
  });
  let safe=await context.newPage();
  await check('Benign local fixture through existing trusted-domain policy: URL then full analysis',async()=>{
    await go(safe,safeBase+'/benign');const a=await analysis(safe,'full');assert.equal(a.riskLevel,'safe');assert.equal(a.degraded,false);assert.equal(a.shouldBlock,false);
    assert(a.nlpRisk<=30);assert.equal(a.domRisk,0);await screenshot(safe,'safe-analysis');return a;
  });
  await check('Benign localhost false-positive measurement',async()=>{
    const p=await context.newPage();await go(p,'http://localhost:8765/benign');await until(()=>p.url().includes('/warning/warning.html'));
    const observed={url:'http://localhost:8765/benign',score:await p.locator('#riskScore').textContent(),outcome:'FALSE POSITIVE: trained model blocks benign local hostname'};
    summary.observations.push(observed);await p.close();return observed;
  });
  let bad=await context.newPage();
  await check('Dangerous URL redirects to warning with real model reasons and Go Back',async()=>{
    await go(bad,dangerBase+'/login');await until(()=>bad.url().includes('/warning/warning.html'));
    assert(Number(await bad.locator('#riskScore').textContent())>=50);assert((await bad.locator('#reasonsList').innerText()).length>10);
    assert.equal(await bad.locator('.risk-label').textContent(),'URL protection score');await screenshot(bad,'warning-page');
    await bad.locator('#backBtn').click();await until(()=>bad.url()==='about:blank');
  });
  await check('Proceed Anyway, bypass and real MiniLM/DOM full phishing analysis',async()=>{
    await go(bad,dangerBase+'/login');await until(()=>bad.url().includes('/warning/warning.html'));await bad.locator('#proceedBtn').click();await until(()=>bad.url()===dangerBase+'/login');
    const a=await analysis(bad,'full');assert.equal(a.detectors.nlp.status,'ok');assert.equal(a.detectors.dom.status,'ok');assert(a.suspicious_phrases.length>0);assert(a.domRisk>=70);assert(a.finalScore>70);
    await sleep(1000);assert.equal(bad.url(),dangerBase+'/login');await screenshot(bad,'suspicious-analysis');
    await bad.reload();await analysis(bad,'full');assert.equal(bad.url(),dangerBase+'/login');return a;
  });
  await check('Popup dashboard, full score/bars, rescan, toggle and reopen',async()=>{
    const a=await analysis(bad,'full');let panel=await popup(bad);
    await until(async()=>(await panel.locator('#risk-score').textContent())===String(a.finalScore));
    assert.equal(await panel.locator('#domain').textContent(),bad.url());
    assert.equal(await panel.locator('#score-nlp').textContent(),a.nlpRisk+'%');assert.equal(await panel.locator('#score-dom').textContent(),a.domRisk+'%');
    await panel.locator('#toggle-details').click();await screenshot(panel,'popup-dashboard');
    const old= (await analysis(bad)).timestamp;await panel.locator('#rescan-btn').click();await until(async()=>(await analysis(bad)).timestamp>old);
    await until(async()=>await panel.locator('#nlp-toggle').isChecked());await panel.locator('.slider').click();await until(async()=>!(await msg({type:'GET_SETTINGS'})).nlpHighlightingEnabled);
    await until(async()=>await bad.locator('.phishguard-highlight').count()===0);
    await panel.locator('.slider').click();await until(async()=>await bad.locator('.phishguard-highlight').count()>0);
    await panel.close();panel=await popup(bad);await until(async()=>await panel.locator('#nlp-toggle').isChecked());await panel.close();
  });
  await check('Dynamic text, highlighting without nesting, observer settles and interactions',async()=>{
    await safe.bringToFront();const before=(await analysis(safe)).timestamp;
    await safe.locator('#dynamic').evaluate(el=>el.textContent='Urgent! Verify your account immediately. Enter your password.');
    await until(async()=>await safe.locator('#dynamic [data-phishguard-mark]').count()>0);
    await until(async()=>(await analysis(safe)).timestamp>before);
    assert.equal(await safe.locator('[data-phishguard-mark] [data-phishguard-mark]').count(),0);
    const stamp=(await analysis(safe)).timestamp;await sleep(2000);assert.equal((await analysis(safe)).timestamp,stamp);
    await safe.locator('#interact').click();assert.equal(await safe.locator('#interact').textContent(),'Clicked');await screenshot(safe,'dynamic-highlights');
  });
  await check('XSS regression: warning parameters, popup explanations and restricted target',async()=>{
    const p=await context.newPage();const attack='<img src=x onerror="document.body.dataset.injected=1">';
    await p.goto(origin+'/warning/warning.html?'+new URLSearchParams({url:'javascript:alert(1)',score:'<svg>',reasons:attack}));
    assert.equal(await p.locator('#proceedBtn').isDisabled(),true);assert.equal(await p.locator('#riskScore').textContent(),'--');
    assert((await p.locator('#reasonsList').textContent()).includes(attack));assert.equal(await p.locator('#reasonsList img').count(),0);await p.close();
    const panel=await popup(safe);const rendered=await panel.evaluate(attack=>{renderExplanations([{type:'danger',message:attack}]);return {count:document.querySelectorAll('#explanations-list img').length,text:document.querySelector('#explanations-list').textContent};},attack);
    assert.equal(rendered.count,0);assert(rendered.text.includes(attack));await panel.close();
    const cdp=await context.newCDPSession(safe);const worlds=[];
    cdp.on('Runtime.executionContextCreated',ev=>worlds.push(ev.context));await cdp.send('Runtime.enable');
    const isolated=await until(async()=>{
      for(const world of worlds) {const v=await cdp.send('Runtime.evaluate',{expression:'typeof showWarningOverlay',contextId:world.id,returnByValue:true});if(v.result.value==='function')return world;}
      return false;
    });
    const input={finalScore:80,urlRisk:80,explanations:[{type:'danger',message:attack}]};
    await cdp.send('Runtime.evaluate',{expression:`showWarningOverlay(${JSON.stringify(input)})`,contextId:isolated.id});
    assert.equal(await safe.locator('#phishguard-overlay img').count(),0);assert((await safe.locator('#phishguard-overlay').textContent()).includes(attack));
    await sleep(100);
    await safe.evaluate(()=>document.querySelector('#phishguard-proceed-btn').click());
    await sleep(100);
    assert.equal((await msg({type:'CHECK_BYPASS',url:safe.url()})).bypassed,false);
    await cdp.send('Runtime.evaluate',{expression:'removeOverlay()',contextId:isolated.id});
    const tokenAccess=await cdp.send('Runtime.evaluate',{expression:'chrome.storage.local.get("apiToken").then(v => Boolean(v.apiToken))',contextId:isolated.id,awaitPromise:true,returnByValue:true});
    assert.notEqual(tokenAccess.result.value,true);
    const databases=await cdp.send('Runtime.evaluate',{expression:'indexedDB.databases().then(v => v.map(d=>d.name))',contextId:isolated.id,awaitPromise:true,returnByValue:true});
    assert(!databases.result.value.includes('phishguard-pairing'));await cdp.detach();
  });
  await check('Multiple tabs, rapid navigation, redirect and reload discard stale results',async()=>{
    const p=await context.newPage();await go(p,safeBase+'/benign?first=1');await go(p,safeBase+'/benign?second=2');let a=await analysis(p,'full');assert.equal(a.url,p.url());
    await go(p,safeBase+'/redirect');await until(()=>p.url().includes('redirected=1'));a=await analysis(p,'full');assert.equal(a.url,p.url());
    await p.reload();await analysis(p,'full');assert.equal((await analysis(bad)).url,dangerBase+'/login');await p.close();
  });
  await check('Empty/long page, encoded special characters and overlong URL rejection',async()=>{
    const p=await context.newPage();await go(p,safeBase+'/empty');let a=await analysis(p,'url_dom');assert.equal(a.nlpRisk,null);assert.equal(a.detectors.nlp.status,'not_run');
    await go(p,safeBase+'/long');a=await analysis(p,'full');assert(!a.degraded);
    await go(p,safeBase+'/benign?q=%3Cscript%3E&unicode=%E2%9C%93');await analysis(p,'full');
    const response=await msg({type:'ANALYZE_URL',url:safeBase+'/'+'x'.repeat(2050)});assert(response.error);
    const unicode=await msg({type:'ANALYZE_URL',url:'https://例え.jp/道'});assert.equal(unicode.apiResponse,true);assert(Number.isFinite(unicode.riskScore));await p.close();
    const edge=await context.newPage();
    await go(edge,safeBase+'/benign?long='+'x'.repeat(2050));
    await until(async()=>(await edge.locator('#phishguard-indicator').textContent()).includes('Reduced protection'));
    await go(edge,'http://例え.test:8765/benign');await until(()=>edge.url().includes('/warning/warning.html'));
    assert((await edge.locator('#urlDisplay').textContent()).includes('xn--r8jz45g.test'));await edge.close();
  });
  await check('Malformed API response and real network timeout visibly degrade and recover',async()=>{
    await settings('http://127.0.0.1:5058/api/analyze');let a=await rescan(safe);assert(a.degraded&&!a.apiResponse);assert.equal(a.nlpRisk,null);
    fault='timeout';const start=Date.now();a=await msg({type:'ANALYZE_URL',url:safeBase+'/timeout',forceRefresh:true});assert(a.degraded);assert(Date.now()-start>=7000);
    fault='malformed';await settings();a=await rescan(safe);assert.equal(a.degraded,false);assert.equal(a.analysisStage,'full');
  });
  await check('Stopped Flask: safe/suspicious navigation fallback and restart recovery',async()=>{
    await stopBackend();await settings();const p=await context.newPage();await go(p,safeBase+'/benign?offline=1');const a=await analysis(p);
    assert(a.degraded);assert.equal(a.riskLevel,'unknown');assert.equal(a.nlpRisk,null);
    const panel=await popup(p);await until(async()=>(await panel.locator('#connection-status').textContent()).includes('Reduced'));await screenshot(panel,'offline-popup');await panel.close();
    const suspicious=await msg({type:'ANALYZE_URL',url:dangerBase+'/offline',forceRefresh:true});assert(suspicious.degraded&&suspicious.shouldBlock);
    const offlineBad=await context.newPage();await go(offlineBad,dangerBase+'/offline');await until(()=>offlineBad.url().includes('/warning/warning.html'));
    assert.equal(Number(await offlineBad.locator('#riskScore').textContent()),suspicious.riskScore);
    assert((await offlineBad.locator('#reasonsList').textContent()).includes('Reduced protection'));await screenshot(offlineBad,'offline-warning');await offlineBad.close();
    await startBackend();const recovered=await rescan(p);assert(!recovered.degraded&&recovered.analysisStage==='full');await p.close();
  });
  await check('Service-worker stop/restart retains pairing and session bypass',async()=>{
    const browserSession=await context.newCDPSession(options);
    const versions=[];browserSession.on('ServiceWorker.workerVersionUpdated',ev=>versions.push(...ev.versions));await browserSession.send('ServiceWorker.enable');
    const v=await until(()=>versions.find(v=>v.scriptURL===worker.url()&&v.runningStatus==='running'));
    await browserSession.send('ServiceWorker.stopWorker',{versionId:v.versionId});
    const result=await msg({type:'CHECK_BYPASS',url:dangerBase+'/login'});assert(result.bypassed);
    worker=context.serviceWorkers().find(w=>w.url()===origin+'/background/background.js')||await context.waitForEvent('serviceworker');
    assert.equal((await msg({type:'TEST_CONNECTION'})).status,'operational');await browserSession.detach();
  });
  await check('Browser restart retains connection settings and clears temporary bypass',async()=>{
    await context.close();await launch();assert.equal((await msg({type:'GET_SETTINGS'})).paired,true);
    assert.equal((await msg({type:'TEST_CONNECTION'})).status,'operational');
    assert.equal((await msg({type:'CHECK_BYPASS',url:dangerBase+'/login'})).bypassed,false);
    const p=await context.newPage();await go(p,safeBase+'/benign');await analysis(p,'full');await p.close();
  });
  await check('Ordinary public website (non-gating availability check)',async()=>{
    const p=await context.newPage();await go(p,'https://www.wikipedia.org/');const a=await analysis(p,undefined,30000);summary.observations.push({publicWebsite:p.url(),stage:a.analysisStage,degraded:a.degraded});await p.close();
  });
  await check('No uncaught page or worker JavaScript exceptions',async()=>{assert.deepEqual(summary.pageErrors,[]);assert.deepEqual(summary.workerErrors,[]);});
})().catch(error=>{summary.fatal=clean(error.stack);console.error(error.message);process.exitCode=1;}).finally(async()=>{
  if(context)await context.close().catch(()=>{});await stopBackend().catch(()=>{});
  fixtureServer?.closeAllConnections();fixtureServer?.close();faultServer?.closeAllConnections();faultServer?.close();
  fs.writeFileSync(path.join(artifacts,'backend-browser.log'),backendLog);
  summary.finishedAt=new Date().toISOString();save();
  const escape=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  fs.writeFileSync(path.join(artifacts,'browser-report.html'),'<!doctype html><meta charset="utf-8"><title>PhishGuard executed browser checks</title><h1>Actual browser results</h1><pre>'+escape(JSON.stringify(summary,null,2))+'</pre>');
  if(summary.checks.some(c=>c.status==='FAILED'))process.exitCode=1;
  console.log(JSON.stringify({verified:summary.checks.filter(c=>c.status==='VERIFIED').length,failed:summary.checks.filter(c=>c.status==='FAILED').length,fatal:summary.fatal}));
});
