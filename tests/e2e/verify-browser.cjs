/* Real unpacked MV3 extension + normal run.py + real saved models.
 * Authenticated requests, no patched analysis responses or model overrides.
 * Original 2026-10-24 diagnostic harness is retained outside this checkout.
 */
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),os=require('node:os'),http=require('node:http');
const {spawn}=require('node:child_process'),{randomBytes}=require('node:crypto');
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||path.join(os.homedir(),'.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright'));
const root=path.resolve(__dirname,'../..'),out=path.join(__dirname,'artifacts');fs.mkdirSync(out,{recursive:true});
const executablePath=process.env.CHROME_PATH||'D:/scam_extension/main-verification-2026-10-24/browser-runtime/chrome-win64/chrome.exe';
const python=process.env.PYTHON||path.join(os.homedir(),'.pyenv/pyenv-win/versions/3.11.0/python.exe');
const profile=fs.mkdtempSync(path.join(os.tmpdir(),'phishguard-main-repair-')),token=randomBytes(32).toString('base64url');
const summary={checks:[],observations:{},requests:[],pageErrors:[],workerErrors:[],console:[]};
let context,worker,origin,control,backend,fixtureServer,backendLog='';
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const clean=value=>String(value).split(token).join('[REDACTED]');
async function until(fn,timeout=20000){const end=Date.now()+timeout;let err;while(Date.now()<end){try{const v=await fn();if(v)return v;}catch(e){err=e;}await sleep(200);}throw Error('Timed out'+(err?': '+err.message:''));}
function save(){fs.writeFileSync(path.join(out,'browser-results.json'),JSON.stringify(summary,null,2));}
async function check(name,fn){console.log('CHECK '+name);try{const detail=await fn();summary.checks.push({name,status:'VERIFIED',detail});console.log('PASS '+name);}catch(e){summary.checks.push({name,status:'FAILED',error:clean(e.stack)});console.log('FAIL '+name+': '+clean(e.message));}save();}
async function startBackend(){backend=spawn(python,['-X','utf8','-u','backend/run.py'],{cwd:root,windowsHide:true,env:{...process.env,FLASK_ENV:'production',PORT:'5000',PYTHONDONTWRITEBYTECODE:'1',PHISHGUARD_API_TOKEN:token,PHISHGUARD_EXTENSION_ORIGINS:origin}});const log=d=>{backendLog+=clean(d);fs.writeFileSync(path.join(out,'backend-browser.log'),backendLog);};backend.stdout.on('data',log);backend.stderr.on('data',log);backend.on('error',e=>console.error(e.message));await until(async()=>{if(backend.exitCode!==null)throw Error('Backend exited '+backend.exitCode);const r=await fetch('http://127.0.0.1:5000/health',{signal:AbortSignal.timeout(1500)});return r.ok;},120000);}
async function stopBackend(){if(backend&&backend.exitCode===null&&backend.signalCode===null){backend.kill();await until(()=>backend.exitCode!==null||backend.signalCode!==null);}}
async function api(route,data,authenticated=true){const r=await fetch('http://127.0.0.1:5000'+route,{method:data?'POST':'GET',headers:{...(data?{'Content-Type':'application/json'}:{}),...(authenticated?{Authorization:'Bearer '+token}:{})},body:data?JSON.stringify(data):undefined,signal:AbortSignal.timeout(30000)});const text=await r.text();let body;try{body=JSON.parse(text);}catch{body=text.slice(0,500);}return {status:r.status,body};}
async function go(page,url){try{await page.goto(url,{waitUntil:'domcontentloaded',timeout:15000});}catch(e){if(!/interrupted|ERR_ABORTED/.test(e.message))throw e;}await sleep(400);}
const msg=message=>control.evaluate(message=>chrome.runtime.sendMessage(message),message);
async function analysis(page,stage='full'){return until(()=>worker.evaluate(async({url,stage})=>{const tab=(await chrome.tabs.query({})).find(t=>t.url===url);const a=tab&&state.analysisCache.get(tab.id);return a?.url===url&&(!stage||a.analysisStage===stage)?a:null;},{url:page.url(),stage}),35000);}
async function shot(page,name){await page.screenshot({path:path.join(out,name+'.png'),fullPage:true});}
// Existing trusted-domain policy exercises Safe UI without falsifying model accuracy.
// A separate localhost observation below preserves the known model false positive.
const safeBase='http://fixture.github.com:8766',dangerBase='http://verify-paypal-account-security.xyz:8766';
const benign='<h1>Community Library</h1><p>Books, gardening and weekend reading events for all local families.</p><button id="interact" onclick="this.textContent=\'Clicked\'">Browse books</button><main id="dynamic"></main>';
const phishing='<h1>PayPal account verification — local simulation</h1><p>Urgent! Verify your account immediately. Your account will be closed within 24 hours. Confirm your identity. Enter your password.</p><form onsubmit="event.preventDefault()"><label>Dummy email<input name="email" type="email"></label><label>Dummy password<input name="password" type="password"></label><button>Demonstration only</button></form><p>No credentials are collected or submitted.</p>';

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
  fixtureServer=http.createServer((req,res)=>{if(req.url.startsWith('/redirect')){res.writeHead(302,{Location:'/benign?redirected=1'});res.end();return;}res.writeHead(200,{'Content-Type':'text/html; charset=utf-8'});res.end('<!doctype html><html><head><title>'+(req.url.startsWith('/login')?'PayPal account verification':'Community Library')+'</title><style>body{font:20px system-ui;margin:50px auto;max-width:850px;line-height:1.6}input,button{display:block;padding:10px;margin:10px}</style></head><body>'+(req.url.startsWith('/login')?phishing:benign)+'</body></html>');}).listen(8766,'127.0.0.1');
  context=await chromium.launchPersistentContext(profile,{executablePath,headless:process.env.HEADED!=='1',ignoreDefaultArgs:['--disable-extensions'],viewport:{width:1200,height:850},args:[`--disable-extensions-except=${root}/extension`,`--load-extension=${root}/extension`,'--no-proxy-server','--host-resolver-rules=MAP fixture.github.com 127.0.0.1, MAP verify-paypal-account-security.xyz 127.0.0.1']});
  context.setDefaultTimeout(15000);
  await context.route('**/*',route=>{const u=new URL(route.request().url());if(['http:','https:'].includes(u.protocol)&&!['localhost','127.0.0.1','fixture.github.com','verify-paypal-account-security.xyz'].includes(u.hostname))return route.abort();return route.continue();});
  const attach=p=>{p.on('pageerror',e=>summary.pageErrors.push(clean(e.message)));p.on('console',m=>{if(m.type()==='error')summary.console.push({type:'error',text:clean(m.text()).slice(0,500)});});};context.on('page',attach);context.pages().forEach(attach);
  context.on('request',r=>{if(r.url().startsWith('http://127.0.0.1:5000/'))summary.requests.push({url:r.url(),body:r.postData()});});
  worker=context.serviceWorkers()[0]||await context.waitForEvent('serviceworker');origin='chrome-extension://'+new URL(worker.url()).host;
  control=await context.newPage();await control.goto(origin+'/options/options.html');
  const cd=await context.newCDPSession(control);cd.on('ServiceWorker.workerErrorReported',e=>summary.workerErrors.push(e.errorMessage));await cd.send('ServiceWorker.enable');
  await startBackend();
  await check('Original run.py backend starts and health responds',async()=>{const r=await api('/health');assert.equal(r.status,200);return r;});
  await check('Standard startup activates trained-model pipeline',async()=>{const r=await api('/api/status');summary.observations.status=r;assert.equal(r.status,200);assert.equal(r.body.model_loaded,true);assert.equal(r.body.analysis_mode,'url_nlp_dom');return r;});
  await check('API info endpoint',async()=>{const r=await api('/api/info');assert.equal(r.status,200);return r;});
  await check('Batch URL analysis and missing-field handling',async()=>{const r=await api('/api/batch',{urls:['https://example.com',dangerBase+'/login']});assert.equal(r.status,200);assert.equal(r.body.results.length,2);assert.equal((await api('/api/analyze',{})).status,400);return r;});
  summary.observations.rawPhishing=await api('/api/analyze',{url:dangerBase+'/login'});
  summary.observations.legacyPayload=await api('/api/analyze',{url:dangerBase+'/login',content:'Confirm your identity immediately. Enter your password.',forms:[{hasPasswordField:true,isExternal:true}]});
  summary.observations.localhostModelAccuracy=await api('/api/analyze',{url:'http://localhost:8766/benign'});
  await check('API rejects invalid schemes',async()=>{for(const url of ['javascript:alert(1)','data:text/plain,test','file:///tmp/test'])assert.equal((await api('/api/analyze',{url})).status,400);});
  await check('API rejects unauthenticated analysis requests',async()=>{assert.equal((await api('/api/analyze',{url:dangerBase+'/login'},false)).status,401);});
  await check('Actual unpacked MV3 extension starts and pairs through options',async()=>{assert(worker.url().endsWith('/background/background.js'));await control.locator('#endpoint').fill('http://127.0.0.1:5000/api/analyze');await control.locator('#token').fill(token);await control.getByRole('button',{name:'Save connection'}).click();await until(async()=>(await control.locator('#status').textContent()).includes('saved'));await control.locator('#test-connection').click();await until(async()=>(await control.locator('#status').textContent()).includes('Connected and authenticated'));assert.equal((await msg({type:'GET_SETTINGS'})).apiToken,undefined);return {worker:worker.url(),browser:await worker.evaluate(()=>navigator.userAgent),mode:process.env.HEADED==='1'?'headed':'headless'};});
  const safe=await context.newPage(),danger=await context.newPage();
  await check('Benign local navigation and content-script request',async()=>{await go(safe,safeBase+'/benign');const a=await analysis(safe);summary.observations.safe=a;assert.equal(a.apiResponse,true);assert.equal(a.riskLevel,'safe');assert.equal(a.url,safeBase+'/benign');assert.equal(await safe.locator('#phishguard-overlay').count(),0);await shot(safe,'safe-page');return a;});
  await check('Online phishing warning and preserved backend risk score',async()=>{await go(danger,dangerBase+'/login');await until(()=>danger.url().startsWith(origin+'/warning/'));const shown=Number(await danger.locator('#riskScore').textContent());assert.equal(shown,summary.observations.rawPhishing.body.risk_score);assert(shown>=50);assert((await danger.locator('#reasonsList').textContent()).length>0);await shot(danger,'online-warning');return {score:shown};});
  await check('Online full NLP/DOM scoring available after explicit Proceed',async()=>{await danger.locator('#proceedBtn').click();await until(()=>danger.url()===dangerBase+'/login');const a=await analysis(danger);summary.observations.fullPhishing=a;assert(a.nlpRisk>0&&a.domRisk>0);assert.equal(a.degraded,false);assert.equal(a.finalScore,Math.max(a.urlRisk>=90?90:0,Math.floor((30*a.urlRisk+40*a.nlpRisk+30*a.domRisk)/100)));assert.equal(a.riskLevel,a.finalScore>70?'dangerous':a.finalScore>30?'suspicious':'safe');return a;});
  await check('Native popup displays correct URL, score, bars and badge',async()=>{
    const a=await analysis(danger),panel=await popup(danger);
    await until(async()=>Number(await panel.locator('#risk-score').textContent())===a.finalScore);
    const value=await panel.evaluate(()=>Object.fromEntries(['domain','risk-score','score-url','score-nlp','score-dom','risk-badge','connection-status'].map(id=>[id,document.getElementById(id)?.textContent])));
    summary.observations.popup=value;
    assert(value.domain.includes('verify-paypal'));
    assert.equal(value['score-url'],a.urlRisk+'%');assert.equal(value['score-nlp'],a.nlpRisk+'%');assert.equal(value['score-dom'],a.domRisk+'%');assert.equal(value['risk-badge'],a.riskLevel.toUpperCase());
    // Wait for real CSS transitions, then assert visible rendering, not just text.
    const visual=await until(()=>panel.evaluate(expected=>{
      const badgeColor=getComputedStyle(document.querySelector('#risk-badge')).color;
      const gauge=getComputedStyle(document.querySelector('#gauge-arc'));
      const bars=['url','nlp','dom'].map(name=>{const bar=document.querySelector('#bar-'+name);return 100*bar.getBoundingClientRect().width/bar.parentElement.getBoundingClientRect().width;});
      const scores=[expected.urlRisk,expected.nlpRisk,expected.domRisk];
      const offset=251.2*(1-expected.finalScore/100);
      if(badgeColor!=='rgb(239, 68, 68)'||gauge.stroke!=='rgb(239, 68, 68)'||Math.abs(parseFloat(gauge.strokeDashoffset)-offset)>0.1||bars.some((v,i)=>Math.abs(v-scores[i])>0.1))return null;
      return {badgeColor,gaugeColor:gauge.stroke,gaugeOffset:gauge.strokeDashoffset,barWidthsPercent:bars};
    },a));
    summary.observations.popupVisual=visual;
    await panel.screenshot({path:path.join(out,'native-popup.png')});await panel.close();return {...value,visual};
  });
  await check('Popup rescan requests fresh full-page analysis',async()=>{const panel=await popup(danger);await sleep(300);const before=summary.requests.length;await panel.locator('#rescan-btn').click();await until(()=>summary.requests.slice(before).some(r=>{try{const p=JSON.parse(r.body);return p.text?.length>20&&p.dom?.forms?.length>0&&p.force_refresh===true;}catch{return false;}}));await analysis(danger);summary.observations.rescanRequests=summary.requests.slice(before);await panel.close();});
  await check('Initial phishing text highlighting',async()=>{await until(async()=>(await danger.locator('.phishguard-highlight').count())>0);const count=await danger.locator('.phishguard-highlight').count();assert.equal(await danger.locator('.phishguard-highlight .phishguard-highlight').count(),0);await shot(danger,'initial-highlights');return {count};});
  await check('Highlight toggle off/on and saved setting',async()=>{let panel=await popup(danger);if(await panel.locator('#nlp-toggle').isChecked())await panel.locator('#nlp-toggle').click();await until(async()=>(await danger.locator('.phishguard-highlight').count())===0);await panel.close();panel=await popup(danger);assert.equal(await panel.locator('#nlp-toggle').isChecked(),false);await panel.locator('#nlp-toggle').click();await until(async()=>(await danger.locator('.phishguard-highlight').count())>0);await panel.close();});
  await check('Dynamically inserted suspicious paragraph highlighted',async()=>{await safe.evaluate(()=>{const p=document.createElement('p');p.id='new-warning';p.textContent='Urgent! Verify your account immediately. Confirm your identity within 24 hours.';document.querySelector('#dynamic').appendChild(p);});await until(async()=>(await safe.locator('#new-warning .phishguard-highlight').count())>0);await safe.locator('#interact').click();assert.equal(await safe.locator('#interact').textContent(),'Clicked');await shot(safe,'dynamic-highlights');});
  await check('Short dynamically inserted suspicious phrase highlighted',async()=>{await safe.evaluate(()=>{const p=document.createElement('p');p.id='short-warning';p.textContent='verify your account';document.body.appendChild(p);});await until(async()=>(await safe.locator('#short-warning .phishguard-highlight').count())>0,5000);assert.equal(await safe.locator('.phishguard-highlight .phishguard-highlight').count(),0);});
  await check('Warning explanations render HTML as inert text',async()=>{const p=await context.newPage();const reason='<b id="injected-markup">Injected text</b>';await p.goto(origin+'/warning/warning.html?'+new URLSearchParams({url:safeBase+'/benign',score:'80',level:'dangerous',reasons:reason}));assert.equal(await p.locator('#injected-markup').count(),0);assert((await p.locator('#reasonsList').textContent()).includes(reason));await shot(p,'warning-inert-html');await p.close();});
  await check('Rapid navigation and redirects update current URL',async()=>{await go(safe,safeBase+'/benign?first=1');await go(safe,safeBase+'/redirect');const a=await analysis(safe);assert.equal(a.url,safe.url());return {url:a.url};});
  await stopBackend();
  const offline=await context.newPage(),offlineTarget=dangerBase+'/login?offline=1';
  await check('Offline heuristic warning appears with reduced-protection label',async()=>{await go(offline,offlineTarget);await until(()=>offline.url().startsWith(origin+'/warning/'));assert(Number(await offline.locator('#riskScore').textContent())>=50);assert((await offline.locator('#reasonsList').textContent()).includes('Reduced protection'));await shot(offline,'offline-warning');});
  await check('Proceed Anyway bypass and reload',async()=>{await offline.locator('#proceedBtn').click();await until(()=>offline.url()===offlineTarget);assert.equal((await msg({type:'CHECK_BYPASS',url:offlineTarget})).bypassed,true);await offline.reload();await sleep(600);assert.equal(offline.url(),offlineTarget);});
  await check('Go Back to Safety action',async()=>{const p=await context.newPage();await go(p,dangerBase+'/login?back=1');await until(()=>p.url().startsWith(origin+'/warning/'));await p.locator('#backBtn').click();await until(()=>p.url()==='about:blank');await p.close();return {destination:'about:blank'};});
  await check('Offline safe page exposes reduced protection in popup',async()=>{const p=await context.newPage();await go(p,safeBase+'/benign?offline=1');const panel=await popup(p);await until(async()=>(await panel.locator('#connection-status').textContent()).includes('Reduced protection'));const value=await panel.locator('#connection-status').textContent();await panel.screenshot({path:path.join(out,'offline-popup.png')});await panel.close();return {label:value};});
  await startBackend();
  await check('Backend recovery updates a fresh navigation',async()=>{await go(safe,safeBase+'/benign?recovered=1');const a=await analysis(safe);assert.equal(a.apiResponse,true);assert.equal(a.degraded,false);return a;});
  await check('Service-worker restart retains active temporary bypass',async()=>{await cd.send('ServiceWorker.stopAllWorkers');await sleep(500);await control.reload();await msg({type:'GET_SETTINGS'});worker=context.serviceWorkers()[0]||await context.waitForEvent('serviceworker');const value=await msg({type:'CHECK_BYPASS',url:offlineTarget});assert.equal(value.bypassed,true);await offline.reload();await sleep(600);assert.equal(offline.url(),offlineTarget);return value;});
  await check('No uncaught page or unexpected worker errors',async()=>{assert.equal(summary.pageErrors.length,0);assert.equal(summary.workerErrors.length,0);return {pageErrors:summary.pageErrors.length,workerErrors:summary.workerErrors.length};});
})().catch(e=>{summary.fatal=clean(e.stack);console.error(clean(e.stack));process.exitCode=1;}).finally(async()=>{if(context)await context.close().catch(()=>{});await stopBackend().catch(()=>{});if(fixtureServer)fixtureServer.close();summary.finishedAt=new Date().toISOString();save();const counts={verified:summary.checks.filter(c=>c.status==='VERIFIED').length,failed:summary.checks.filter(c=>c.status==='FAILED').length,fatal:summary.fatal};console.log(JSON.stringify(counts));if(counts.failed||counts.verified!==25||counts.fatal)process.exitCode=1;});
