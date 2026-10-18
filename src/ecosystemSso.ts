import appWorker from './routerV9';
import type { Env } from './types';
import { getUserFromRequest } from './db';
import { checkCentralAppEntitlement } from './centralAppAccess';

const SSO_JS = String.raw`(() => {
  const CLIENT_ID='661055525630-ndcq5gtr16h7rqqprlqqkkvineea87lc.apps.googleusercontent.com';
  const CENTRAL='https://id.starry.phd';
  const TICKET= CENTRAL + '/api/apps/gostarry/ticket';
  const CENTRAL_SESSION= CENTRAL + '/api/ecosystem/session';
  let overlay=null;
  let syncing=false;
  let lastSync=0;

  const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
  const email = value => String(value || '').trim().toLowerCase();

  async function localUser(){
    try{
      const r=await fetch('/api/me',{credentials:'include',cache:'no-store'});
      const d=await r.json().catch(()=>({}));
      return d?.user || null;
    }catch(_){ return null; }
  }

  async function centralState(){
    try{
      const r=await fetch(CENTRAL_SESSION,{credentials:'include',cache:'no-store'});
      const d=await r.json().catch(()=>({}));
      return r.ok ? d : {authenticated:false};
    }catch(_){ return null; }
  }

  async function localLogout(){
    try{ await fetch('/api/logout',{method:'POST',credentials:'include',cache:'no-store'}); }catch(_){ }
  }

  async function centralLogout(){
    try{
      await fetch(CENTRAL+'/api/logout',{
        method:'POST',credentials:'include',cache:'no-store',
        headers:{'Content-Type':'application/json'},body:'{}'
      });
    }catch(_){ }
  }

  async function issueTicket(){
    const r=await fetch(TICKET,{
      method:'POST',credentials:'include',cache:'no-store',
      headers:{'Content-Type':'application/json'},body:'{}'
    });
    const d=await r.json().catch(()=>({}));
    if(!r.ok || !d?.code) throw new Error(d?.error || '無法建立繁星通行證登入票證');
    return String(d.code);
  }

  async function sync(force=false){
    const now=Date.now();
    if(syncing || (!force && now-lastSync<2500)) return;
    syncing=true; lastSync=now;
    try{
      const [local,central]=await Promise.all([localUser(),centralState()]);
      if(central===null) return;

      if(!central?.authenticated || !central?.user?.id){
        if(local){
          await localLogout();
          location.reload();
        }
        return;
      }

      if(local && email(local.email)===email(central.user.email)) return;
      if(local) await localLogout();

      const code=await issueTicket();
      location.replace('/auth/callback?code='+encodeURIComponent(code));
    }catch(error){
      console.warn('繁星生態系登入同步暫時略過',error);
    }finally{
      syncing=false;
    }
  }

  function close(){overlay?.remove();overlay=null;}

  function show(){
    if(overlay)return;
    overlay=document.createElement('div');
    overlay.className='starry-sso-overlay';
    overlay.innerHTML='<div class="starry-sso-card"><button type="button" data-close class="starry-sso-close" aria-label="關閉">×</button><div class="starry-sso-title">登入繁星通行證</div><div class="starry-sso-copy">選擇 Google 帳號，完成後會留在繁星任意門。</div><div data-google class="starry-sso-google"></div><div data-status class="starry-sso-status">正在準備登入…</div></div>';
    document.body.appendChild(overlay);
    overlay.querySelector('[data-close]')?.addEventListener('click',close);
    bootGoogle();
  }

  async function googleLogin(credential){
    const status=overlay?.querySelector('[data-status]');
    if(status)status.textContent='正在登入…';
    try{
      const r=await fetch(CENTRAL+'/api/google-sync',{
        method:'POST',credentials:'include',cache:'no-store',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({credential,appId:'gostarry'})
      });
      const d=await r.json().catch(()=>({}));
      if(!r.ok || !d?.success) throw new Error(d?.error || '登入失敗');
      close();
      await wait(80);
      await sync(true);
    }catch(error){
      if(status)status.textContent=error?.message || '登入失敗，請再試一次。';
    }
  }

  function bootGoogle(){
    if(!window.google?.accounts?.id){setTimeout(bootGoogle,80);return;}
    window.google.accounts.id.initialize({
      client_id:CLIENT_ID,
      callback:r=>googleLogin(String(r?.credential||'')),
      ux_mode:'popup',auto_select:false,itp_support:true
    });
    const slot=overlay?.querySelector('[data-google]');
    if(slot && !slot.childElementCount){
      window.google.accounts.id.renderButton(slot,{theme:'filled_black',size:'large',shape:'pill',text:'continue_with',locale:'zh_TW',width:300});
    }
    const status=overlay?.querySelector('[data-status]');
    if(status)status.textContent='請選擇 Google 帳號';
  }

  function loadGoogle(){
    if(document.querySelector('script[data-starry-gsi]'))return;
    const s=document.createElement('script');
    s.src='https://accounts.google.com/gsi/client';
    s.async=true;s.defer=true;s.dataset.starryGsi='1';
    document.head.appendChild(s);
  }

  loadGoogle();

  document.addEventListener('click',async event=>{
    const target=event.target instanceof Element ? event.target : null;
    if(!target)return;

    const login=target.closest('a[href^="/auth/starry"],a[href^="/auth/google"]');
    if(login){
      event.preventDefault();
      show();
      return;
    }

    const switcher=target.closest('#menuSwitchAccount');
    if(switcher){
      event.preventDefault();
      await Promise.allSettled([localLogout(),centralLogout()]);
      try{window.google?.accounts?.id?.disableAutoSelect?.();}catch(_){ }
      show();
      return;
    }

    const logout=target.closest('#menuLogout');
    if(logout){
      void centralLogout();
      try{window.google?.accounts?.id?.disableAutoSelect?.();}catch(_){ }
    }
  },true);

  window.addEventListener('focus',()=>void sync());
  window.addEventListener('online',()=>void sync(true));
  document.addEventListener('visibilitychange',()=>{if(document.visibilityState==='visible')void sync();});
  setTimeout(()=>void sync(true),0);
})();`;

const SSO_CSS = String.raw`
.starry-sso-overlay{position:fixed;inset:0;z-index:99999;display:grid;place-items:center;background:rgba(0,0,0,.62);backdrop-filter:blur(5px);padding:20px}
.starry-sso-card{width:min(390px,100%);padding:24px 18px;border:1px solid rgba(125,249,255,.35);border-radius:20px;background:#081225;color:#fff;text-align:center;box-shadow:0 20px 70px rgba(0,0,0,.45)}
.starry-sso-close{float:right;border:0;background:transparent;color:#fff;font-size:24px;line-height:1;cursor:pointer}
.starry-sso-title{margin:4px 0 8px;font-size:20px;font-weight:800}
.starry-sso-copy{color:#b8d6e8;font-size:13px;line-height:1.6}
.starry-sso-google{display:flex;justify-content:center;margin-top:18px;min-height:44px}
.starry-sso-status{margin-top:12px;font-size:12px;color:#bfeaff}
`;

async function injectSso(response: Response) {
  const type = response.headers.get('Content-Type') || '';
  if (!type.toLowerCase().includes('text/html')) return response;
  let html = await response.text();
  if (!html.includes('/starry-ecosystem-sso.css')) html = html.replace('</head>', '<link rel="stylesheet" href="/starry-ecosystem-sso.css"></head>');
  if (!html.includes('/starry-ecosystem-sso.js')) html = html.replace('</body>', '<script src="/starry-ecosystem-sso.js"></script></body>');
  const headers = new Headers(response.headers);
  headers.delete('Content-Length');
  headers.set('Cache-Control', 'no-store');
  return new Response(html, { status: response.status, statusText: response.statusText, headers });
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const method = request.method.toUpperCase();

    if (method === 'GET' && url.pathname === '/starry-ecosystem-sso.js') {
      return new Response(SSO_JS, { headers: { 'Content-Type': 'application/javascript; charset=utf-8', 'Cache-Control': 'no-store' } });
    }
    if (method === 'GET' && url.pathname === '/starry-ecosystem-sso.css') {
      return new Response(SSO_CSS, { headers: { 'Content-Type': 'text/css; charset=utf-8', 'Cache-Control': 'public, max-age=3600' } });
    }

    // Only private member screens/API require membership. Public short-link redirects
    // and visitor routes continue working without a central entitlement lookup.
    if (url.pathname === '/' || url.pathname.startsWith('/api/')) {
      if (url.pathname !== '/api/logout') {
        const user=await getUserFromRequest(request,env);
        if (user) {
          const mapping=await env.DB.prepare('SELECT starry_user_id FROM starry_identities WHERE local_user_id=? LIMIT 1')
            .bind(user.id).first<{starry_user_id:string}>().catch(()=>null);
          if (!mapping?.starry_user_id) {
            if (url.pathname === '/') {
              return new Response('<!doctype html><html lang="zh-Hant"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><main style="max-width:440px;margin:14vh auto;padding:24px;text-align:center;font-family:system-ui"><h1>請重新登入 Starry ID</h1><p>為了確保會員身分安全，請重新登入一次。</p><a href="https://id.starry.phd/auth/gostarry">使用繁星通行證登入</a></main></html>',{status:401,headers:{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store'}});
            }
            return new Response(JSON.stringify({error:'請重新登入 Starry ID',code:'CENTRAL_LOGIN_REQUIRED'}),{
              status:401,headers:{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'}
            });
          }
          let allowed;
          try {allowed=await checkCentralAppEntitlement(env.STARRY_ID_DB,mapping.starry_user_id,'gostarry');}
          catch {return new Response('會員權限驗證暫時無法使用',{status:503,headers:{'Cache-Control':'no-store'}});}
          if (!allowed.allowed) {
            if (url.pathname === '/') {
              return new Response('<!doctype html><html lang="zh-Hant"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>使用權限</title><main style="max-width:440px;margin:14vh auto;padding:24px;text-align:center;font-family:system-ui"><h1>您沒有使用權限</h1><p>請聯絡繁星管理員開通繁星任意門。</p><a href="https://id.starry.phd/">前往 Starry ID</a></main></html>',{status:403,headers:{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store'}});
            }
            return new Response(JSON.stringify({error:'您沒有使用權限',code:'APP_ACCESS_DENIED'}),{
              status:403,headers:{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'}
            });
          }
        }
      }
    }
    return injectSso(await appWorker.fetch(request, env, ctx));
  }
};
