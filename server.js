const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const PW=process.env.EDU_PASSWORD,SECRET=process.env.SESSION_SECRET||crypto.randomBytes(32).toString('hex');
if(!PW){console.error('Set EDU_PASSWORD (and SESSION_SECRET) env vars');process.exit(1)}
const h=s=>crypto.createHash('sha256').update(s).digest();
const sign=v=>crypto.createHmac('sha256',SECRET).update(v).digest('hex');
const T={'.html':'text/html; charset=utf-8','.css':'text/css','.js':'text/javascript','.jpg':'image/jpeg','.webp':'image/webp','.avif':'image/avif','.svg':'image/svg+xml','.txt':'text/plain'};
const NI={'X-Robots-Tag':'noindex, nofollow','Cache-Control':'no-store'},fails=new Map();
function authed(req){const m=/(?:^|; )edu=([^;]+)/.exec(req.headers.cookie||'');if(!m)return false;const[e,s]=m[1].split('.');if(!e||!s||+e<Date.now())return false;const a=Buffer.from(sign(e)),b=Buffer.from(s);return a.length===b.length&&crypto.timingSafeEqual(a,b)}
function send(res,c,b,t='text/html; charset=utf-8',x={}){res.writeHead(c,{'Content-Type':t,'X-Content-Type-Options':'nosniff','Referrer-Policy':'same-origin',...x});res.end(b)}
function file(res,p,x){fs.readFile(p,(e,d)=>e?send(res,404,'Not found'):send(res,200,d,T[path.extname(p)]||'application/octet-stream',x))}
http.createServer((req,res)=>{
 const p=new URL(req.url,'http://x').pathname,ip=req.socket.remoteAddress;
 if(p==='/education'||p==='/education/')return file(res,path.join(__dirname,'private',authed(req)?'arcade.html':'login.html'),NI);
 if(p==='/education/login'&&req.method==='POST'){
  const f=fails.get(ip)||{n:0,t:Date.now()};if(Date.now()-f.t>6e5){f.n=0;f.t=Date.now()}
  if(f.n>=5)return send(res,429,'{"ok":false}','application/json',NI);
  let b='';req.on('data',c=>{b+=c;if(b.length>1e4)req.destroy()});
  req.on('end',()=>{let pw='';try{pw=String(JSON.parse(b).password||'')}catch{}
   if(crypto.timingSafeEqual(h(pw),h(PW))){fails.delete(ip);const e=Date.now()+8*36e5;
    const sec=(req.headers['x-forwarded-proto']==='https'||process.env.NODE_ENV==='production')?'; Secure':'';
    return send(res,200,'{"ok":true}','application/json',{...NI,'Set-Cookie':`edu=${e}.${sign(String(e))}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800${sec}`})}
   f.n++;fails.set(ip,f);send(res,401,'{"ok":false}','application/json',NI)});return}
 if(p==='/education/logout'&&req.method==='POST')return send(res,200,'{"ok":true}','application/json',{...NI,'Set-Cookie':'edu=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'});
 const g=/^\/education\/games\/(\w+)\.js$/.exec(p);
 if(g)return authed(req)?file(res,path.join(__dirname,'private/games',g[1]+'.js'),NI):send(res,401,'Locked');
 if(p==='/robots.txt')return send(res,200,'User-agent: *\nDisallow: /education\n','text/plain');
 const root=path.join(__dirname,'public'),full=path.normalize(path.join(root,p==='/'?'index.html':p.slice(1)));
 if(!full.startsWith(root))return send(res,400,'Bad');
 file(res,full,{'Cache-Control':'public, max-age=3600'});
}).listen(process.env.PORT||3000,()=>console.log('http://localhost:'+(process.env.PORT||3000)));
