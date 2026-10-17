(() => {
'use strict';
const $=id=>document.getElementById(id);
const K='sqlpro2-lima-';
const read=(name,fallback)=>{try{return JSON.parse(localStorage.getItem(K+name))??fallback}catch{return fallback}};
const save=(name,val)=>{try{localStorage.setItem(K+name,JSON.stringify(val))}catch{}};
const clean=s=>String(s??'').normalize('NFD').replace(/[\u0300-\u036f]/g,'').toLowerCase();
const el=(tag,cls,text)=>{const e=document.createElement(tag); if(cls)e.className=cls;if(text!==undefined)e.textContent=String(text);return e};
let apps=[], section='all',category='Todas',query='',view=read('view','grid'),favorites=new Set(read('favorites',[])),recent=read('recent',[]),csrf='';
function notify(message){const box=$('toast');box.textContent=message;box.classList.add('show');setTimeout(()=>box.classList.remove('show'),3500)}
function choose(list){let x=list.filter(a=>section==='favorites'?favorites.has(a.id):section==='recent'?recent.some(r=>r.id===a.id):section==='featured'?a.featured||favorites.has(a.id):true);
 if(category!=='Todas')x=x.filter(a=>a.category===category);
 if(query)x=x.filter(a=>clean([a.name,a.category,a.description,...(a.tags||[])].join(' ')).includes(clean(query)));
 if(section==='recent')x.sort((a,b)=>recent.findIndex(r=>r.id===a.id)-recent.findIndex(r=>r.id===b.id));
 else x.sort((a,b)=>Number(favorites.has(b.id))-Number(favorites.has(a.id))||Number(b.featured)-Number(a.featured)||a.name.localeCompare(b.name,'pt-BR'));
 return x}
function reconcile(){const ids=new Set(apps.map(a=>a.id));favorites=new Set([...favorites].filter(id=>ids.has(id)));recent=recent.filter(r=>ids.has(r.id));}
function nav(){const entries=[['all','▦','Todos',apps.length],['favorites','★','Favoritos',[...favorites].length],['recent','◷','Recentes',recent.length],['featured','✦','Sugestões',apps.filter(a=>a.featured||favorites.has(a.id)).length]];
 for(const dest of ['navDesktop','navMobile']){const root=$(dest);root.replaceChildren();for(const [key,ic,name,count] of entries){const btn=el('button','nav-btn'+(section===key?' active':''));btn.type='button';btn.setAttribute('aria-pressed',String(section===key));btn.append(el('span','nav-icon',ic),el('span','',name),el('span','nav-count',count));btn.addEventListener('click',()=>{section=key;category='Todas';render()});root.append(btn)}}}
function filters(){const root=$('categoryFilters');root.replaceChildren();const categories=['Todas',...new Set(apps.map(a=>a.category))].sort((a,b)=>a.localeCompare(b,'pt-BR'));if(!categories.includes(category))category='Todas';for(const c of categories){const btn=el('button','chip'+(category===c?' active':''),c);btn.type='button';btn.setAttribute('aria-pressed',String(category===c));btn.append(el('span','chip-count',c==='Todas'?apps.length:apps.filter(a=>a.category===c).length));btn.addEventListener('click',()=>{category=c;render()});root.append(btn)}}
function record(id){recent=recent.filter(x=>x.id!==id);recent.unshift({id,time:Date.now()});recent=recent.slice(0,20);save('recent',recent);nav()}
function card(a){const root=el('article','card'),top=el('div','card-top'),icon=el('span','app-icon',a.icon||'🔗'),star=el('button','fav-btn'+(favorites.has(a.id)?' selected':''),favorites.has(a.id)?'★':'☆');star.type='button';star.setAttribute('aria-label',favorites.has(a.id)?'Remover dos favoritos':'Adicionar aos favoritos');star.setAttribute('aria-pressed',String(favorites.has(a.id)));star.addEventListener('click',()=>{if(favorites.has(a.id))favorites.delete(a.id);else favorites.add(a.id);save('favorites',[...favorites]);render()});top.append(icon,star);
 const content=el('div','card-body');content.append(el('span','card-cat',a.category),el('h3','',a.name),el('p','',a.description||'Acesse sua aplicação autorizada.'));
 const base=el('div','card-bottom'),link=el('a','','Abrir aplicação ↗');link.href='/api/portal/launch/'+encodeURIComponent(a.id);link.target='_blank';link.rel='noopener noreferrer';link.setAttribute('aria-label','Abrir '+a.name+' em nova aba');link.addEventListener('click',()=>record(a.id));base.append(link,el('small','',a.featured?'✦ Destaque':'Licença ativa'));root.append(top,content,base);return root}
function render(){reconcile();nav();filters();$('totalApps').textContent=String(apps.length);$('favTotal').textContent=String(favorites.size);$('catTotal').textContent=String(new Set(apps.map(a=>a.category)).size);$('siteStatus').textContent=apps.length+' aplicativo(s) autorizado(s)';const names={all:['Seus aplicativos autorizados','Só aparecem sistemas liberados para esta conta.'],favorites:['Seus favoritos','Atalhos que você marcou como favoritos.'],recent:['Acessados recentemente','Últimos sistemas abertos neste navegador.'],featured:['Destaques para você','Aplicativos destacados e favoritos.']};$('listTitle').textContent=names[section][0];$('listSubtitle').textContent=names[section][1];const list=choose(apps),grid=$('grid');grid.replaceChildren();grid.classList.toggle('list-mode',view==='list');for(const a of list)grid.append(card(a));$('empty').hidden=list.length>0; if(!list.length){$('emptyTitle').textContent=apps.length?'Nenhum aplicativo nesta seleção':'Nenhum aplicativo autorizado';$('emptyMessage').textContent=apps.length?'Altere os filtros ou a pesquisa.':'Solicite ao administrador a liberação de um aplicativo.'}}
async function api(path,options={}){const r=await fetch(path,{credentials:'same-origin',cache:'no-store',...options});if(!r.ok){if(r.status===401)location.href='/';throw Error('Falha HTTP '+r.status)}return r.json()}
async function logout(){try{csrf=(await api('/api/csrf')).csrf;await api('/api/logout',{method:'POST',headers:{'Content-Type':'application/json','x-csrf-token':csrf},body:'{}'});location.href='/'}catch(e){notify('Não foi possível encerrar a sessão. '+e.message)}}
$('year').textContent=new Date().getFullYear();
$('search').addEventListener('input',e=>{query=e.target.value.trim();render()});
$('viewBtn').addEventListener('click',()=>{view=view==='grid'?'list':'grid';save('view',view);render()});
$('clearFilters').addEventListener('click',()=>{section='all';category='Todas';query='';$('search').value='';render()});
$('themeBtn').addEventListener('click',()=>document.body.classList.toggle('high-contrast'));
$('logoutBtn').addEventListener('click',logout);
document.addEventListener('keydown',e=>{if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='k'){e.preventDefault();$('search').focus()}});
const localPreview=Boolean(document.querySelector('meta[name="sqlpro-preview"][content="offline"]')) || !['http:', 'https:'].includes(location.protocol);
if (localPreview) {
  document.body.classList.add('offline-preview');
  $('offlineNotice').hidden=false;
  $('siteStatus').textContent='Prévia local — sem autenticação';
  $('heroTitle').innerHTML='Seu portal, <span>com o visual restaurado.</span>';
  $('heroTitle').nextElementSibling.textContent='Esta é uma prévia da interface; o catálogo real é carregado somente após login no SQL Pro.';
  $('logoutBtn').hidden=true;
  for(const link of document.querySelectorAll('[data-requires-server]')) {
    link.removeAttribute('href');
    link.setAttribute('role','button');link.tabIndex=0;
    link.addEventListener('click',e=>{e.preventDefault();notify('Inicie o SQL Pro no servidor para administrar a conta.')});
    link.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();link.click()}});
  }
  render();
  $('listTitle').textContent='Área de aplicativos';
  $('listSubtitle').textContent='Prévia visual: nenhum aplicativo real é carregado sem uma sessão válida.';
  $('emptyTitle').textContent='Pré-visualização, sem aplicativos';
  $('emptyMessage').textContent='Para visualizar seus aplicativos autorizados, faça login pelo endereço do SQL Pro hospedado.';
  $('siteStatus').textContent='Prévia local — sem autenticação';
} else {
  (async()=>{try{const user=await api('/api/me');const rows=await api('/api/portal/apps');if(!Array.isArray(rows))throw Error('Catálogo inválido');apps=rows;render();$('siteStatus').textContent='Conta: '+user.email}catch(e){$('siteStatus').textContent='Falha na integração';$('listSubtitle').textContent='Não foi possível consultar o serviço SQL Pro.';notify(e.message)}})();
}
})();
