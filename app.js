const $ = id => document.getElementById(id);
let mode = 'login', csrf = '';
const showMessage = (id, text) => { $(id).textContent = text; };
function switchMode(next) {
 mode = next;
 $('login-tab').classList.toggle('active', mode === 'login');
 $('register-tab').classList.toggle('active', mode === 'register');
 $('heading').textContent = mode === 'login' ? 'Bem-vindo de volta.' : 'Crie sua identidade.';
 $('intro').textContent = mode === 'login' ? 'Entre para acessar seu ambiente de identidade.' : 'Cadastre-se para começar com uma conta protegida.';
 $('submit').firstChild.textContent = mode === 'login' ? 'Acessar conta ' : 'Criar minha conta ';
 $('password').autocomplete = mode === 'login' ? 'current-password' : 'new-password';
 showMessage('message', '');
}
$('login-tab').addEventListener('click', () => switchMode('login'));
$('register-tab').addEventListener('click', () => switchMode('register'));
async function api(path, options = {}) {
 const response = await fetch(path, {credentials:'same-origin', ...options, headers:{'Content-Type':'application/json', ...(options.headers || {})}});
 const data = await response.json().catch(() => ({}));
 if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : `Falha (${response.status})`);
 return data;
}
async function authenticated(user, sessionCsrf) {
 csrf = sessionCsrf || (await api('/api/csrf')).csrf;
 $('guest').classList.add('hidden'); $('private').classList.remove('hidden');
 $('user-email').textContent = user.email;
 $('user-role').textContent = user.admin ? 'Administrador' : 'Usuário';
 $('stats').classList.toggle('hidden', !user.admin);
 if(user.admin) {
  $('management').style.display = 'block';
  await refreshAdmin();
  try { const s=await api('/api/admin/stats'); $('users-total').textContent=s.users; $('sessions-total').textContent=s.active_sessions; }
  catch(e) {showMessage('private-message',e.message)}
 }
}
$('form').addEventListener('submit', async event => {
 event.preventDefault(); const button = $('submit');button.disabled=true;showMessage('message','');
 try {
  const data = await api(mode === 'login' ? '/api/login' : '/api/register', {method:'POST',body:JSON.stringify({email:$('email').value,password:$('password').value})});
  $('password').value=''; await authenticated(data.user, data.csrf);
 } catch (e) {showMessage('message',e.message)} finally {button.disabled=false}
});
$('logout').addEventListener('click', async () => {
 try{ await api('/api/logout', {method:'POST',headers:{'x-csrf-token':csrf},body:'{}'});csrf='';$('private').classList.add('hidden');$('guest').classList.remove('hidden');showMessage('message','Sessão encerrada.'); }
 catch(e){showMessage('private-message',e.message)}
});
(async()=>{try{const user=await api('/api/me');await authenticated(user);}catch(e){/* Anonymous session is expected. */}})();

async function refreshAdmin(){
 try{const apps=await api('/api/admin/apps'),grants=await api('/api/admin/grants');
 const choices=$('grant-slug');choices.replaceChildren();for(const app of apps){const option=document.createElement('option');option.value=app.id;option.textContent=app.name+' ('+app.id+')';choices.append(option)}
 const appList=$('admin-app-list');appList.replaceChildren();for(const app of apps){const div=document.createElement('div');div.textContent=app.name+' · '+app.id+' · '+app.url;appList.append(div)}
 const grantList=$('admin-grant-list');grantList.replaceChildren();for(const g of grants){const div=document.createElement('div');div.textContent=g.email+' / '+g.slug+' / '+(g.active?'Ativo':'Revogado')+(g.expires_at?' até '+g.expires_at:'');grantList.append(div)}
 }catch(e){showMessage('admin-message',e.message)}
}
$('app-form').addEventListener('submit',async event=>{event.preventDefault();try{const payload={slug:$('app-slug').value,name:$('app-name').value,url:$('app-url').value,description:$('app-description').value,category:$('app-category').value,icon:$('app-icon').value};await api('/api/admin/apps',{method:'POST',headers:{'x-csrf-token':csrf},body:JSON.stringify(payload)});showMessage('admin-message','Aplicativo salvo no banco de dados.');await refreshAdmin()}catch(e){showMessage('admin-message',e.message)}});
$('grant-form').addEventListener('submit',async event=>{event.preventDefault();try{const expiry=$('grant-expire').value;const payload={email:$('grant-email').value,slug:$('grant-slug').value,active:$('grant-enabled').value==='true',expires_at:expiry?new Date(expiry).toISOString():null};await api('/api/admin/grants',{method:'POST',headers:{'x-csrf-token':csrf},body:JSON.stringify(payload)});showMessage('admin-message','Permissão atualizada no servidor.');await refreshAdmin()}catch(e){showMessage('admin-message',e.message)}});
