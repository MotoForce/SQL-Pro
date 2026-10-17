<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

function api_route(string $path): never {
    if (!installed()) fail(503, 'Instalação pendente. Acesse /install.php.');
    if (str_starts_with($path, '/api/')) {
        header('Cache-Control: no-store');
    }
    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
    if ($path === '/api/health') { require_method('GET'); db()->query('SELECT 1')->fetchColumn(); json_reply(['status'=>'ok','version'=>SQLPRO_VERSION]); }
    if ($path === '/api/config') { require_method('GET'); json_reply(['registration_enabled'=>(bool)(config()['allow_registration']??false),'version'=>SQLPRO_VERSION]); }
    if ($path === '/api/register') {
        require_method('POST'); check_origin();
        if (!(bool)(config()['allow_registration'] ?? false)) fail(403,'Cadastro público desativado. Solicite sua conta ao administrador.');
        $input=read_json(); $email=valid_email($input['email']??'');$password=valid_password($input['password']??'');
        $ip=remote_ip();
        if (is_throttled('register-ip', $ip, 5, 60)) fail(429,'Muitas tentativas. Aguarde.');
        record_failure('register-ip',$ip,5,60);
        try { stmt("INSERT INTO users(email,password_hash,role,status,created_at) VALUES (?,?,'user','active',UTC_TIMESTAMP())", [$email,password_hash($password,PASSWORD_ARGON2ID)]); }
        catch (PDOException $e) { if (($e->errorInfo[1] ?? null) == 1062) fail(409,'E-mail já cadastrado.'); throw $e; }
        $id=(int)db()->lastInsertId(); $s=create_session($id);audit($id,'user.register');
        json_reply(['user'=>['email'=>$email,'admin'=>false],...$s],201);
    }
    if ($path === '/api/login') {
        require_method('POST'); check_origin();
        $input=read_json(); $email=valid_email($input['email']??'');$pass=(string)($input['password']??'');
        if(strlen($pass)>512) fail(422,'Senha inválida.');
        $ip=remote_ip();
        if(is_throttled('login-ip',$ip,12,15)||is_throttled('login-email',$email,20,15)) fail(429,'Muitas tentativas. Tente novamente mais tarde.');
        $user=stmt('SELECT id,email,password_hash,role,status FROM users WHERE email=? LIMIT 1',[$email])->fetch();
        $good=$user && $user['status']==='active' && password_verify($pass,$user['password_hash']);
        if(!$good) {
            record_failure('login-ip',$ip,12,15);record_failure('login-email',$email,20,15);
            fail(401,'E-mail ou senha inválidos.');
        }
        clear_throttle('login-email',$email);
        // Do not delete the IP throttle on success: prevents attackers cycling credentials.
        if(password_needs_rehash($user['password_hash'], PASSWORD_ARGON2ID)) stmt('UPDATE users SET password_hash=? WHERE id=?',[password_hash($pass,PASSWORD_ARGON2ID),$user['id']]);
        $old=$_COOKIE[SQLPRO_COOKIE]??'';
        if(is_string($old)&&preg_match('/^[a-f0-9]{64}$/D',$old)) stmt('DELETE FROM auth_sessions WHERE token_hash=?',[hash('sha256',$old)]);
        $session=create_session((int)$user['id']);
        stmt('UPDATE users SET last_login_at=UTC_TIMESTAMP() WHERE id=?',[$user['id']]);
        audit((int)$user['id'],'user.login');
        json_reply(['user'=>public_user($user),...$session]);
    }
    if ($path === '/api/account/password') {
        require_method('POST');$a=require_auth();check_csrf($a);$v=read_json();
        $old=(string)($v['old_password']??'');$new=valid_password($v['new_password']??'');
        $row=stmt('SELECT password_hash FROM users WHERE id=?',[$a['id']])->fetch();
        if(!$row || !password_verify($old,$row['password_hash']))fail(403,'Senha atual incorreta.');
        if(password_verify($new,$row['password_hash']))fail(422,'A nova senha precisa ser diferente.');
        stmt('UPDATE users SET password_hash=? WHERE id=?',[password_hash($new,PASSWORD_ARGON2ID),$a['id']]);
        stmt('DELETE FROM auth_sessions WHERE user_id=? AND token_hash<>?',[$a['id'],hash('sha256',(string)$_COOKIE[SQLPRO_COOKIE])]);
        audit($a['id'],'user.password.change');json_reply(['ok'=>true]);
    }
    if ($path === '/api/me') {require_method('GET');$a=require_auth();json_reply(['email'=>$a['email'],'admin'=>$a['admin']]);}
    if ($path === '/api/csrf') {require_method('GET');$a=require_auth();json_reply(['csrf'=>csrf_rotate($a)]);}
    if ($path === '/api/logout') {require_method('POST');$a=require_auth();check_csrf($a);stmt('DELETE FROM auth_sessions WHERE token_hash=?',[hash('sha256',(string)$_COOKIE[SQLPRO_COOKIE])]);audit($a['id'],'user.logout');clean_session_cookie();json_reply(['ok'=>true]);}
    if ($path === '/api/portal/apps') {
        require_method('GET');$a=require_auth();
        $rows=stmt('SELECT a.slug AS id,a.name,a.url,a.description,a.category,a.icon FROM grants g JOIN apps a ON a.slug=g.app_slug WHERE g.user_id=? AND g.active=1 AND a.enabled=1 AND (g.expires_at IS NULL OR g.expires_at>UTC_TIMESTAMP()) ORDER BY a.name',[$a['id']])->fetchAll();
        foreach($rows as &$row){unset($row['url']);$row['featured']=false;$row['tags']=[];}unset($row);
        json_reply($rows);
    }
    if(preg_match('~^/api/portal/launch/([^/]+)$~D',$path,$m)) {
        require_method('GET');$a=require_auth();$slug=valid_slug(rawurldecode($m[1]));
        $app=stmt('SELECT a.url FROM grants g JOIN apps a ON g.app_slug=a.slug WHERE g.user_id=? AND g.app_slug=? AND g.active=1 AND a.enabled=1 AND (g.expires_at IS NULL OR g.expires_at>UTC_TIMESTAMP()) LIMIT 1',[$a['id'],$slug])->fetch();
        if(!$app) fail(403,'Aplicativo não liberado ou licença expirada.');
        $url=valid_url($app['url']);
        audit($a['id'],'app.launch',$slug);
        http_response_code(302);header('Cache-Control: no-store');header('Referrer-Policy: no-referrer');header('Location: '.$url);exit;
    }
    if (str_starts_with($path,'/api/admin/')) {
        $admin=require_admin();
        if($method==='POST')check_csrf($admin);
        if($path==='/api/admin/stats'){
            require_method('GET');
            $users=(int)db()->query('SELECT COUNT(*) FROM users')->fetchColumn();
            $sessions=(int)db()->query('SELECT COUNT(*) FROM auth_sessions WHERE expires_at>UTC_TIMESTAMP()')->fetchColumn();
            json_reply(['users'=>$users,'active_sessions'=>$sessions]);
        }
        if($path==='/api/admin/apps'){
            if($method==='GET') {
                $rows=stmt('SELECT slug AS id,name,url,description,category,icon,enabled FROM apps ORDER BY name')->fetchAll();
                foreach($rows as &$r)$r['enabled']=(bool)$r['enabled'];unset($r);
                json_reply($rows);
            }
            require_method('POST');$v=read_json();$slug=valid_slug($v['slug']??'');$name=trim((string)($v['name']??''));$url=valid_url($v['url']??'');$desc=trim((string)($v['description']??''));$cat=trim((string)($v['category']??'Aplicativos'));$icon=trim((string)($v['icon']??'🔗'));
            if(!$name || strlen($name)>200 || !$cat || strlen($cat)>120 || strlen($desc)>560 || strlen($icon)>80)fail(422,'Campos do aplicativo excedem limites.');
            $enabled=array_key_exists('enabled',$v)?($v['enabled']===true?1:0):1;
            stmt('INSERT INTO apps(slug,name,url,description,category,icon,enabled) VALUES (?,?,?,?,?,?,?) ON DUPLICATE KEY UPDATE name=VALUES(name),url=VALUES(url),description=VALUES(description),category=VALUES(category),icon=VALUES(icon),enabled=VALUES(enabled)',[$slug,mb_limit($name,65),$url,mb_limit($desc,140),mb_limit($cat,35),mb_limit($icon,20),$enabled]);
            audit($admin['id'],'admin.app.save',$slug);json_reply(['ok'=>true]);
        }
        if($path==='/api/admin/grants'){
            if($method==='GET'){
                $rows=stmt('SELECT u.email,g.app_slug AS slug,g.active,g.expires_at FROM grants g JOIN users u ON g.user_id=u.id ORDER BY u.email,g.app_slug')->fetchAll();
                foreach($rows as &$r){$r['active']=(bool)$r['active'];if($r['expires_at']!==null)$r['expires_at']=gmdate('Y-m-d\TH:i:s\Z',strtotime($r['expires_at'].' UTC'));}unset($r);
                json_reply($rows);
            }
            require_method('POST');$v=read_json();$email=valid_email($v['email']??'');$slug=valid_slug($v['slug']??'');$activeField=$v['active']??null;if(!is_bool($activeField))fail(422,'Status de licença inválido.');$active=$activeField; $expiry=valid_expiry($v['expires_at']??null);
            $u=stmt('SELECT id FROM users WHERE email=?',[$email])->fetch();if(!$u)fail(404,'Usuário não encontrado.');
            $app=stmt('SELECT slug FROM apps WHERE slug=?',[$slug])->fetch();if(!$app)fail(404,'Aplicativo não encontrado.');
            stmt('INSERT INTO grants(user_id,app_slug,active,expires_at) VALUES (?,?,?,?) ON DUPLICATE KEY UPDATE active=VALUES(active),expires_at=VALUES(expires_at)',[$u['id'],$slug,$active?1:0,$expiry]);
            audit($admin['id'],$active?'admin.grant.allow':'admin.grant.revoke',$slug);
            json_reply(['ok'=>true]);
        }
        if($path==='/api/admin/users'){
            if($method==='GET'){
                $rows=stmt('SELECT email,role,status,created_at FROM users ORDER BY created_at DESC LIMIT 500')->fetchAll();json_reply($rows);
            }
            require_method('POST');$v=read_json();$email=valid_email($v['email']??'');$pass=valid_password($v['password']??'');
            try{stmt("INSERT INTO users(email,password_hash,role,status,created_at) VALUES (?,?,'user','active',UTC_TIMESTAMP())",[$email,password_hash($pass,PASSWORD_ARGON2ID)]);}
            catch(PDOException $e){if(($e->errorInfo[1]??null)==1062)fail(409,'E-mail já cadastrado.');throw $e;}
            audit($admin['id'],'admin.user.create');json_reply(['ok'=>true],201);
        }
        if($path==='/api/admin/user-status'){
            require_method('POST');$v=read_json();$email=valid_email($v['email']??'');$enabled=$v['active']??null;if(!is_bool($enabled))fail(422,'Status inválido.');
            $u=stmt('SELECT id,role FROM users WHERE email=?',[$email])->fetch();if(!$u)fail(404,'Usuário não encontrado.');
            if($u['role']==='admin')fail(403,'Esta operação não altera administradores.');
            stmt('UPDATE users SET status=? WHERE id=?',[$enabled?'active':'disabled',$u['id']]);
            if(!$enabled) stmt('DELETE FROM auth_sessions WHERE user_id=?',[$u['id']]);
            audit($admin['id'],'admin.user.status',$enabled?'enable':'disable');json_reply(['ok'=>true]);
        }
        fail(404,'Rota administrativa desconhecida.');
    }
    fail(404,'Rota de API não encontrada.');
}
