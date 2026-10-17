<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/sqlpro-core/bootstrap.php';
$messages=[];$success=false;
header('Cache-Control: no-store');header('X-Content-Type-Options: nosniff');header('X-Frame-Options: DENY');header('Referrer-Policy: no-referrer');header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
$keyFile=dirname(__DIR__) . '/sqlpro-core/INSTALL_KEY.txt';
$ready=is_file($keyFile) && is_readable($keyFile) && strlen(trim((string)@file_get_contents($keyFile)))>=32;
if ($_SERVER['REQUEST_METHOD']==='POST' && !installed() && $ready) {
    $key=trim((string)(@file_get_contents($keyFile) ?: ''));
    $given=(string)($_POST['install_key']??'');
    if(!hash_equals($key,$given)) $messages[]='Chave de instalação incorreta.';
    elseif(!extension_loaded('pdo_mysql')) $messages[]='Seu plano não possui a extensão pdo_mysql do PHP.';
    elseif(!defined('PASSWORD_ARGON2ID')) $messages[]='Seu PHP não possui suporte a senhas Argon2id.';
    elseif(!extension_loaded('openssl')) $messages[]='Extensão OpenSSL não disponível.';
    else {
        $host=trim((string)($_POST['host']??''));$port=(int)($_POST['port']??3306);$dbName=trim((string)($_POST['database']??''));$user=trim((string)($_POST['db_user']??''));$dbPass=(string)($_POST['db_pass']??'');
        $email=strtolower(trim((string)($_POST['admin_email']??'')));$pass=(string)($_POST['admin_password']??'');
        $site=rtrim(trim((string)($_POST['app_url']??'')),'/');
        $parsed=parse_url($site);$originOk=is_array($parsed) && !isset($parsed['user']) && !isset($parsed['pass']) && empty($parsed['path']) && empty($parsed['query']) && empty($parsed['fragment']) && !empty($parsed['host']);
        $ssl=str_starts_with($site,'https://');$localhost=in_array($site,['http://127.0.0.1:8000','http://localhost:8000'],true);
        if (!preg_match('/^[a-zA-Z0-9.:-]{1,253}$/D',$host)||!preg_match('/^[a-zA-Z0-9_]{1,64}$/D',$dbName)||$port<1||$port>65535||$user===''||strlen($user)>128) $messages[]='Dados de conexão inválidos.';
        if (!filter_var($email,FILTER_VALIDATE_EMAIL)||strlen($email)>254) $messages[]='E-mail administrativo inválido.';
        if(strlen($pass)<15||strlen($pass)>128||!preg_match('/[A-Za-z]/',$pass)||!preg_match('/[0-9]/',$pass)) $messages[]='Senha administrativa deve ter 15 a 128 caracteres, com letras e números.';
        if (!$originOk || (!$ssl&&!$localhost)) $messages[]='Informe apenas a origem HTTPS (sem caminhos ou parâmetros).';
        if($ssl && !is_https()) $messages[]='Abra o instalador por HTTPS antes de configurar.';
        if(!$messages) {
            try {
                $pdo=new PDO('mysql:host='.$host.';port='.$port.';dbname='.$dbName.';charset=utf8mb4',$user,$dbPass,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false,PDO::ATTR_TIMEOUT=>5]);
                require_once dirname(__DIR__) . '/sqlpro-core/schema.php';
                install_schema($pdo);
                if((int)$pdo->query('SELECT COUNT(*) FROM users')->fetchColumn()!==0) throw new RuntimeException('O banco já contém usuários; instale em banco vazio ou recupere sua configuração anterior.');
                $s=$pdo->prepare("INSERT INTO users(email,password_hash,role,status,created_at) VALUES (?,?,'admin','active',UTC_TIMESTAMP())");
                $s->execute([$email,password_hash($pass,PASSWORD_ARGON2ID)]);
                $conf=['db_host'=>$host,'db_port'=>$port,'db_name'=>$dbName,'db_user'=>$user,'db_pass'=>$dbPass,'app_url'=>$site,'app_secret'=>bin2hex(random_bytes(32)),'allow_registration'=>isset($_POST['allow_registration'])];
                $serialized="<?php\n// SQL Pro 3.0 - credenciais privadas; nunca publicar este arquivo.\nreturn ".var_export($conf,true).";\n";
                $temp=dirname(__DIR__).'/sqlpro-core/config.'.bin2hex(random_bytes(8)).'.tmp';
                if(file_put_contents($temp,$serialized,LOCK_EX)===false) throw new RuntimeException('Sem permissão para gravar a configuração privada.');
                @chmod($temp,0600);
                if(!rename($temp,config_file())) throw new RuntimeException('Falha ao concluir configuração.');
                @unlink($keyFile);
                $success=true;
            } catch(Throwable $e) {
                // Do not disclose DSN/password in errors.
                $messages[]=$e instanceof RuntimeException?$e->getMessage():'Falha na instalação. Confira credenciais, privilégios e extensões do PHP.';
                error_log('SQL Pro instalação falhou: '.get_class($e));
            }
        }
    }
}
$installed=installed();
?><!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Instalador SQL Pro 3.0</title><style>
:root{color-scheme:dark;font-family:system-ui,-apple-system,Segoe UI,sans-serif;background:#081726;color:#f3f6fa}*{box-sizing:border-box}body{margin:0;padding:24px 14px}main{width:min(640px,100%);margin:30px auto;background:#10273d;border:1px solid #315069;border-radius:24px;padding:clamp(22px,5vw,38px);box-shadow:0 15px 50px #0004}.eyebrow{color:#edc47d;font-size:12px;font-weight:700;letter-spacing:.12em}h1{font-size:clamp(28px,5vw,38px);margin:8px 0}p{color:#bfd0df;line-height:1.6}form{display:grid;gap:13px;margin-top:22px}label{font-size:14px;font-weight:650;display:grid;gap:6px}input{width:100%;padding:13px 14px;background:#091b2d;border:1px solid #49647d;border-radius:11px;color:#fff;font:inherit}input:focus{outline:2px solid #ecc783}button,.button{background:#ecc783;color:#162639;border:0;border-radius:11px;padding:13px 15px;font-weight:800;font:inherit;text-decoration:none;cursor:pointer}small{color:#afc2d3}.msg{padding:13px;background:#462a35;color:#ffbfc8;border-radius:10px}.good{background:#163f32;color:#bcf7d7}.check{display:flex;gap:10px;align-items:center;font-weight:400}.check input{width:auto}footer{font-size:12px;margin-top:24px;color:#a9bbcd}
</style></head><body><main><span class="eyebrow">SQL PRO • IDENTIDADE SEGURA</span><h1>Instalação 3.0</h1><p>Instale uma única vez. Seus dados e credenciais ficam na pasta privada, fora do diretório público.</p>
<?php if($installed): ?><div class="msg good">Instalação concluída. O instalador está bloqueado. <?php if($success): ?>A chave inicial foi excluída.<?php endif; ?></div><p><a class="button" href="/">Abrir SQL Pro →</a></p>
<?php elseif(!$ready): ?><div class="msg">Instalador bloqueado: crie <code>sqlpro-core/INSTALL_KEY.txt</code> fora da pasta pública, com uma chave secreta aleatória de pelo menos 32 caracteres. Copie essa chave para o formulário depois de atualizar a página.</div>
<?php else: ?>
<?php foreach($messages as $message): ?><p class="msg"><?=htmlspecialchars($message,ENT_QUOTES,'UTF-8')?></p><?php endforeach; ?>
<form method="post" autocomplete="off">
<label>Chave secreta da instalação<input name="install_key" type="password" required minlength="32" autocomplete="off"></label>
<label>Endereço HTTPS definitivo<input name="app_url" type="url" required placeholder="https://painel.limavirtual.online"></label>
<label>Servidor MySQL (DB_HOST)<input name="host" required value="localhost"></label>
<label>Porta MySQL<input name="port" type="number" min="1" max="65535" required value="3306"></label>
<label>Nome do banco<input name="database" required placeholder="sqlpro"></label>
<label>Usuário MySQL<input name="db_user" required placeholder="usuario_sqlpro"></label>
<label>Senha do banco<input name="db_pass" type="password" autocomplete="new-password"></label>
<label>Seu e-mail de administrador<input name="admin_email" type="email" required></label>
<label>Senha administrativa forte<input name="admin_password" type="password" minlength="15" maxlength="128" required autocomplete="new-password"></label>
<label class="check"><input type="checkbox" name="allow_registration" value="1"> Permitir cadastro público de contas (sem verificação de e-mail nesta versão)</label>
<button type="submit">Criar banco e conta administrativa →</button>
</form>
<?php endif; ?><footer>© 2026 Nailson Rodrigues de Lima · SQL Pro 3.0</footer></main></body></html>
