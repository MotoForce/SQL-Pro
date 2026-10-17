<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/sqlpro-core/bootstrap.php';
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
header('Cache-Control: no-store, private');
if (is_https()) header('Strict-Transport-Security: max-age=31536000');
$path=parse_url($_SERVER['REQUEST_URI']??'/',PHP_URL_PATH);
$path=is_string($path) ? rtrim($path,'/') : '/';if($path==='')$path='/';
try {
    if(str_starts_with($path,'/api/')){require_once dirname(__DIR__) . '/sqlpro-core/api.php';api_route($path);}
    if(!installed()){header('Location: /install.php',true,302);exit;}
    if($path==='/panel') {
        $auth=current_auth();if(!$auth){header('Location: /',true,303);exit;}
        $html=file_get_contents(dirname(__DIR__).'/sqlpro-core/panel_sqlpro.html');
        if($html===false) throw new RuntimeException('Painel indisponível.');
        preg_match('~<style>(.*?)</style>~s',$html,$s);preg_match('~<script>(.*?)</script>~s',$html,$j);
        $cssHash=!empty($s[1]) ? " 'sha256-".base64_encode(hash('sha256',$s[1],true))."'" : '';
        $jsHash=!empty($j[1]) ? " 'sha256-".base64_encode(hash('sha256',$j[1],true))."'" : '';
        header("Content-Security-Policy: default-src 'none'; script-src 'self'".$jsHash."; style-src 'self' 'unsafe-inline'".$cssHash."; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'");
        header('Content-Type: text/html; charset=utf-8');echo $html;exit;
    }
    if($path==='/'){
        header("Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
        header('Content-Type: text/html; charset=utf-8');readfile(__DIR__.'/assets/index.html');exit;
    }
    http_response_code(404);echo '404 — Endereço não encontrado.';
} catch (Throwable $e) {
    error_log('SQL Pro: '.get_class($e).' '.$e->getMessage());
    if(str_starts_with($path,'/api/'))fail(503,'Serviço temporariamente indisponível. Verifique a configuração do banco.');
    http_response_code(503);header('Content-Type: text/html; charset=utf-8');echo '<!doctype html><html lang="pt-BR"><meta charset="utf-8"><title>SQL Pro indisponível</title><body style="font-family:system-ui;max-width:620px;margin:10vh auto;padding:24px"><h1>SQL Pro temporariamente indisponível</h1><p>Verifique o banco de dados e o registro de erros do servidor.</p></body></html>';
}
