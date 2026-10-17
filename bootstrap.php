<?php
declare(strict_types=1);

const SQLPRO_VERSION = '3.0.0';
const SQLPRO_COOKIE = 'sqlpro_sid';
const SQLPRO_SESSION_SECONDS = 43200; // 12 hours

function config_file(): string { return __DIR__ . '/config.php'; }
function installed(): bool { return is_file(config_file()); }
function config(): array {
    if (!installed()) throw new RuntimeException('Instalação pendente.');
    $c = require config_file();
    if (!is_array($c) || !isset($c['db_host'], $c['db_name'], $c['db_user'], $c['app_url'])) throw new RuntimeException('Configuração inválida.');
    return $c;
}
function db(): PDO {
    static $pdo;
    if ($pdo instanceof PDO) return $pdo;
    $c = config();
    $dsn = 'mysql:host=' . $c['db_host'] . ';port=' . (int) ($c['db_port'] ?? 3306) . ';dbname=' . $c['db_name'] . ';charset=utf8mb4';
    $pdo = new PDO($dsn, $c['db_user'], $c['db_pass'], [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
        PDO::ATTR_TIMEOUT => 5,
    ]);
    return $pdo;
}
function stmt(string $query, array $params = []): PDOStatement {
    $s = db()->prepare($query);
    $s->execute($params);
    return $s;
}
function now_utc(): string { return gmdate('Y-m-d H:i:s'); }
function utc_plus(int $seconds): string { return gmdate('Y-m-d H:i:s', time() + $seconds); }
function json_reply(mixed $data, int $status = 200): never {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store, private');
    echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}
function fail(int $status, string $message): never { json_reply(['detail' => $message, 'error' => $message], $status); }
function read_json(): array {
    if (!str_starts_with(strtolower($_SERVER['CONTENT_TYPE'] ?? ''), 'application/json')) fail(415, 'Use application/json.');
    $content = file_get_contents('php://input', false, null, 0, 16385);
    if ($content === false || strlen($content) > 16384) fail(413, 'Requisição muito grande.');
    try { $obj = json_decode($content, true, 20, JSON_THROW_ON_ERROR); }
    catch (JsonException) { fail(400, 'JSON inválido.'); }
    if (!is_array($obj) || array_is_list($obj) && $obj !== []) fail(400, 'Objeto JSON obrigatório.');
    return $obj;
}
function check_origin(): void {
    $c = config();
    $expect = strtolower(rtrim($c['app_url'], '/'));
    foreach (['HTTP_ORIGIN', 'HTTP_REFERER'] as $key) {
        if (!empty($_SERVER[$key])) {
            $origin = parse_url((string) $_SERVER[$key]);
            if (!is_array($origin) || empty($origin['scheme']) || empty($origin['host'])) fail(403, 'Origem não autorizada.');
            $v = strtolower($origin['scheme'] . '://' . $origin['host'] . (isset($origin['port']) ? ':' . $origin['port'] : ''));
            if (!hash_equals($expect, $v)) fail(403, 'Origem não autorizada.');
        }
    }
}
function require_method(string $method): void {
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== $method) { header('Allow: ' . $method); fail(405, 'Método não permitido.'); }
}
function valid_email(mixed $value): string {
    $v = strtolower(trim((string) $value));
    if (strlen($v) > 254 || !filter_var($v, FILTER_VALIDATE_EMAIL)) fail(422, 'Informe um e-mail válido.');
    return $v;
}
function valid_password(mixed $value): string {
    $v = (string) $value;
    if (strlen($v) < 12 || strlen($v) > 128 || !preg_match('/[A-Za-z]/', $v) || !preg_match('/[0-9]/', $v)) fail(422, 'Use uma senha entre 12 e 128 caracteres, com letras e números.');
    return $v;
}
function is_https(): bool { return (!empty($_SERVER['HTTPS']) && strtolower((string) $_SERVER['HTTPS']) !== 'off') || (int) ($_SERVER['SERVER_PORT'] ?? 0) === 443; }
function cookie_session(string $value, int $expires): void {
    setcookie(SQLPRO_COOKIE, $value, [
        'expires' => $expires, 'path' => '/', 'secure' => is_https() || (installed() && str_starts_with((string)config()['app_url'], 'https://')),
        'httponly' => true, 'samesite' => 'Lax',
    ]);
}
function clean_session_cookie(): void { cookie_session('', time() - 3600); }
function current_auth(): ?array {
    static $cache = false;
    if ($cache !== false) return $cache;
    $token = $_COOKIE[SQLPRO_COOKIE] ?? '';
    if (!is_string($token) || !preg_match('/^[a-f0-9]{64}$/D', $token)) return $cache = null;
    $s = stmt('SELECT s.user_id,s.csrf_hash,s.expires_at,u.email,u.role,u.status FROM auth_sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at > UTC_TIMESTAMP() LIMIT 1', [hash('sha256', $token)])->fetch();
    if (!$s || $s['status'] !== 'active') return $cache = null;
    return $cache = ['id' => (int) $s['user_id'], 'email' => $s['email'], 'admin' => $s['role'] === 'admin', 'csrf_hash' => $s['csrf_hash'], 'expires_at' => $s['expires_at']];
}
function require_auth(): array { $auth = current_auth(); if (!$auth) fail(401, 'Entre na sua conta.'); return $auth; }
function require_admin(): array { $a = require_auth(); if (!$a['admin']) fail(403, 'Permissão administrativa necessária.'); return $a; }
function check_csrf(array $auth): void {
    check_origin();
    $submitted = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if (!is_string($submitted) || !preg_match('/^[a-f0-9]{64}$/D', $submitted) || !hash_equals($auth['csrf_hash'], hash('sha256', $submitted))) fail(403, 'Token CSRF ausente ou inválido.');
}
function create_session(int $userId): array {
    $token = bin2hex(random_bytes(32));
    $csrf = bin2hex(random_bytes(32));
    $expiry = utc_plus(SQLPRO_SESSION_SECONDS);
    stmt('INSERT INTO auth_sessions (token_hash, user_id, csrf_hash, expires_at, created_at) VALUES (?,?,?,?,UTC_TIMESTAMP())', [hash('sha256', $token), $userId, hash('sha256', $csrf), $expiry]);
    cookie_session($token, time() + SQLPRO_SESSION_SECONDS);
    return ['csrf' => $csrf];
}
function csrf_rotate(array $auth): string {
    $csrf = bin2hex(random_bytes(32));
    $token = (string) ($_COOKIE[SQLPRO_COOKIE] ?? '');
    stmt('UPDATE auth_sessions SET csrf_hash=? WHERE token_hash=? AND user_id=?', [hash('sha256', $csrf), hash('sha256', $token), $auth['id']]);
    return $csrf;
}
function public_user(array $user): array { return ['email' => $user['email'], 'admin' => ($user['role'] === 'admin')]; }
function audit(?int $userId, string $action, string $details=''): void {
    try { stmt('INSERT INTO audit_events (actor_user_id, action, details, created_at) VALUES (?,?,?,UTC_TIMESTAMP())', [$userId, $action, mb_limit($details, 200)]); }
    catch (Throwable) { /* Auditing must never expose details to the caller. */ }
}
function mb_limit(string $str, int $max): string { return function_exists('mb_substr') ? mb_substr($str, 0, $max) : substr($str, 0, $max); }
function throttle_id(string $namespace, string $key): string { return hash_hmac('sha256', $namespace . ':' . $key, config()['app_secret']); }
function is_throttled(string $namespace, string $key, int $limit, int $minutes): bool {
    $r = stmt('SELECT attempts,window_start,blocked_until FROM auth_throttle WHERE key_hash=?', [throttle_id($namespace,$key)])->fetch();
    if (!$r) return false;
    if ($r['blocked_until'] !== null && strtotime($r['blocked_until'].' UTC') > time()) return true;
    if (strtotime($r['window_start'].' UTC') < time() - $minutes * 60) return false;
    return (int)$r['attempts'] >= $limit;
}
function record_failure(string $namespace, string $key, int $limit, int $minutes): void {
    $id = throttle_id($namespace, $key);
    // Each upsert is atomic; avoids a race between concurrent attempts.
    stmt('INSERT INTO auth_throttle (key_hash,attempts,window_start,blocked_until) VALUES (?,1,UTC_TIMESTAMP(),NULL) ON DUPLICATE KEY UPDATE attempts=IF(window_start < DATE_SUB(UTC_TIMESTAMP(), INTERVAL '.$minutes.' MINUTE),1,attempts+1), blocked_until=IF(window_start >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL '.$minutes.' MINUTE) AND attempts + 1 >= '.$limit.',DATE_ADD(UTC_TIMESTAMP(), INTERVAL '.$minutes.' MINUTE),NULL),window_start=IF(window_start < DATE_SUB(UTC_TIMESTAMP(), INTERVAL '.$minutes.' MINUTE),UTC_TIMESTAMP(),window_start)', [$id]);
}
function clear_throttle(string $namespace,string $key): void { stmt('DELETE FROM auth_throttle WHERE key_hash=?', [throttle_id($namespace, $key)]); }
function remote_ip(): string { return (string) ($_SERVER['REMOTE_ADDR'] ?? 'unknown'); } // never trust X-Forwarded-For
function valid_slug(mixed $slug): string {
    $v = (string)$slug;
    if (!preg_match('/^[a-z0-9][a-z0-9_-]{0,79}$/D', $v)) fail(422, 'Identificador inválido (letras minúsculas, números, _ ou -).');
    return $v;
}
function valid_url(mixed $value): string {
    $v = trim((string)$value);
    if (strlen($v) > 2048 || !filter_var($v, FILTER_VALIDATE_URL)) fail(422, 'Informe uma URL HTTPS válida.');
    $p = parse_url($v);
    if (!is_array($p) || strtolower((string)($p['scheme'] ?? '')) !== 'https' || empty($p['host']) || isset($p['user']) || isset($p['pass'])) fail(422, 'Informe um endereço HTTPS sem credenciais.');
    return $v;
}
function valid_expiry(mixed $v): ?string {
    if ($v === null || $v === '') return null;
    if (!is_string($v) || !preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/D', $v)) fail(422, 'Validade deve estar em ISO-8601 UTC.');
    $ts = strtotime($v);
    if ($ts === false || $ts < 0 || $ts > strtotime('2100-01-01 UTC')) fail(422, 'Validade inválida.');
    return gmdate('Y-m-d H:i:s', $ts);
}
