<?php
require_once __DIR__ . '/medoo.php';

use Medoo\Medoo;

function loadEnv(string $path): array {
    if (!file_exists($path)) {
        return [];
    }
    $env = [];
    foreach (file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        if (strpos(trim($line), '#') === 0) {
            continue;
        }
        if (!str_contains($line, '=')) {
            continue;
        }
        list($name, $value) = array_map('trim', explode('=', $line, 2));
        $env[$name] = $value;
    }
    return $env;
}
$env = loadEnv(__DIR__ . '/../../.env');

$databaseInfo = [
    'database_type' => 'mysql',
    'database_name' => $env['DB_DATABASE'],
    'server'        => $env['DB_SERVER'] ?? 'localhost',
    'username'      => $env['DB_USERNAME'],
    'password'      => $env['DB_PASSWORD'],
    'charset'       => $env['DB_CHARSET'] ?? 'utf8',
    'collation'     => $env['DB_COLLATE'] ?? 'utf8_unicode_ci', 
];

$database = new Medoo($databaseInfo);
?>
