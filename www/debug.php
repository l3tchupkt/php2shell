<?php
header('Content-Type: text/plain');
echo "=== PHP2Shell Debug ===\n";
echo "PHP: " . phpversion() . "\n";
echo "upload_progress.enabled: " . ini_get('session.upload_progress.enabled') . "\n";
echo "upload_progress.cleanup: " . ini_get('session.upload_progress.cleanup') . "\n";
echo "upload_progress.name: " . ini_get('session.upload_progress.name') . "\n";
echo "save_path: " . ini_get('session.save_path') . "\n";
echo "use_strict_mode: " . ini_get('session.use_strict_mode') . "\n";
echo "use_only_cookies: " . ini_get('session.use_only_cookies') . "\n\n";

$path = session_save_path();
echo "Session dir writable: " . (is_writable($path) ? "YES" : "NO") . "\n\n";

echo "=== Session Files ===\n";
foreach (glob("$path/sess_*") as $f) {
    echo basename($f) . " (" . filesize($f) . "b): ";
    echo file_get_contents($f) . "\n\n";
}
if (!glob("$path/sess_*")) echo "(none)\n";

echo "\n=== Request ===\n";
echo "Cookie PHPSESSID: " . ($_COOKIE['PHPSESSID'] ?? '(not set)') . "\n";
echo "POST keys: " . implode(', ', array_keys($_POST)) . "\n";
echo "FILES keys: " . implode(', ', array_keys($_FILES)) . "\n";
