<?php
header('Content-Type: text/html; charset=utf-8');
$progress_on  = ini_get('session.upload_progress.enabled') ? 'ON' : 'OFF';
$cleanup_on   = ini_get('session.upload_progress.cleanup')  ? 'ON' : 'OFF';
?>
<!DOCTYPE html>
<html>
<head><title>php2shell lab</title></head>
<body>
<h1>php2shell PoC Lab</h1>
<table border="1" cellpadding="6" cellspacing="0">
<tr><td>PHP Version</td><td><?= phpversion() ?></td></tr>
<tr><td>SAPI</td><td><?= php_sapi_name() ?></td></tr>
<tr><td>upload_progress</td><td><?= $progress_on ?></td></tr>
<tr><td>progress.cleanup</td><td><?= $cleanup_on ?></td></tr>
<tr><td>progress.name</td><td><?= ini_get('session.upload_progress.name') ?></td></tr>
<tr><td>progress.prefix</td><td><?= ini_get('session.upload_progress.prefix') ?></td></tr>
<tr><td>session.save_path</td><td><?= ini_get('session.save_path') ?></td></tr>
<tr><td>use_strict_mode</td><td><?= ini_get('session.use_strict_mode') ?></td></tr>
<tr><td>use_only_cookies</td><td><?= ini_get('session.use_only_cookies') ?></td></tr>
</table>
<hr>
<?php phpinfo(); ?>
</body>
</html>
