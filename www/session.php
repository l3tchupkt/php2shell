<?php
session_start();

$action = $_GET['action'] ?? '';

switch ($action) {
    case 'destroy':
        session_destroy();
        echo "destroyed";
        break;
    case 'regenerate':
        session_regenerate_id(true);
        echo "regenerated";
        break;
    case 'gc':
        $old = ini_get('session.gc_maxlifetime');
        ini_set('session.gc_maxlifetime', 0);
        session_gc();
        ini_set('session.gc_maxlifetime', $old);
        echo "gc_done";
        break;
    case 'read':
        header('Content-Type: application/json');
        echo json_encode($_SESSION);
        break;
    default:
        echo "session_ok";
}
