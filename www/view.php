<?php
// Intentional LFI for PoC — DO NOT use in production
if (isset($_GET['file'])) {
    include($_GET['file']);
}
