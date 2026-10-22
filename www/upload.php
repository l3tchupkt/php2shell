<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_FILES['file'])) {
        echo "OK: " . htmlspecialchars(basename($_FILES['file']['name']));
    } else {
        echo "No file.";
    }
} else {
    echo '<form method="POST" enctype="multipart/form-data">';
    echo '<input type="file" name="file"><button>Upload</button></form>';
}
