<?php
// Test fixtures for PHP security rules
// DO NOT use as templates!

// SQL Injection
function unsafeQuery($userId) {
    $query = "SELECT * FROM users WHERE id=" . $userId;
    $result = mysqli_query($conn, $query);
    $pdo->query("SELECT * FROM users WHERE id=" . $userId);
}

// Command Injection
function runCommand($cmd) {
    system($cmd);
    shell_exec($userInput);
    passthru($userCommand);
    exec($userCmd);
    popen($userInput, "r");
}

// XSS / Output
function renderUser($input) {
    echo $userData;
    print($userInput);
}

// Hardcoded Secrets
$apiKey = "sk_live_abcdef1234567890";
$password = "SuperSecret123!";

// eval /动态代码执行
function dynamicCode($code) {
    eval($userCode);
    assert($userExpression);
    preg_replace($pattern, $userReplacement, $subject);
}

// Path Traversal
function readFile($filename) {
    include($userFilename);
    require($userInput);
    readfile($unsafePath);
}

// Debug statements
function processOrder($order) {
    echo "Processing order: " . $order;
    var_dump($data);
    print_r($userData);
}

// Weak Crypto
function hashPassword($pwd) {
    return md5($pwd);
    return sha1($data);
}

// SQLi via LIKE
function searchUsers($term) {
    $result = $pdo->query("SELECT * FROM users WHERE name LIKE '%" . $term . "%'");
}
?>
