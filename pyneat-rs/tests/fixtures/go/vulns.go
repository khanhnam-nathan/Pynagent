// Test fixtures for Go security rules
// DO NOT use as templates!

package main

import (
    "fmt"
    "os/exec"
    "database/sql"
    _ "github.com/lib/pq"
)

func unsafeQuery(userID string) {
    // SQL Injection
    query := "SELECT * FROM users WHERE id=" + userID
    db.Query(query)

    // Command Injection
    cmd := exec.Command("sh", "-c", userInput)
    cmd.Run()
}

func hardcodedSecrets() {
    // Hardcoded password
    password := "SuperSecret123!"

    // API Key
    apiKey := "sk_live_abcdef1234567890"
}

func debugStatements() {
    fmt.Println("Debug: starting process")
    fmt.Printf("User data: %v\n", userData)
}

func weakCrypto() {
    // MD5 for password hashing
    // SHA1 for integrity
    // DES encryption
}

func pathTraversal(filename string) {
    // Unsanitized file access
}
