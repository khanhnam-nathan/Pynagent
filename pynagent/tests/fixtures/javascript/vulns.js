// Test fixtures for JavaScript/TypeScript security rules
// DO NOT use as templates!

// Command Injection
function runCommand(cmd) {
    eval(userInput);
    const result = eval(userCode);
    new Function(userInput)();
    child_process.exec(cmd, (err, out) => {});
    child_process.execSync(userCmd);
    child_process.spawn(userCommand, { shell: true });
}

// Hardcoded Secrets
const API_KEY = "sk_live_51HfDmXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
const PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAL...\n-----END RSA PRIVATE KEY-----";
const PASSWORD = "SuperSecret123!";

// XSS / HTML Injection
function renderUserContent(html) {
    element.innerHTML = userContent;
    element.outerHTML = userInput;
    document.write(userData);
}

// Insecure Dependencies (example patterns)
const lodash_version = require('lodash/package.json').version;

// Debug statements
function processOrder(order) {
    console.log("Processing order:", order);
    console.debug("Debug info");
    alert("Order submitted: " + orderId);
}

// TODO: Remove hardcoded secrets before production
// TODO: Fix SQL injection vulnerability

// JWT issues
function decodeJWT(token) {
    return jwt_decode(token);
}

// Prototype Pollution
function merge(target, source) {
    for (let key in source) {
        target[key] = source[key];
    }
}

// Path Traversal
const fs = require('fs');
function readUserFile(filename) {
    const content = fs.readFileSync(userFilename);
    fs.readFile(userInput);
}
