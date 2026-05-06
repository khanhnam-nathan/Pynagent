// Test fixtures for TypeScript security rules
// DO NOT use as templates!

// Hardcoded Secrets
const apiKey: string = "sk_test_51HfDmXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
const awsSecret: string = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

// XSS
function render(input: string) {
    document.body.innerHTML = input;
    element.outerHTML = userContent;
}

// Debug statements
function processData(data: any) {
    console.log("Processing:", data);
    console.debug("Debug");
}

// JWT
function parseToken(token: string) {
    return jwt_decode(token);
}
