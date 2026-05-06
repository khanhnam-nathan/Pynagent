// Test fixtures for C# security rules
// DO NOT use as templates!

using System;
using System.Diagnostics;
using System.IO;
using System.Web;
using System.Security.Cryptography;

public class VulnerableCode
{
    // Hardcoded Secrets
    private const string ApiKey = "sk_live_abcdef1234567890";
    private const string Password = "SuperSecret123!";

    // SQL Injection
    public void UnsafeQuery(string userId)
    {
        var query = "SELECT * FROM users WHERE id=" + userId;
        var cmd = new SqlCommand(query, conn);
    }

    // Command Injection
    public void RunCommand(string cmd)
    {
        Process.Start(userInput);
        var psi = new ProcessStartInfo("cmd.exe", "/c " + userCommand);
        Process.Start(psi);
    }

    // Path Traversal
    public string ReadFile(string filename)
    {
        return File.ReadAllText(userFilename);
    }

    // Weak Crypto
    public void WeakCrypto()
    {
        using (var md5 = MD5.Create())
        using (var sha1 = SHA1.Create())
        using (var des = DES.Create())
        {
        }
    }

    // Debug statements
    public void ProcessOrder(string order)
    {
        Console.WriteLine("Processing order: " + order);
    }

    // XSS
    public void RenderContent(string content)
    {
        Response.Write(userContent);
    }
}
