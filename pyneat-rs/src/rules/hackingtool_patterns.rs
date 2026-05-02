//! Hackingtool-Inspired Security Rules for PyNEAT
//!
//! Copyright (C) 2026 PyNEAT Authors
//!
//! Detects patterns from offensive security tools: phishing, rogue AP,
//! backdoors, C2, surveillance, credential attacks, MITM.

use crate::rules::base::{extract_snippet, Fix, Finding, Rule, Severity};
use once_cell::sync::Lazy;
use regex::Regex;
use tree_sitter::Tree;

static SEC118_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r##"SocialFish\.py.*(?:'|")[root|admin|user](?:'|").*(?:'|")[pass|password](?:'|")"##, "Hardcoded credentials in social engineering tool"),
    (r##"(?i)(?:maskphish|maskurl|hide.*url|url.*mask)"##, "URL masking/hiding tool"),
    (r##"(?i)(?:otp\s*phishing|phishing.*otp|otp.*bypass)"##, "OTP phishing pattern"),
    (r##"(?i)(?:login\.html.*password|index\.html.*credential|post\.php.*username)"##, "Landing page with credential harvesting"),
    (r##"(?i)(?:evilginx|evil\.ginx|phishing.*proxy|credential.*proxy)"##, "Phishing proxy / MITM credential capture"),
    (r##"(?i)(?:HiddenEye|hidden.*eye.*phish)"##, "HiddenEye phishing tool"),
    (r##"(?i)(?:blackeye|black.*eye.*phish)"##, "BlackEye phishing toolkit"),
    (r##"header\s*\(\s*['"]Location:\s*['"].*post"##, "Phishing redirect pattern"),
    (r##"(?i)(?:document\.getElementById.*password.*innerHTML|keylogger.*document)"##, "Browser-side credential harvesting"),
]);

pub struct SocialEngineeringRule;
impl Rule for SocialEngineeringRule {
    fn id(&self) -> &str { "SEC-118" }
    fn name(&self) -> &str { "Social Engineering / Phishing Patterns" }
    fn severity(&self) -> Severity { Severity::High }
    fn supported_languages(&self) -> Option<&'static [&'static str]> { Some(&["python", "bash", "shell", "html", "javascript", "php"]) }
    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (pattern, problem) in SEC118_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-118".to_string(),
                        severity: Severity::High.as_str().to_string(),
                        cwe_id: Some("CWE-1021".to_string()),
                        cvss_score: Some(8.6),
                        owasp_id: Some("A01:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: problem.to_string(),
                        fix_hint: "Review for social engineering intent. Remove hardcoded credentials. Phishing tools only for authorized pentesting.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }
    fn fix(&self, _: &Finding, _: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

static SEC119_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r##"(?i)(?:wifipumpkin|wifipumpkin3)"##, "WiFi-Pumpkin rogue access point framework"),
    (r##"(?i)(?:fluxion|fluxion\.sh)"##, "Fluxion evil twin attack tool"),
    (r##"(?i)(?:wifiphisher|wifiphisher\.sh)"##, "Wifiphisher evil twin tool"),
    (r##"(?i)(?:evil.*twin|fakeap|fake.*ap)"##, "Evil Twin / Fake AP pattern"),
    (r##"(?i)(?:hostapd.*create.*fake.*ap|hostapd.*rogue)"##, "Rogue access point via hostapd"),
    (r##"(?i)(?:dnsmasq.*fake.*dhcp|dnsmasq.*rogue)"##, "Rogue DHCP/DNS via dnsmasq"),
    (r##"(?i)(?:airbase-ng|deauth.*attack|aireplay.*deauth)"##, "WiFi deauthentication attack"),
    (r##"(?i)(?:rogue.*ap.*mitm|mitm.*rogue.*ap)"##, "Rogue AP with MITM attack"),
    (r##"(?i)(?:ettercap.*filter.*spoof|ettercap.*arp.*spoof)"##, "ARP spoofing via Ettercap"),
]);

pub struct RogueAccessPointRule;
impl Rule for RogueAccessPointRule {
    fn id(&self) -> &str { "SEC-119" }
    fn name(&self) -> &str { "Rogue Access Point / Evil Twin Patterns" }
    fn severity(&self) -> Severity { Severity::High }
    fn supported_languages(&self) -> Option<&'static [&'static str]> { Some(&["python", "bash", "shell"]) }
    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (pattern, problem) in SEC119_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-119".to_string(),
                        severity: Severity::High.as_str().to_string(),
                        cwe_id: Some("CWE-669".to_string()),
                        cvss_score: Some(7.4),
                        owasp_id: Some("A01:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: problem.to_string(),
                        fix_hint: "Rogue AP tools create fake WiFi networks. Only for authorized red team engagements.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }
    fn fix(&self, _: &Finding, _: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

static SEC120_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r##"curl\s+.*\|\s*(?:sudo\s+)?bash|curl\s+-sSL.*\|\s*(?:sudo\s+)?bash"##, "curl piped to bash - RCE risk"),
    (r##"wget\s+.*\|\s*(?:sudo\s+)?bash|wget\s+-O\s+-.*\|\s*bash"##, "wget piped to bash - RCE risk"),
    (r##"(?i)(?:sudo\s+pip3?\s+install|sudo\s+pip\s+install)"##, "pip install as root - system-wide risk"),
    (r##"git\s+clone\s+.*&&\s*cd\s+.*&&\s*(?:sudo\s+)?(?:pip|apt-get|make|bash|chmod)"##, "git clone pipeline with privilege escalation"),
    (r##"git\s+clone\s+.*&&\s*(?:sudo\s+)?bash\s*\|"##, "git clone followed by interactive shell"),
    (r##"(?i)(?:pip\s+install\s+https?://(?:raw\.githubusercontent|pastebin|gist))"##, "pip install from untrusted URL"),
    (r##"(?i)(?:chmod\s+777|chmod\s+-R\s+777|chmod\s+0755|chmod\s+755)"##, "Overly permissive file permissions"),
    (r##"(?i)(?:sudo\s+su|sudo\s+-i|su\s+-\s*root)"##, "Interactive root shell spawned"),
    (r##"python3?\s+-c\s+['\"].*(?:import|exec|system|pty)"##, "Python one-liner with shell execution"),
    (r##"(?i)(?:pty\.spawn|os\.fork.*exec|spawn.*pseudo)"##, "PTY spawn for interactive shell"),
    (r##"curl\s+[^|]*\|\s*(?:python|bash|sh)\s*(?!-)"##, "Unvalidated remote script execution"),
]);

pub struct InsecureInstallPipelineRule;
impl Rule for InsecureInstallPipelineRule {
    fn id(&self) -> &str { "SEC-120" }
    fn name(&self) -> &str { "Insecure Installation Pipeline Patterns" }
    fn severity(&self) -> Severity { Severity::High }
    fn supported_languages(&self) -> Option<&'static [&'static str]> { Some(&["python", "bash", "shell"]) }
    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (pattern, problem) in SEC120_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-120".to_string(),
                        severity: Severity::High.as_str().to_string(),
                        cwe_id: Some("CWE-347".to_string()),
                        cvss_score: Some(7.5),
                        owasp_id: Some("A03:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: problem.to_string(),
                        fix_hint: "Download scripts to file first and inspect. Use venv for pip. Verify checksums. Prefer package managers.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }
    fn fix(&self, _: &Finding, _: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

static SEC121_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r##"(?i)(?:keylog|key.*log|keyboard.*record|key.*capture|key.*sniff)"##, "Keylogger / keyboard capture"),
    (r##"(?i)(?:pynput.*keyboard|pynput.*key|keyboard.*listener|keyboard.*hook)"##, "Keyboard input hooking (keylogger)"),
    (r##"(?i)(?:pyHook|pyhook|windows.*hook.*key|SetWindowsHookEx.*keyboard)"##, "Windows keyboard hook for keylogging"),
    (r##"(?i)(?:saycheese|say.*cheese|webcam.*capture|capture.*webcam|webcam.*snapshot)"##, "Webcam capture / surveillance tool"),
    (r##"(?i)(?:opencv.*VideoCapture|cv2\.VideoCapture|video.*capture.*webcam)"##, "OpenCV webcam capture"),
    (r##"(?i)(?:fswebcam|stream.*webcam|webcam.*stream|snapshot.*camera)"##, "Webcam snapshot/stream tool"),
    (r##"(?i)(?:msfvenom.*webcam|screenshot.*loop|screen.*capture.*every|screen.*log)"##, "Screen/webcam capture with persistence"),
    (r##"(?i)(?:microphone.*record|audio.*record.*device|record.*mic|pyaudio.*record)"##, "Microphone recording / audio surveillance"),
    (r##"(?i)(?:chrome.*history|firefox.*history|browser.*history.*steal|steal.*credential)"##, "Browser credential/history theft"),
    (r##"(?i)(?:herakeylogger|HeraKeylogger|chrome.*keylog|keylog.*chrome)"##, "Chrome keylogger pattern"),
    (r##"(?i)(?:clipboard.*read|pyperclip.*read|tkinter.*clipboard.*get)"##, "Clipboard content theft"),
]);

pub struct SurveillanceToolRule;
impl Rule for SurveillanceToolRule {
    fn id(&self) -> &str { "SEC-121" }
    fn name(&self) -> &str { "Surveillance / Keylogger / Webcam Hijacking Patterns" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn supported_languages(&self) -> Option<&'static [&'static str]> { Some(&["python", "bash", "shell", "javascript"]) }
    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (pattern, problem) in SEC121_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-121".to_string(),
                        severity: Severity::Critical.as_str().to_string(),
                        cwe_id: Some("CWE-200".to_string()),
                        cvss_score: Some(9.1),
                        owasp_id: Some("A01:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: problem.to_string(),
                        fix_hint: "Surveillance tools without consent are illegal. Requires immediate security review.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }
    fn fix(&self, _: &Finding, _: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

static SEC122_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r##"(?i)(?:sliver|mythic|havoc|covenant|powertools|koadic|merlin)"##, "C2 framework signature"),
    (r##"(?i)(?:pwncat|pwncat-cs|Empire|empire.*ps1|cobalt.*strike)"##, "C2 / RAT framework signature"),
    (r##"(?i)(?:reverse.*shell|rev.*shell|bind.*shell|nc.*-e|ncat.*-e)"##, "Reverse shell handler pattern"),
    (r##"(?i)(?:pentestmonkey|reverse.*shell.*php|rm\s+/tmp/f\;mkfifo)"##, "Reverse shell one-liner"),
    (r##"(?i)(?:meterpreter|msf.*payload|msfvenom.*meterpreter)"##, "Meterpreter / Metasploit payload"),
    (r##"/bin/(?:ba)?sh.*-i|/dev/tcp|bash.*-i.*udp"##, "Interactive shell from network payload"),
    (r##"(?i)(?:powershell.*-enc|powershell.*-encoded|iex.*web.*client|downloadstring)"##, "PowerShell RCE / C2 pattern"),
    (r##"(?i)(?:cron.*reverse|crontab.*reverse|systemd.*reverse|persistence.*cron)"##, "Persistence mechanism for C2"),
    (r##"(?i)(?:while.*true.*sleep.*http|beacon.*sleep|check.*in.*interval)"##, "Beaconing for C2 communication"),
    (r##"(?i)(?:msfconsole.*handler|exploit.*multi.*handler|set.*payload.*reverse)"##, "Metasploit multi-handler"),
]);

pub struct C2FrameworkRule;
impl Rule for C2FrameworkRule {
    fn id(&self) -> &str { "SEC-122" }
    fn name(&self) -> &str { "C2 Framework / RAT Communication Patterns" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn supported_languages(&self) -> Option<&'static [&'static str]> { Some(&["python", "bash", "shell", "powershell"]) }
    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (pattern, problem) in SEC122_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-122".to_string(),
                        severity: Severity::Critical.as_str().to_string(),
                        cwe_id: Some("CWE-506".to_string()),
                        cvss_score: Some(9.8),
                        owasp_id: Some("A01:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: problem.to_string(),
                        fix_hint: "C2/RAT patterns indicate compromise. Investigate source. Check persistence. Never in production code.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }
    fn fix(&self, _: &Finding, _: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

static SEC123_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r##"(?i)(?:backdoor|rootkit|veil|shellcode.*inject|inject.*shell)"##, "Backdoor / rootkit / shellcode injection"),
    (r##"(?i)(?:msfvenom.*-p\s+(?:linux|windows|php|java|python).*Meterpreter)"##, "Metasploit Meterpreter payload generation"),
    (r##"(?i)(?:msfvenom.*-p\s+.*--format\s+(?:exe|php|asp|war|jsp))"##, "Metasploit cross-platform payload"),
    (r##"(?i)(?:TheFatRat|fatrat.*backdoor|fatrat.*payload)"##, "TheFatRat backdoor creation"),
    (r##"(?i)(?:steganography.*inject|steg.*payload|hide.*payload.*image|image.*payload.*inject)"##, "Steganographic payload hiding"),
    (r##"(?i)(?:Vegile|ghost.*shell|rootkit.*inject|inject.*rootkit)"##, "Vegile ghost-in-the-shell rootkit"),
    (r##"(?i)(?:hide.*process|hidden.*process|libprocess|process.*inject)"##, "Process hiding / injection"),
    (r##"(?i)(?:HKLM.*Run|HKCU.*Run|startup.*reg|registry.*persist)"##, "Windows registry persistence"),
    (r##"(?i)(?:\.(?:bashrc|bash_profile|profile|zshrc).*reverse|rc.*local.*reverse)"##, "Shell RC file persistence for backdoor"),
    (r##"(?i)(?:msf.*encode|x86/shikata|shellcode.*encode|av.*evasion)"##, "AV evasion / shellcode encoding"),
    (r##"(?i)(?:dropper|download.*payload|fetch.*payload|write.*binary.*disk)"##, "Payload dropper pattern"),
    (r##"(?i)(?:hid.*attack|badusb|usb.*rubber|keyboard.*inject.*device)"##, "HID/BadUSB attack pattern"),
]);

pub struct BackdoorRootkitRule;
impl Rule for BackdoorRootkitRule {
    fn id(&self) -> &str { "SEC-123" }
    fn name(&self) -> &str { "Backdoor / Rootkit / Payload Dropper Patterns" }
    fn severity(&self) -> Severity { Severity::Critical }
    fn supported_languages(&self) -> Option<&'static [&'static str]> { Some(&["python", "bash", "shell", "powershell", "c"]) }
    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (pattern, problem) in SEC123_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-123".to_string(),
                        severity: Severity::Critical.as_str().to_string(),
                        cwe_id: Some("CWE-506".to_string()),
                        cvss_score: Some(9.8),
                        owasp_id: Some("A01:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: problem.to_string(),
                        fix_hint: "Backdoor/rootkit patterns indicate severe compromise. Isolate affected systems immediately.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }
    fn fix(&self, _: &Finding, _: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

static SEC124_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r##"(?i)(?:bruteforce.*login|brute.*force.*auth|login.*brute|credential.*brute)"##, "Credential brute-forcing pattern"),
    (r##"(?i)(?:wordlist.*attack|dictionary.*attack|passlist|rockyou|cupp.*-i)"##, "Dictionary/wordlist attack"),
    (r##"(?i)(?:hashcat.*-a\s*0|hashcat.*-m\s*\d|john.*--wordlist|john.*--rules)"##, "Password cracking (hashcat/John)"),
    (r##"(?i)(?:ssh.*brute|brute.*ssh|medusa.*ssh|hydra.*ssh|patator.*ssh)"##, "SSH brute-force attack"),
    (r##"(?i)(?:hydra.*http|hydra.*form|brute.*http.*login|patator.*http)"##, "HTTP login brute-force"),
    (r##"(?i)(?:credential.*stuff|username.*list.*password.*list|stuff.*credential)"##, "Credential stuffing pattern"),
    (r##"(?i)(?:default.*credential|default.*password.*check|brute.*default.*pass)"##, "Default credential checking"),
    (r##"(?i)(?:kerbrute|kerberos.*brute|ASREPRoast|Kerberoast)"##, "Kerberos attack pattern"),
    (r##"(?i)(?:rainbow.*table|md5.*decrypt|sha1.*decrypt|hash.*lookup)"##, "Precomputed hash / rainbow table"),
    (r##"(?i)(?:aircrack|hashcat.*wpa|wpa.*crack|wifi.*crack|pmkid)"##, "WiFi credential cracking"),
]);

pub struct CredentialAttackRule;
impl Rule for CredentialAttackRule {
    fn id(&self) -> &str { "SEC-124" }
    fn name(&self) -> &str { "Password / Credential Attack Patterns" }
    fn severity(&self) -> Severity { Severity::High }
    fn supported_languages(&self) -> Option<&'static [&'static str]> { Some(&["python", "bash", "shell"]) }
    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (pattern, problem) in SEC124_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-124".to_string(),
                        severity: Severity::High.as_str().to_string(),
                        cwe_id: Some("CWE-307".to_string()),
                        cvss_score: Some(7.5),
                        owasp_id: Some("A07:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: problem.to_string(),
                        fix_hint: "Tools for cracking passwords. Legitimate for authorized auditing. Ensure rate limiting, lockout, MFA in production.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }
    fn fix(&self, _: &Finding, _: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

static SEC125_PATTERNS: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    (r##"(?i)(?:scapy\.sniff|sniff.*packets|packet.*capture|tcpdump.*-i)"##, "Network packet sniffing"),
    (r##"(?i)(?:scapy.*ARP.*spoof|arp.*spoof|ettercap.*arp|arpspoof)"##, "ARP spoofing / poisoning"),
    (r##"(?i)(?:bettercap|bettercap.*-X|bettercap.*-P.*HUD|bettercap.*caplet)"##, "Bettercap network attack framework"),
    (r##"(?i)(?:sslstrip|ssl.*strip|https.*downgrade|hstshijack)"##, "SSL/TLS stripping / HTTPS downgrade"),
    (r##"(?i)(?:dns.*spoof|ettercap.*dns|dnspoison|host.*-A.*fake)"##, "DNS spoofing / poisoning"),
    (r##"(?i)(?:mitmproxy|mitmproxy.*-p|mitm.*proxy|man.*in.*the.*middle)"##, "MITM proxy / traffic interception"),
    (r##"(?i)(?:responder.*-I|responder.*LLMNR|llmnr.*spoof|nbtscan)"##, "LLMNR/NBT-NS spoofing via Responder"),
    (r##"(?i)(?:packet.*inject|scapy.*send|craft.*packet.*send|netcut)"##, "Network packet injection"),
    (r##"(?i)(?:tcpdump.*-i.*-A|tcpdump.*-X.*http|tcpdump.*-w.*\.pcap)"##, "TCP dump capturing network traffic"),
]);

pub struct NetworkSniffingRule;
impl Rule for NetworkSniffingRule {
    fn id(&self) -> &str { "SEC-125" }
    fn name(&self) -> &str { "Network Sniffing / MITM / Packet Capture Patterns" }
    fn severity(&self) -> Severity { Severity::High }
    fn supported_languages(&self) -> Option<&'static [&'static str]> { Some(&["python", "bash", "shell"]) }
    fn detect(&self, _tree: &Tree, code: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (pattern, problem) in SEC125_PATTERNS.iter() {
            if let Ok(re) = Regex::new(pattern) {
                for m in re.find_iter(code) {
                    let snippet = extract_snippet(code, m.start(), m.end());
                    findings.push(Finding {
                        rule_id: "SEC-125".to_string(),
                        severity: Severity::High.as_str().to_string(),
                        cwe_id: Some("CWE-311".to_string()),
                        cvss_score: Some(7.5),
                        owasp_id: Some("A01:2021".to_string()),
                        start: m.start(), end: m.end(), snippet,
                        problem: problem.to_string(),
                        fix_hint: "Network sniffing tools. Legitimate for authorized testing. Enforce HTTPS and HSTS to prevent MITM.".to_string(),
                        auto_fix_available: false,
                    });
                }
            }
        }
        findings.sort_by_key(|f| f.start);
        findings
    }
    fn fix(&self, _: &Finding, _: &str) -> Option<Fix> { None }
    fn supports_auto_fix(&self) -> bool { false }
}

pub fn all_hackingtool_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(SocialEngineeringRule),
        Box::new(RogueAccessPointRule),
        Box::new(InsecureInstallPipelineRule),
        Box::new(SurveillanceToolRule),
        Box::new(C2FrameworkRule),
        Box::new(BackdoorRootkitRule),
        Box::new(CredentialAttackRule),
        Box::new(NetworkSniffingRule),
    ]
}
