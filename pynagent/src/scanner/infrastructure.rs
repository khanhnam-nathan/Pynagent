//! Infrastructure Security Rules
//!
//! Scans Dockerfile, Kubernetes manifests, and Terraform files for security issues.
//! Severity levels follow CVSS: critical (10), high (8-9), medium (4-7), low (1-3)

use crate::scanner::base::{LangFinding, LangRule};
use crate::scanner::ln_ast::LnAst;
use regex::Regex;

/// Helper: get line text from line number (1-indexed).
fn get_line_text(code: &str, line: usize) -> Option<String> {
    code.lines()
        .nth(line.saturating_sub(1))
        .map(|l| l.to_string())
}

// ─────────────────────────────────────────────────────────────────────────────
// IAC-001: Dockerfile Running as Root
// Severity: high | CWE-250
// ─────────────────────────────────────────────────────────────────────────────
pub struct IacRootUser;

impl LangRule for IacRootUser {
    fn id(&self) -> &str {
        "IAC-001"
    }
    fn name(&self) -> &str {
        "Dockerfile Running as Root"
    }
    fn severity(&self) -> &'static str {
        "high"
    }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];
        let mut has_user_instruction = false;

        let user_root_pattern = Regex::new(r"(?i)^\s*USER\s+root").unwrap();
        let user_0_pattern = Regex::new(r"(?i)^\s*USER\s+0\s*$").unwrap();

        for (line_idx, line) in code.lines().enumerate() {
            let trimmed = line.trim();

            if trimmed.to_uppercase().starts_with("USER ") {
                has_user_instruction = true;

                if user_root_pattern.is_match(trimmed) || user_0_pattern.is_match(trimmed) {
                    findings.push(LangFinding::new(
                        self.id(),
                        self.severity(),
                        line_idx + 1,
                        trimmed,
                        "Container running as root user. This increases the impact of container breakout attacks.",
                        "Use a non-root user with USER directive: USER appuser or USER 1000"
                    ));
                }
            }
        }

        if !has_user_instruction && (code.contains("FROM") || code.contains("RUN")) {
            findings.push(LangFinding::new(
                self.id(),
                self.severity(),
                1,
                "FROM ...",
                "No USER instruction found. Docker defaults to root user if not specified.",
                "Add USER directive to run container as non-root: USER appuser or USER 1000",
            ));
        }

        findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IAC-002: Secrets in Dockerfile
// Severity: critical | CWE-798
// ─────────────────────────────────────────────────────────────────────────────
pub struct IacDockerSecret;

impl LangRule for IacDockerSecret {
    fn id(&self) -> &str {
        "IAC-002"
    }
    fn name(&self) -> &str {
        "Secrets in Dockerfile"
    }
    fn severity(&self) -> &'static str {
        "critical"
    }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let env_secret_pattern = Regex::new(r"(?i)^\s*ENV\s+(API_KEY|SECRET_KEY|PASSWORD|PASSWD|PWD|ACCESS_KEY|SECRET|TOKEN|AUTH).*=").unwrap();
        let aws_key_pattern =
            Regex::new(r"(?i)^\s*ENV\s+AWS_(ACCESS_KEY_ID|SECRET_ACCESS_KEY| SECRET_KEY).*=")
                .unwrap();
        let copy_env_pattern =
            Regex::new(r"(?i)^\s*COPY\s+(\.env|\.env\.\w+|\.env\.\w+\.\w+)").unwrap();
        let arg_secret_pattern =
            Regex::new(r"(?i)^\s*ARG\s+\w*(PASSWORD|SECRET|KEY|TOKEN|API_KEY)\w*=.*").unwrap();
        let echo_secret_pattern =
            Regex::new(r"(?i)RUN\s+.*\$\w*(PASSWORD|SECRET|KEY|TOKEN).*").unwrap();

        for (line_idx, line) in code.lines().enumerate() {
            let trimmed = line.trim();

            if env_secret_pattern.is_match(trimmed) || aws_key_pattern.is_match(trimmed) {
                findings.push(LangFinding::new(
                    self.id(),
                    self.severity(),
                    line_idx + 1,
                    trimmed,
                    "Hardcoded secret detected in ENV instruction. Secrets in Dockerfiles can be extracted from image layers.",
                    "Use Docker secrets, environment variables from secure vault, or build arguments passed at build time only"
                ));
            }

            if copy_env_pattern.is_match(trimmed) {
                let caps = copy_env_pattern.captures(trimmed).unwrap();
                let env_file = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                findings.push(LangFinding::new(
                    self.id(),
                    self.severity(),
                    line_idx + 1,
                    trimmed,
                    &format!("Copying {} file which may contain secrets. Environment files should not be baked into images.", env_file),
                    "Remove .env files from Dockerfile and use runtime environment variables or Docker secrets"
                ));
            }

            if arg_secret_pattern.is_match(trimmed) {
                findings.push(LangFinding::new(
                    self.id(),
                    self.severity(),
                    line_idx + 1,
                    trimmed,
                    "ARG instruction with default secret value. Build arguments with defaults may be exposed in image history.",
                    "Use multi-stage builds and pass secrets only at build time without defaults"
                ));
            }

            if echo_secret_pattern.is_match(trimmed) {
                findings.push(LangFinding::new(
                    self.id(),
                    self.severity(),
                    line_idx + 1,
                    trimmed,
                    "Potential secret exposure in RUN command. Commands echoing secrets may be visible in image layers.",
                    "Avoid echoing secrets in shell commands. Use Docker secrets for sensitive data"
                ));
            }
        }

        findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IAC-003: Unpinned Base Image
// Severity: medium | CWE-1357
// ─────────────────────────────────────────────────────────────────────────────
pub struct IacUnpinnedImage;

impl LangRule for IacUnpinnedImage {
    fn id(&self) -> &str {
        "IAC-003"
    }
    fn name(&self) -> &str {
        "Unpinned Base Image"
    }
    fn severity(&self) -> &'static str {
        "medium"
    }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let from_pattern = Regex::new(r"(?i)^\s*FROM\s+([^@\s]+)").unwrap();

        for (line_idx, line) in code.lines().enumerate() {
            let trimmed = line.trim();

            if let Some(caps) = from_pattern.captures(trimmed) {
                let image = caps.get(1).map(|m| m.as_str()).unwrap_or("");

                if image.contains(':') || image.contains('@') {
                    continue;
                }

                let unpinned_images = [
                    "ubuntu",
                    "debian",
                    "alpine",
                    "centos",
                    "fedora",
                    "amazonlinux",
                    "node",
                    "nodejs",
                    "python",
                    "ruby",
                    "php",
                    "golang",
                    "rust",
                    "nginx",
                    "apache",
                    "httpd",
                    "mysql",
                    "postgres",
                    "postgresql",
                    "mongo",
                    "mongodb",
                    "redis",
                    "rabbitmq",
                    "elasticsearch",
                    "openjdk",
                    "jdk",
                    "maven",
                    "gradle",
                    "dotnet",
                    "perl",
                ];

                let image_lower = image.to_lowercase();
                if unpinned_images
                    .iter()
                    .any(|&img| image_lower == img || image_lower.starts_with(&format!("{}/", img)))
                {
                    findings.push(LangFinding::new(
                        self.id(),
                        self.severity(),
                        line_idx + 1,
                        trimmed,
                        &format!("Base image '{}' has no version tag. Unpinned images may receive security updates with breaking changes.", image),
                        "Pin to specific version: FROM ubuntu:22.04, FROM python:3.11-slim, or use digest: FROM image@sha256:..."
                    ));
                }
            }
        }

        findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IAC-004: Overly Permissive Permissions
// Severity: medium | CWE-732
// ─────────────────────────────────────────────────────────────────────────────
pub struct IacOverlyPermissive;

impl LangRule for IacOverlyPermissive {
    fn id(&self) -> &str {
        "IAC-004"
    }
    fn name(&self) -> &str {
        "Overly Permissive File Permissions"
    }
    fn severity(&self) -> &'static str {
        "medium"
    }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let chmod_777_pattern = Regex::new(r"(?i)\bchmod\s+777").unwrap();
        let chmod_777_recursive_pattern = Regex::new(r"(?i)\bchmod\s+-R\s+777").unwrap();
        let chmod_755_pattern =
            Regex::new(r"(?i)\bchmod\s+755\s+(/etc|/usr|/var|/home|/root)").unwrap();
        let chmod_plus_x_pattern = Regex::new(r"(?i)\bchmod\s+\+x").unwrap();
        let user_7777_pattern = Regex::new(r"(?i)^\s*USER\s+7777").unwrap();
        let chmod_000_pattern = Regex::new(r"(?i)\bchmod\s+0[0-7]{3}").unwrap();

        for (line_idx, line) in code.lines().enumerate() {
            let trimmed = line.trim();

            if chmod_777_pattern.is_match(trimmed) || chmod_777_recursive_pattern.is_match(trimmed)
            {
                findings.push(LangFinding::new(
                    self.id(),
                    self.severity(),
                    line_idx + 1,
                    trimmed,
                    "chmod 777 grants read/write/execute to all users. This is a security risk.",
                    "Use least privilege permissions: chmod 644 for files, chmod 755 for directories"
                ));
            }

            if chmod_755_pattern.is_match(trimmed) {
                findings.push(LangFinding::new(
                    self.id(),
                    self.severity(),
                    line_idx + 1,
                    trimmed,
                    "chmod 755 on sensitive system directories grants execute permission to all users.",
                    "Use chmod 750 on sensitive directories to restrict access to owner only"
                ));
            }

            if chmod_plus_x_pattern.is_match(trimmed)
                && !chmod_plus_x_pattern.is_match("/bin/")
                && !chmod_plus_x_pattern.is_match("/usr/bin/")
            {
                if trimmed.contains("/tmp") || trimmed.contains("/var") || trimmed.contains("/home")
                {
                    findings.push(LangFinding::new(
                        self.id(),
                        self.severity(),
                        line_idx + 1,
                        trimmed,
                        "Making files executable with chmod +x on writable directories can be exploited.",
                        "Only make necessary files executable and ensure they're in read-only locations"
                    ));
                }
            }

            if user_7777_pattern.is_match(trimmed) {
                findings.push(LangFinding::new(
                    self.id(),
                    self.severity(),
                    line_idx + 1,
                    trimmed,
                    "User ID 7777 appears unusual. This may indicate misconfiguration or attempt to escalate privileges.",
                    "Use standard user IDs (1000+) and ensure users are properly configured"
                ));
            }

            if chmod_000_pattern.is_match(trimmed) {
                findings.push(LangFinding::new(
                    self.id(),
                    "low",
                    line_idx + 1,
                    trimmed,
                    "Overly restrictive permissions (chmod 0) may break application functionality.",
                    "Use appropriate permissions: chmod 644 for files, chmod 755 for executables",
                ));
            }
        }

        findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IAC-005: Secrets in Kubernetes
// Severity: critical | CWE-798
// ─────────────────────────────────────────────────────────────────────────────
pub struct IacK8sSecret;

impl LangRule for IacK8sSecret {
    fn id(&self) -> &str {
        "IAC-005"
    }
    fn name(&self) -> &str {
        "Secrets in Kubernetes Manifests"
    }
    fn severity(&self) -> &'static str {
        "critical"
    }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let kubectl_secret_pattern = Regex::new(
            r"(?i)kubectl\s+create\s+secret\s+(generic|docker-registry|tls).*--from-literal",
        )
        .unwrap();
        let kind_secret_pattern = Regex::new(r"(?i)^\s*kind:\s*Secret").unwrap();
        let string_data_pattern = Regex::new(r"(?i)^\s*stringData:").unwrap();
        let plaintext_data_pattern = Regex::new(r"(?i)^\s*data:\s*$").unwrap();

        let secret_key_pattern =
            Regex::new(r"(?i)(password|secret|api_key|apikey|token|credential|auth|passwd)\s*:")
                .unwrap();

        let mut in_string_data = false;
        let mut in_data = false;
        let mut data_line_num = 0;
        let mut checking_plaintext = false;

        for (line_idx, line) in code.lines().enumerate() {
            let trimmed = line.trim();
            let line_num = line_idx + 1;

            if kubectl_secret_pattern.is_match(trimmed) {
                findings.push(LangFinding::new(
                    self.id(),
                    self.severity(),
                    line_num,
                    trimmed,
                    "kubectl create secret with --from-literal may expose secrets in shell history.",
                    "Use sealed secrets, external secrets operator, or apply manifests from encrypted sources"
                ));
            }

            if kind_secret_pattern.is_match(trimmed) {
                checking_plaintext = true;
            }

            if string_data_pattern.is_match(trimmed) {
                in_string_data = true;
                in_data = false;
                checking_plaintext = false;
            }

            if plaintext_data_pattern.is_match(trimmed) {
                in_data = true;
                data_line_num = line_num;
                in_string_data = false;
            }

            if in_string_data && secret_key_pattern.is_match(trimmed) && !trimmed.starts_with('#') {
                findings.push(LangFinding::new(
                    self.id(),
                    self.severity(),
                    line_num,
                    trimmed,
                    "Secrets in stringData are not base64 encoded. They will be visible in plain text in the manifest.",
                    "Move secrets to a proper secrets management system (Vault, AWS Secrets Manager, etc.) and reference them"
                ));
            }

            if in_data && secret_key_pattern.is_match(trimmed) && !trimmed.starts_with('#') {
                let value = trimmed.split(':').nth(1).unwrap_or("").trim();
                if !value.is_empty()
                    && !value.starts_with("LS0t")
                    && !value.contains(" ")
                    && value.len() < 100
                {
                    findings.push(LangFinding::new(
                        self.id(),
                        self.severity(),
                        line_num,
                        trimmed,
                        "Potential plaintext secret in data section. Secrets should be base64 encoded.",
                        "Encode secrets with base64: echo -n 'secret' | base64"
                    ));
                }
            }

            if trimmed.starts_with("---") || trimmed.is_empty() {
                if in_data && data_line_num > 0 && !findings.iter().any(|f| f.line == data_line_num)
                {
                    in_data = false;
                }
                if trimmed.is_empty() {
                    in_string_data = false;
                }
            }

            if secret_key_pattern.is_match(trimmed)
                && !trimmed.starts_with('#')
                && !in_string_data
                && !in_data
            {
                let value = trimmed.split(':').nth(1).unwrap_or("").trim();
                if !value.is_empty()
                    && !value.starts_with('{')
                    && !value.contains('"')
                    && value.len() < 50
                {
                    if value != "true" && value != "false" && !value.parse::<f64>().is_ok() {
                        findings.push(LangFinding::new(
                            self.id(),
                            self.severity(),
                            line_num,
                            trimmed,
                            "Potential plaintext secret detected. Secrets should be properly managed via secrets management tools.",
                            "Use Kubernetes secrets, external secrets operators, or secrets management systems"
                        ));
                    }
                }
            }
        }

        findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IAC-006: Terraform Public S3 Bucket
// Severity: high | CWE-284
// ─────────────────────────────────────────────────────────────────────────────
pub struct IacTerraformPublicS3;

impl LangRule for IacTerraformPublicS3 {
    fn id(&self) -> &str {
        "IAC-006"
    }
    fn name(&self) -> &str {
        "Terraform Public S3 Bucket"
    }
    fn severity(&self) -> &'static str {
        "high"
    }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let s3_resource_pattern = Regex::new(r#"resource\s+"aws_s3_bucket"\s+"([^"]+)""#).unwrap();
        let acl_public_pattern = Regex::new(r#"(?i)\bacl\s*=\s*"public(-read|-write)""#).unwrap();
        let acl_public_other_pattern =
            Regex::new(r#"(?i)\bacl\s*=\s*"(public|authenticated-read)""#).unwrap();
        let block_public_pattern =
            Regex::new(r#"(?i)block_public_(acl|policy|policy|acls)\s*=\s*false"#).unwrap();
        let public_access_pattern = Regex::new(r#"(?i)(public_access|acl\s*=\s*"off")"#).unwrap();

        let mut in_s3_resource = false;
        let mut current_bucket_name = String::new();
        let mut has_block_public_acls = false;
        let mut has_block_public_policy = false;
        let mut has_public_acl = false;
        let mut resource_start_line = 0;

        for (line_idx, line) in code.lines().enumerate() {
            let trimmed = line.trim();
            let line_num = line_idx + 1;

            if let Some(caps) = s3_resource_pattern.captures(trimmed) {
                in_s3_resource = true;
                current_bucket_name = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
                resource_start_line = line_num;
                has_block_public_acls = false;
                has_block_public_policy = false;
                has_public_acl = false;
            }

            if in_s3_resource {
                if trimmed.starts_with("}") && !trimmed.contains("{") {
                    if has_public_acl && !has_block_public_acls && !has_block_public_policy {
                        findings.push(LangFinding::new(
                            self.id(),
                            self.severity(),
                            resource_start_line,
                            &format!("resource \"aws_s3_bucket\" \"{}\"", current_bucket_name),
                            "S3 bucket has public ACL or missing public access blocks. This allows public access to bucket contents.",
                            "Remove public ACL: acl = \"private\" or set block_public_acls = true and block_public_policy = true"
                        ));
                    }
                    in_s3_resource = false;
                }

                if block_public_pattern.is_match(trimmed) {
                    if trimmed.to_lowercase().contains("block_public_acls")
                        && trimmed.contains("false")
                    {
                        has_block_public_acls = true;
                    }
                    if trimmed.to_lowercase().contains("block_public_policy")
                        && trimmed.contains("false")
                    {
                        has_block_public_policy = true;
                    }
                }

                if acl_public_other_pattern.is_match(trimmed) {
                    has_public_acl = true;
                }

                if public_access_pattern.is_match(trimmed) && trimmed.contains("true") {
                    has_public_acl = true;
                }
            }
        }

        if in_s3_resource && has_public_acl && !has_block_public_acls && !has_block_public_policy {
            findings.push(LangFinding::new(
                self.id(),
                self.severity(),
                resource_start_line,
                &format!("resource \"aws_s3_bucket\" \"{}\"", current_bucket_name),
                "S3 bucket has public ACL or missing public access blocks.",
                "Set acl = \"private\" or enable block_public_acls = true and block_public_policy = true"
            ));
        }

        findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IAC-007: Terraform Hardcoded Credentials
// Severity: critical | CWE-798
// ─────────────────────────────────────────────────────────────────────────────
pub struct IacTerraformCredentials;

impl LangRule for IacTerraformCredentials {
    fn id(&self) -> &str {
        "IAC-007"
    }
    fn name(&self) -> &str {
        "Terraform Hardcoded Credentials"
    }
    fn severity(&self) -> &'static str {
        "critical"
    }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let access_key_pattern =
            Regex::new(r#"(?i)\b(access_key|aws_access_key|aws_access_key_id)\s*=\s*"[^"]+""#)
                .unwrap();
        let secret_key_pattern = Regex::new(
            r#"(?i)\b(secret_key|aws_secret|aws_secret_key|aws_secret_access_key)\s*=\s*"[^"]+""#,
        )
        .unwrap();
        let password_pattern =
            Regex::new(r#"(?i)\b(password|passwd|pwd|secret)\s*=\s*"[^"]+""#).unwrap();
        let token_pattern = Regex::new(r#"(?i)\btoken\s*=\s*"[^"]+""#).unwrap();
        let api_key_pattern =
            Regex::new(r#"(?i)\b(api_key|apikey|api-key)\s*=\s*"[^"]+""#).unwrap();
        let private_key_pattern =
            Regex::new(r#"(?i)\b(private_key|ssh_key|ssh_private_key)\s*=\s*"[^"]+""#).unwrap();

        let skip_patterns = [
            r#"(?i)arn:"#,
            r#"(?i)role_arn"#,
            r#"(?i)source_arn"#,
            r#"(?i)bucket_arn"#,
            r#"(?i)aws_key_pair"#,
            r#"(?i)key_name\s*=\s*"[^"]+""#,
        ];

        for (line_idx, line) in code.lines().enumerate() {
            let trimmed = line.trim();
            let line_num = line_idx + 1;

            if trimmed.starts_with('#') || trimmed.starts_with("//") {
                continue;
            }

            let should_skip = skip_patterns
                .iter()
                .any(|p| Regex::new(p).unwrap().is_match(trimmed));

            if should_skip {
                continue;
            }

            let patterns = [
                (&access_key_pattern as &dyn Fn(&str) -> bool, "AWS access key hardcoded", "Use AWS Secrets Manager, environment variables, or assume role instead"),
                (&secret_key_pattern, "AWS secret key hardcoded", "Use AWS Secrets Manager, environment variables, or assume role instead"),
                (&password_pattern, "Password or secret hardcoded", "Use secrets management tools (Vault, AWS Secrets Manager) or environment variables"),
                (&token_pattern, "API token hardcoded", "Use secrets management tools or environment variables instead"),
                (&api_key_pattern, "API key hardcoded", "Use secrets management tools or environment variables instead"),
                (&private_key_pattern, "Private key hardcoded", "Use secrets management tools or external key management systems"),
            ];

            for (pattern, problem, fix) in patterns.iter() {
                if pattern(trimmed) {
                    findings.push(LangFinding::new(
                        self.id(),
                        self.severity(),
                        line_num,
                        trimmed,
                        &format!("{} in Terraform configuration. Hardcoded secrets can be committed to version control.", problem),
                        fix
                    ));
                    break;
                }
            }
        }

        findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IAC-008: Privileged Container in Kubernetes
// Severity: critical | CWE-250
// ─────────────────────────────────────────────────────────────────────────────
pub struct IacPrivilegedContainer;

impl LangRule for IacPrivilegedContainer {
    fn id(&self) -> &str {
        "IAC-008"
    }
    fn name(&self) -> &str {
        "Privileged Container in Kubernetes"
    }
    fn severity(&self) -> &'static str {
        "critical"
    }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let privileged_pattern = Regex::new(r"(?i)^\s*privileged:\s*true").unwrap();
        let host_network_pattern = Regex::new(r"(?i)^\s*hostNetwork:\s*true").unwrap();
        let host_pid_pattern = Regex::new(r"(?i)^\s*hostPID:\s*true").unwrap();
        let host_ipc_pattern = Regex::new(r"(?i)^\s*hostIPC:\s*true").unwrap();
        let allow_priv_esc_pattern =
            Regex::new(r"(?i)^\s*allowPrivilegeEscalation:\s*true").unwrap();
        let security_context_pattern = Regex::new(r"(?i)^\s*securityContext:").unwrap();

        let capabilities_add_pattern = Regex::new(r"(?i)^\s*capabilities:\s*$|^\s*add:").unwrap();
        let cap_add_privileged = Regex::new(r"(?i)^\s*-\s*SYS_ADMIN|^\s*-\s*NET_ADMIN|^\s*-\s*SYS_MODULE|^\s*-\s*DAC_READ_SEARCH|^\s*-\s*DAC_OVERRIDE").unwrap();

        let mut in_security_context = false;
        let mut has_security_context = false;

        for (line_idx, line) in code.lines().enumerate() {
            let trimmed = line.trim();
            let line_num = line_idx + 1;

            if security_context_pattern.is_match(trimmed) {
                in_security_context = true;
                has_security_context = true;
            }

            if in_security_context {
                if !trimmed.is_empty()
                    && !trimmed.contains(':')
                    && !trimmed.starts_with('-')
                    && !trimmed.starts_with('#')
                {
                    in_security_context = false;
                }
                if trimmed.starts_with("---") || trimmed.is_empty() {
                    in_security_context = false;
                }
            }

            if privileged_pattern.is_match(trimmed) {
                findings.push(LangFinding::new(
                    self.id(),
                    self.severity(),
                    line_num,
                    trimmed,
                    "Container runs in privileged mode. This gives the container full access to the host system's devices.",
                    "Remove privileged: true or set privileged: false. Use specific capabilities if needed"
                ));
            }

            if host_network_pattern.is_match(trimmed) {
                findings.push(LangFinding::new(
                    self.id(),
                    self.severity(),
                    line_num,
                    trimmed,
                    "Container shares the host's network namespace. This allows network access to host services.",
                    "Set hostNetwork: false or remove the line. Use NetworkPolicy for network isolation"
                ));
            }

            if host_pid_pattern.is_match(trimmed) {
                findings.push(LangFinding::new(
                    self.id(),
                    self.severity(),
                    line_num,
                    trimmed,
                    "Container shares the host's PID namespace. This allows seeing and potentially affecting host processes.",
                    "Set hostPID: false or remove the line"
                ));
            }

            if host_ipc_pattern.is_match(trimmed) {
                findings.push(LangFinding::new(
                    self.id(),
                    self.severity(),
                    line_num,
                    trimmed,
                    "Container shares the host's IPC namespace. This allows shared memory access with host processes.",
                    "Set hostIPC: false or remove the line"
                ));
            }

            if allow_priv_esc_pattern.is_match(trimmed) {
                findings.push(LangFinding::new(
                    self.id(),
                    self.severity(),
                    line_num,
                    trimmed,
                    "Container allows privilege escalation. This enables processes to gain more privileges than their parent.",
                    "Set allowPrivilegeEscalation: false"
                ));
            }

            if cap_add_privileged.is_match(trimmed) {
                findings.push(LangFinding::new(
                    self.id(),
                    self.severity(),
                    line_num,
                    trimmed,
                    "Container adds privileged Linux capabilities. These grant significant power over the host.",
                    "Remove unnecessary capabilities. Use principle of least privilege for capabilities"
                ));
            }
        }

        if !has_security_context && code.contains("containers:") {
            findings.push(LangFinding::new(
                self.id(),
                "low",
                1,
                "containers:",
                "No securityContext defined for containers. Consider adding security context for better isolation.",
                "Add securityContext with runAsNonRoot: true, runAsUser: 1000, and drop all capabilities"
            ));
        }

        findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IAC-009: Missing Resource Limits in Kubernetes
// Severity: low | CWE-400
// ─────────────────────────────────────────────────────────────────────────────
pub struct IacMissingResourceLimits;

impl LangRule for IacMissingResourceLimits {
    fn id(&self) -> &str {
        "IAC-009"
    }
    fn name(&self) -> &str {
        "Missing Resource Limits in Kubernetes"
    }
    fn severity(&self) -> &'static str {
        "low"
    }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let container_pattern = Regex::new(r"(?i)^\s*-\s*name:\s*\S+").unwrap();
        let resources_pattern = Regex::new(r"(?i)^\s*resources:\s*$").unwrap();
        let limits_pattern = Regex::new(r"(?i)^\s*limits:\s*$").unwrap();
        let cpu_pattern = Regex::new(r"(?i)^\s*cpu:\s*").unwrap();
        let memory_pattern = Regex::new(r"(?i)^\s*memory:\s*").unwrap();

        let mut in_container = false;
        let mut current_container_name = String::new();
        let mut has_resources = false;
        let mut has_limits = false;
        let mut has_cpu = false;
        let mut has_memory = false;
        let mut container_line = 0;

        for (line_idx, line) in code.lines().enumerate() {
            let trimmed = line.trim();
            let line_num = line_idx + 1;

            if container_pattern.is_match(trimmed) {
                if in_container && !has_resources {
                    findings.push(LangFinding::new(
                        self.id(),
                        self.severity(),
                        container_line,
                        &format!("- name: {}", current_container_name),
                        "Container has no resource limits defined. This can cause resource exhaustion.",
                        "Add resources with limits and requests: resources: { limits: { cpu: \"100m\", memory: \"128Mi\" }, requests: { cpu: \"50m\", memory: \"64Mi\" } }"
                    ));
                }

                in_container = true;
                has_resources = false;
                has_limits = false;
                has_cpu = false;
                has_memory = false;
                container_line = line_num;

                if let Some(caps) = container_pattern.captures(trimmed) {
                    current_container_name =
                        caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
                }
            }

            if in_container {
                if resources_pattern.is_match(trimmed)
                    && !trimmed.contains("requests:")
                    && !trimmed.contains("limits:")
                {
                    has_resources = true;
                }

                if limits_pattern.is_match(trimmed) {
                    has_limits = true;
                }

                if cpu_pattern.is_match(trimmed) {
                    has_cpu = true;
                }

                if memory_pattern.is_match(trimmed) {
                    has_memory = true;
                }

                if trimmed.starts_with("---") || trimmed.is_empty() {
                    if in_container && !has_resources {
                        findings.push(LangFinding::new(
                            self.id(),
                            self.severity(),
                            container_line,
                            &format!("- name: {}", current_container_name),
                            "Container has no resource limits defined.",
                            "Add resources section with limits and requests",
                        ));
                    }
                    in_container = false;
                }
            }
        }

        if in_container && !has_resources {
            findings.push(LangFinding::new(
                self.id(),
                self.severity(),
                container_line,
                &format!("- name: {}", current_container_name),
                "Container has no resource limits defined.",
                "Add resources section with limits and requests",
            ));
        }

        findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IAC-010: Dockerfile Latest Tag
// Severity: low | CWE-1357
// ─────────────────────────────────────────────────────────────────────────────
pub struct IacLatestTag;

impl LangRule for IacLatestTag {
    fn id(&self) -> &str {
        "IAC-010"
    }
    fn name(&self) -> &str {
        "Dockerfile Latest Tag"
    }
    fn severity(&self) -> &'static str {
        "low"
    }

    fn detect(&self, _tree: &LnAst, code: &str) -> Vec<LangFinding> {
        let mut findings = vec![];

        let from_pattern = Regex::new(r"(?i)^\s*FROM\s+(\S+)").unwrap();
        let latest_tag_pattern = Regex::new(r"(?i):latest\s*$").unwrap();

        for (line_idx, line) in code.lines().enumerate() {
            let trimmed = line.trim();

            if let Some(caps) = from_pattern.captures(trimmed) {
                let image = caps.get(1).map(|m| m.as_str()).unwrap_or("");

                if latest_tag_pattern.is_match(image) {
                    findings.push(LangFinding::new(
                        self.id(),
                        self.severity(),
                        line_idx + 1,
                        trimmed,
                        "Base image uses ':latest' tag which is mutable and unpredictable.",
                        "Pin to specific version tag: FROM ubuntu:22.04, FROM node:18-alpine, etc.",
                    ));
                }

                if !image.contains(':')
                    && !image.contains('@')
                    && !image.to_lowercase().contains("scratch")
                {
                    let base_images = [
                        "ubuntu",
                        "debian",
                        "alpine",
                        "centos",
                        "fedora",
                        "amazonlinux",
                        "node",
                        "python",
                        "ruby",
                        "php",
                        "golang",
                        "rust",
                        "openjdk",
                        "maven",
                        "gradle",
                    ];
                    let image_lower = image.to_lowercase();
                    if base_images.iter().any(|&img| {
                        image_lower == img || image_lower.starts_with(&format!("{}/", img))
                    }) {
                        if !findings
                            .iter()
                            .any(|f| f.line == line_idx + 1 && f.rule_id == "IAC-003")
                        {
                            findings.push(LangFinding::new(
                                self.id(),
                                self.severity(),
                                line_idx + 1,
                                trimmed,
                                "Base image has no tag specified. Defaults to 'latest' which is mutable.",
                                "Explicitly use ':latest' or better, pin to specific version"
                            ));
                        }
                    }
                }
            }
        }

        findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Registry Function
// ─────────────────────────────────────────────────────────────────────────────
pub fn infrastructure_rules() -> Vec<Box<dyn LangRule>> {
    vec![
        Box::new(IacRootUser),
        Box::new(IacDockerSecret),
        Box::new(IacUnpinnedImage),
        Box::new(IacOverlyPermissive),
        Box::new(IacK8sSecret),
        Box::new(IacTerraformPublicS3),
        Box::new(IacTerraformCredentials),
        Box::new(IacPrivilegedContainer),
        Box::new(IacMissingResourceLimits),
        Box::new(IacLatestTag),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dockerfile_root_user() {
        let rule = IacRootUser;
        let code = r#"
FROM ubuntu:22.04
RUN apt-get update
USER root
"#;
        let ast = LnAst {
            path: "Dockerfile".to_string(),
            code: code.to_string(),
            ast: None,
        };
        let findings = rule.detect(&ast, code);
        assert!(!findings.is_empty(), "Should detect USER root");
    }

    #[test]
    fn test_dockerfile_no_user() {
        let rule = IacRootUser;
        let code = r#"
FROM ubuntu:22.04
RUN apt-get update
"#;
        let ast = LnAst {
            path: "Dockerfile".to_string(),
            code: code.to_string(),
            ast: None,
        };
        let findings = rule.detect(&ast, code);
        assert!(
            !findings.is_empty(),
            "Should detect missing USER instruction"
        );
    }

    #[test]
    fn test_dockerfile_secrets() {
        let rule = IacDockerSecret;
        let code = r#"
FROM ubuntu:22.04
ENV API_KEY=secret123
ENV SECRET_KEY=mysecret
"#;
        let ast = LnAst {
            path: "Dockerfile".to_string(),
            code: code.to_string(),
            ast: None,
        };
        let findings = rule.detect(&ast, code);
        assert!(findings.len() >= 2, "Should detect hardcoded secrets");
    }

    #[test]
    fn test_unpinned_base_image() {
        let rule = IacUnpinnedImage;
        let code = r#"
FROM ubuntu
FROM python
FROM node
"#;
        let ast = LnAst {
            path: "Dockerfile".to_string(),
            code: code.to_string(),
            ast: None,
        };
        let findings = rule.detect(&ast, code);
        assert!(findings.len() >= 2, "Should detect unpinned images");
    }

    #[test]
    fn test_overly_permissive_chmod() {
        let rule = IacOverlyPermissive;
        let code = r#"
RUN chmod 777 /data
RUN chmod +x /tmp/script.sh
"#;
        let ast = LnAst {
            path: "Dockerfile".to_string(),
            code: code.to_string(),
            ast: None,
        };
        let findings = rule.detect(&ast, code);
        assert!(
            !findings.is_empty(),
            "Should detect overly permissive permissions"
        );
    }

    #[test]
    fn test_kubernetes_secrets() {
        let rule = IacK8sSecret;
        let code = r#"
apiVersion: v1
kind: Secret
stringData:
  password: mysecretpassword
  apiKey: secret123
"#;
        let ast = LnAst {
            path: "secret.yaml".to_string(),
            code: code.to_string(),
            ast: None,
        };
        let findings = rule.detect(&ast, code);
        assert!(!findings.is_empty(), "Should detect plaintext secrets");
    }

    #[test]
    fn test_terraform_public_s3() {
        let rule = IacTerraformPublicS3;
        let code = r#"
resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
  acl = "public-read"
}
"#;
        let ast = LnAst {
            path: "main.tf".to_string(),
            code: code.to_string(),
            ast: None,
        };
        let findings = rule.detect(&ast, code);
        assert!(!findings.is_empty(), "Should detect public S3 bucket");
    }

    #[test]
    fn test_terraform_credentials() {
        let rule = IacTerraformCredentials;
        let code = r#"
resource "aws_instance" "web" {
  ami           = "ami-12345"
  instance_type = "t2.micro"
  access_key    = "AKIAIOSFODNN7EXAMPLE"
  secret_key    = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}
"#;
        let ast = LnAst {
            path: "main.tf".to_string(),
            code: code.to_string(),
            ast: None,
        };
        let findings = rule.detect(&ast, code);
        assert!(findings.len() >= 2, "Should detect hardcoded credentials");
    }

    #[test]
    fn test_privileged_container() {
        let rule = IacPrivilegedContainer;
        let code = r#"
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: app
      image: nginx
      securityContext:
        privileged: true
        hostNetwork: true
"#;
        let ast = LnAst {
            path: "pod.yaml".to_string(),
            code: code.to_string(),
            ast: None,
        };
        let findings = rule.detect(&ast, code);
        assert!(
            findings.len() >= 2,
            "Should detect privileged container and hostNetwork"
        );
    }

    #[test]
    fn test_missing_resource_limits() {
        let rule = IacMissingResourceLimits;
        let code = r#"
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: app
      image: nginx
"#;
        let ast = LnAst {
            path: "pod.yaml".to_string(),
            code: code.to_string(),
            ast: None,
        };
        let findings = rule.detect(&ast, code);
        assert!(
            !findings.is_empty(),
            "Should detect missing resource limits"
        );
    }

    #[test]
    fn test_latest_tag() {
        let rule = IacLatestTag;
        let code = r#"
FROM ubuntu:latest
FROM node:latest
FROM python:3.11
"#;
        let ast = LnAst {
            path: "Dockerfile".to_string(),
            code: code.to_string(),
            ast: None,
        };
        let findings = rule.detect(&ast, code);
        assert!(findings.len() >= 2, "Should detect :latest tags");
    }
}
