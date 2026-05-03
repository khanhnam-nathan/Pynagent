//! SPDX License Detection and SBOM Generation
//!
//! Provides:
//! - License identification from files and package manifests
//! - SPDX SBOM generation from lock files
//! - CycloneDX SBOM generation from lock files

#[allow(dead_code)]

use crate::scanner::supplychain::lock_parser::LockPackage;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use regex::Regex;
use once_cell::sync::Lazy;

#[allow(dead_code)]
static SPDX_LICENSE_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(SPDX-License-Identifier:|License:(.+)|Licensed under the (.+?) license)").unwrap()
});

static KNOWN_LICENSE_ALIASES: Lazy<HashMap<&str, &'static str>> = Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert("MIT", "MIT");
    m.insert("APACHE", "Apache-2.0");
    m.insert("APACHE2", "Apache-2.0");
    m.insert("BSD", "BSD-3-Clause");
    m.insert("BSD3", "BSD-3-Clause");
    m.insert("BSD2", "BSD-2-Clause");
    m.insert("GPL", "GPL-3.0-only");
    m.insert("GPL2", "GPL-2.0-only");
    m.insert("GPL3", "GPL-3.0-only");
    m.insert("LGPL", "LGPL-3.0-only");
    m.insert("MPL", "MPL-2.0");
    m.insert("ISC", "ISC");
    m.insert("OSL", "OpenSSL-1.0");
    m.insert("ZLIB", "Zlib");
    m.insert("BOOST", "BSL-1.0");
    m.insert("CC0", "CC0-1.0");
    m.insert("UNLICENSE", "Unlicense");
    m.insert("WTFPL", "WTFPL");
    m.insert("POSTGRESQL", "PostgreSQL");
    m
});

static SPDX_IDS: Lazy<HashMap<&str, &'static str>> = Lazy::new(|| {
    let ids = vec![
        ("Apache-1.0", "Apache-1.0"),
        ("Apache-1.1", "Apache-1.1"),
        ("Apache-2.0", "Apache-2.0"),
        ("BSD-2-Clause", "BSD-2-Clause"),
        ("BSD-3-Clause", "BSD-3-Clause"),
        ("BSD-4-Clause", "BSD-4-Clause"),
        ("CC0-1.0", "CC0-1.0"),
        ("CC-BY-3.0", "CC-BY-3.0"),
        ("CC-BY-4.0", "CC-BY-4.0"),
        ("GPL-2.0-only", "GPL-2.0-only"),
        ("GPL-2.0-or-later", "GPL-2.0-or-later"),
        ("GPL-3.0-only", "GPL-3.0-only"),
        ("GPL-3.0-or-later", "GPL-3.0-or-later"),
        ("ISC", "ISC"),
        ("LGPL-2.0-only", "LGPL-2.0-only"),
        ("LGPL-2.1-only", "LGPL-2.1-only"),
        ("LGPL-3.0-only", "LGPL-3.0-only"),
        ("MIT", "MIT"),
        ("MPL-1.0", "MPL-1.0"),
        ("MPL-1.1", "MPL-1.1"),
        ("MPL-2.0", "MPL-2.0"),
        ("MIT-0", "MIT-0"),
        ("0BSD", "0BSD"),
        ("Unlicense", "Unlicense"),
        ("Zlib", "Zlib"),
        ("PostgreSQL", "PostgreSQL"),
        ("BSL-1.0", "BSL-1.0"),
        ("WTFPL", "WTFPL"),
        ("OpenSSL", "OpenSSL-1.0"),
    ];
    ids.into_iter().collect()
});

/// License SPDX identifier and source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedLicense {
    pub spdx_id: String,
    pub source: LicenseSource,
    pub package: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LicenseSource {
    File { path: String },
    PackageManifest,
    LockFile,
    CargoLock,
}

/// License compliance result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseCompliance {
    pub package: String,
    pub version: String,
    pub spdx_id: Option<String>,
    pub is_osi_approved: bool,
    pub is_copyleft: bool,
    pub is_prohibited: bool,
    pub status: ComplianceStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ComplianceStatus {
    Approved,
    Restricted,
    Prohibited,
    Undeclared,
    Unknown,
}

/// SPDX SBOM document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpdxSbom {
    pub spdx_version: String,
    pub spdx_id: String,
    pub name: String,
    pub document_namespace: String,
    pub creation_info: SpdxCreationInfo,
    pub packages: Vec<SpdxPackage>,
    pub relationships: Vec<SpdxRelationship>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpdxCreationInfo {
    pub created: String,
    pub creators: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpdxPackage {
    pub spdx_id: String,
    pub name: String,
    pub version: String,
    pub supplier: Option<String>,
    pub download_location: Option<String>,
    pub license_concluded: Option<String>,
    pub license_declared: Option<String>,
    pub copyright: Option<String>,
    pub external_refs: Vec<SpdxExternalRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpdxExternalRef {
    pub category: String,
    pub reference_type: String,
    pub reference_locator: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpdxRelationship {
    pub spdx_element_id: String,
    pub relationship_type: String,
    pub related_spdx_element: String,
}

/// CycloneDX SBOM document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycloneDxSbom {
    pub bom_format: String,
    pub spec_version: String,
    pub serial_number: String,
    pub version: u32,
    pub metadata: CycloneDxMetadata,
    pub components: Vec<CycloneDxComponent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycloneDxMetadata {
    pub timestamp: String,
    pub component: Option<CycloneDxComponent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycloneDxComponent {
    pub type_: String,
    pub name: String,
    pub version: String,
    pub license: Option<CycloneDxLicense>,
    pub purl: Option<String>,
    pub hashes: Vec<CycloneDxHash>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycloneDxLicense {
    pub license: CycloneDxLicenseChoice,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycloneDxLicenseChoice {
    pub id: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycloneDxHash {
    pub alg: String,
    pub content: String,
}

/// Prohibited licenses for corporate use.
const PROHIBITED_LICENSES: &[&str] = &[
    "GPL-3.0-only",
    "GPL-3.0-or-later",
    "GPL-2.0-only",
    "GPL-2.0-or-later",
    "AGPL-3.0-only",
    "AGPL-3.0-or-later",
    "SSPL-1.0",
    "SSPL-1.0",
    "Elastic-2.0",
];

/// Copyleft licenses that may require source disclosure.
const COPYLEFT_LICENSES: &[&str] = &[
    "GPL-2.0-only",
    "GPL-2.0-or-later",
    "GPL-3.0-only",
    "GPL-3.0-or-later",
    "LGPL-2.0-only",
    "LGPL-2.1-only",
    "LGPL-3.0-only",
    "AGPL-3.0-only",
    "AGPL-3.0-or-later",
    "MPL-1.0",
    "MPL-1.1",
    "MPL-2.0",
];

/// Parse a license string and return SPDX ID.
pub fn normalize_license(license_str: &str) -> Option<String> {
    let trimmed = license_str.trim();

    if let Some(spdx_id) = SPDX_IDS.get(trimmed.to_uppercase().as_str()) {
        return Some(spdx_id.to_string());
    }

    if let Some(canonical) = KNOWN_LICENSE_ALIASES.get(trimmed.to_uppercase().as_str()) {
        return Some(canonical.to_string());
    }

    for (id, _canonical) in SPDX_IDS.iter() {
        if id.to_uppercase() == trimmed.to_uppercase() {
            return Some(id.to_string());
        }
    }

    if trimmed.to_uppercase().contains("PROPRIETARY") || trimmed.to_uppercase().contains("NO LICENSE") {
        return Some("NOASSERTION".to_string());
    }

    None
}

/// Detect licenses from a LICENSE file content.
pub fn detect_from_license_file(content: &str) -> Vec<DetectedLicense> {
    let mut licenses = Vec::new();

    let lic_re = regex::Regex::new(r"(?im)^SPDX-License-Identifier:\s*(.+)$").unwrap();
    for caps in lic_re.captures_iter(content) {
        if let Some(spdx_match) = caps.get(1) {
            let spdx = spdx_match.as_str().trim();
            // Handle "MIT AND Apache-2.0" style multi-licenses
            let parts: Vec<&str> = if spdx.to_uppercase().contains(" AND ") {
                spdx.split(" AND ").map(|s| s.trim()).collect()
            } else if spdx.contains('+') {
                // Handle "GPL-2.0+"
                vec![spdx]
            } else {
                vec![spdx]
            };
            for part in parts {
                if let Some(id) = normalize_license(part) {
                    licenses.push(DetectedLicense {
                        spdx_id: id,
                        source: LicenseSource::File {
                            path: "LICENSE".to_string(),
                        },
                        package: None,
                    });
                }
            }
        }
    }

    if licenses.is_empty() {
        let lic2_re = regex::Regex::new(r"(?i)License:\s*(.+)$").unwrap();
        for caps in lic2_re.captures_iter(content) {
            if let Some(lic_match) = caps.get(1) {
                let lic = lic_match.as_str().trim();
                if let Some(id) = normalize_license(lic) {
                    licenses.push(DetectedLicense {
                        spdx_id: id,
                        source: LicenseSource::File {
                            path: "LICENSE".to_string(),
                        },
                        package: None,
                    });
                    break;
                }
            }
        }
    }

    if licenses.is_empty() && content.trim().len() > 0 {
        let first_line = content.lines().next().unwrap_or("").trim();
        if let Some(id) = normalize_license(first_line) {
            licenses.push(DetectedLicense {
                spdx_id: id,
                source: LicenseSource::File {
                    path: "LICENSE".to_string(),
                },
                package: None,
            });
        }
    }

    licenses
}

/// Detect license from package.json content.
pub fn detect_from_package_json(content: &str) -> Vec<DetectedLicense> {
    let mut licenses = Vec::new();

    if let Ok(json) = serde_json::from_str::<serde_json::Value>(content) {
        if let Some(license_str) = json.get("license").and_then(|l| l.as_str()) {
            if let Some(id) = normalize_license(license_str) {
                licenses.push(DetectedLicense {
                    spdx_id: id,
                    source: LicenseSource::PackageManifest,
                    package: json.get("name").and_then(|n| n.as_str()).map(String::from),
                });
            }
        }
    }

    licenses
}

/// Detect licenses from Cargo.toml content.
pub fn detect_from_cargo_toml(content: &str) -> Vec<DetectedLicense> {
    let mut licenses = Vec::new();

    let name_re = Regex::new(r#"(?m)^name\s*=\s*"([^"]+)""#).unwrap();
    let lic_re = Regex::new(r#"(?mi)^license\s*=\s*"([^"]+)""#).unwrap();

    let name = name_re.captures(content)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string());

    if let Some(caps) = lic_re.captures(content) {
        if let Some(lic_str) = caps.get(1) {
            if let Some(id) = normalize_license(lic_str.as_str()) {
                licenses.push(DetectedLicense {
                    spdx_id: id,
                    source: LicenseSource::PackageManifest,
                    package: name.clone(),
                });
            }
        }
    }

    licenses
}

/// Generate SPDX SBOM from npm packages.
pub fn generate_spdx_from_packages(
    packages: &[LockPackage],
    project_name: &str,
) -> SpdxSbom {
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let now = chrono_lite_rfc3339();

    let spdx_id = format!("SPDXRef-DOCUMENT");
    let namespace = format!("https://spdx.org/spdxdocs/{}/{}", project_name, timestamp);

    let spdx_packages: Vec<SpdxPackage> = packages
        .iter()
        .enumerate()
        .map(|(i, pkg)| {
            let pkg_id = format!("SPDXRef-Package-{}", i + 1);
            SpdxPackage {
                spdx_id: pkg_id.clone(),
                name: pkg.name.clone(),
                version: pkg.version.clone(),
                supplier: None,
                download_location: pkg.resolved_url.clone(),
                license_concluded: Some("NOASSERTION".to_string()),
                license_declared: Some("NOASSERTION".to_string()),
                copyright: None,
                external_refs: vec![
                    SpdxExternalRef {
                        category: "PACKAGE-MANAGER".to_string(),
                        reference_type: "purl".to_string(),
                        reference_locator: format!("pkg:npm/{}@{}", pkg.name, pkg.version),
                    },
                ],
            }
        })
        .collect();

    let relationships = packages
        .iter()
        .enumerate()
        .map(|(i, _pkg)| SpdxRelationship {
            spdx_element_id: spdx_id.clone(),
            relationship_type: "CONTAINS".to_string(),
            related_spdx_element: format!("SPDXRef-Package-{}", i + 1),
        })
        .collect();

    SpdxSbom {
        spdx_version: "SPDX-2.3".to_string(),
        spdx_id,
        name: project_name.to_string(),
        document_namespace: namespace,
        creation_info: SpdxCreationInfo {
            created: now.clone(),
            creators: vec![
                "Tool: pyneat-rs".to_string(),
                format!("CreatorComment: SPDX SBOM generated by pyneat-rs at {}", now),
            ],
        },
        packages: spdx_packages,
        relationships,
    }
}

/// Generate CycloneDX SBOM from npm packages.
pub fn generate_cyclonedx_from_packages(
    packages: &[LockPackage],
    project_name: &str,
) -> CycloneDxSbom {
    use std::time::{SystemTime, UNIX_EPOCH};

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let components: Vec<CycloneDxComponent> = packages
        .iter()
        .map(|pkg| {
            let mut hashes = Vec::new();
            if let Some(ref hash) = pkg.integrity_hash {
                if hash.starts_with("sha512-") {
                    hashes.push(CycloneDxHash {
                        alg: "SHA-512".to_string(),
                        content: hash.replace("sha512-", ""),
                    });
                } else if hash.starts_with("sha256-") {
                    hashes.push(CycloneDxHash {
                        alg: "SHA-256".to_string(),
                        content: hash.replace("sha256-", ""),
                    });
                } else {
                    hashes.push(CycloneDxHash {
                        alg: "SHA-256".to_string(),
                        content: hash.clone(),
                    });
                }
            }

            CycloneDxComponent {
                type_: "library".to_string(),
                name: pkg.name.clone(),
                version: pkg.version.clone(),
                license: None,
                purl: Some(format!("pkg:npm/{}@{}", pkg.name, pkg.version)),
                hashes,
            }
        })
        .collect();

    CycloneDxSbom {
        bom_format: "CycloneDX".to_string(),
        spec_version: "1.5".to_string(),
        serial_number: format!("urn:uuid:{:032x}", now_secs),
        version: 1,
        metadata: CycloneDxMetadata {
            timestamp: chrono_lite_rfc3339(),
            component: Some(CycloneDxComponent {
                type_: "application".to_string(),
                name: project_name.to_string(),
                version: "0.0.0".to_string(),
                license: None,
                purl: Some(format!("pkg:npm/{}", project_name)),
                hashes: vec![],
            }),
        },
        components,
    }
}

/// Check license compliance for a list of packages.
pub fn check_license_compliance(
    packages: &[LockPackage],
    licenses: &[DetectedLicense],
) -> Vec<LicenseCompliance> {
    let license_map: HashMap<&str, &str> = licenses
        .iter()
        .filter_map(|l| {
            if let LicenseSource::LockFile | LicenseSource::CargoLock = &l.source {
                l.package.as_ref().map(|p| (p.as_str(), l.spdx_id.as_str()))
            } else {
                None
            }
        })
        .collect();

    packages
        .iter()
        .map(|pkg| {
            let spdx_id = license_map.get(pkg.name.as_str()).map(|s| s.to_string());

            let is_copyleft = spdx_id
                .as_ref()
                .map(|id| COPYLEFT_LICENSES.contains(&id.as_str()))
                .unwrap_or(false);

            let is_prohibited = spdx_id
                .as_ref()
                .map(|id| PROHIBITED_LICENSES.contains(&id.as_str()))
                .unwrap_or(false);

            let status = if is_prohibited {
                ComplianceStatus::Prohibited
            } else if is_copyleft {
                ComplianceStatus::Restricted
            } else if spdx_id.is_none() {
                ComplianceStatus::Undeclared
            } else {
                ComplianceStatus::Approved
            };

            LicenseCompliance {
                package: pkg.name.clone(),
                version: pkg.version.clone(),
                spdx_id,
                is_osi_approved: true,
                is_copyleft,
                is_prohibited,
                status,
            }
        })
        .collect()
}

/// Generate RFC3339-like timestamp without external deps.
fn chrono_lite_rfc3339() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap();
    let secs = now.as_secs();
    let days = secs / 86400;
    let remaining = secs % 86400;
    let hours = remaining / 3600;
    let mins = (remaining % 3600) / 60;
    let seconds = remaining % 60;
    let year = 1970 + days / 365;
    let day_of_year = days % 365;
    let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    let month_days: [u64; 12] = if is_leap {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut month = 1;
    let mut day_rem = day_of_year;
    for (i, &md) in month_days.iter().enumerate() {
        if day_rem < md {
            month = i + 1;
            break;
        }
        day_rem -= md;
    }
    let day = day_rem + 1;

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, mins, seconds
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_license() {
        assert_eq!(normalize_license("MIT"), Some("MIT".to_string()));
        assert_eq!(normalize_license("Apache-2.0"), Some("Apache-2.0".to_string()));
        assert_eq!(normalize_license("GPL3"), Some("GPL-3.0-only".to_string()));
        assert_eq!(normalize_license("BSD-3-Clause"), Some("BSD-3-Clause".to_string()));
        assert_eq!(normalize_license("UNKNOWN-X"), None);
    }

    #[test]
    fn test_detect_from_license_file() {
        let content = "MIT License\n\nSPDX-License-Identifier: Apache-2.0";
        let licenses = detect_from_license_file(content);
        assert!(!licenses.is_empty());
    }

    #[test]
    fn test_detect_from_package_json() {
        let content = r#"{"name": "test", "license": "MIT"}"#;
        let licenses = detect_from_package_json(content);
        assert_eq!(licenses.len(), 1);
        assert_eq!(licenses[0].spdx_id, "MIT");
    }

    #[test]
    fn test_spdx_sbom_generation() {
        let packages = vec![
            LockPackage {
                name: "lodash".to_string(),
                version: "4.17.21".to_string(),
                integrity_hash: Some("sha512-abc123".to_string()),
                resolved_url: Some("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz".to_string()),
                has_git_source: false,
                has_http_source: false,
            },
        ];
        let sbom = generate_spdx_from_packages(&packages, "test-project");
        assert_eq!(sbom.name, "test-project");
        assert_eq!(sbom.packages.len(), 1);
        assert_eq!(sbom.packages[0].name, "lodash");
        assert_eq!(sbom.spdx_version, "SPDX-2.3");
    }

    #[test]
    fn test_cyclonedx_sbom_generation() {
        let packages = vec![
            LockPackage {
                name: "express".to_string(),
                version: "4.18.2".to_string(),
                integrity_hash: Some("sha512-abc456".to_string()),
                resolved_url: None,
                has_git_source: false,
                has_http_source: false,
            },
        ];
        let sbom = generate_cyclonedx_from_packages(&packages, "my-app");
        assert_eq!(sbom.bom_format, "CycloneDX");
        assert_eq!(sbom.components.len(), 1);
        assert!(sbom.metadata.component.is_some());
    }

    #[test]
    fn test_license_compliance() {
        let packages = vec![
            LockPackage {
                name: "lodash".to_string(),
                version: "4.17.21".to_string(),
                integrity_hash: None,
                resolved_url: None,
                has_git_source: false,
                has_http_source: false,
            },
            LockPackage {
                name: "gpl-v3-lib".to_string(),
                version: "1.0.0".to_string(),
                integrity_hash: None,
                resolved_url: None,
                has_git_source: false,
                has_http_source: false,
            },
        ];

        let licenses = vec![DetectedLicense {
            spdx_id: "GPL-3.0-only".to_string(),
            source: LicenseSource::LockFile,
            package: Some("gpl-v3-lib".to_string()),
        }];

        let results = check_license_compliance(&packages, &licenses);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].status, ComplianceStatus::Undeclared);
        assert_eq!(results[1].status, ComplianceStatus::Prohibited);
        assert!(results[1].is_prohibited);
    }
}
