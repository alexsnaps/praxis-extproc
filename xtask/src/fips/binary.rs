// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Binary section of the report: the shipped binary must link the system
//! libcrypto dynamically, define no symbol of a bundled crypto backend, import
//! OpenSSL only under the `@OPENSSL_3.0.0` version and only symbols on the
//! reviewed allowlist, and carry the cargo-auditable manifest and the rustc
//! producer string. A binary that is not given, cannot be read or is not an ELF
//! file is a finding too, so the report never passes a build it did not inspect.

use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read as _,
    path::Path,
    process::Command,
};

use object::{
    Endianness, Object as _, ObjectSection as _, ObjectSymbol as _,
    read::elf::{ElfFile64, Sym as _, Version},
};

use super::{
    graph::DENIED,
    report::{Finding, Report},
};

/// Defined-symbol prefixes that identify a bundled crypto backend
/// (check-payload's list).
const BACKEND_PREFIXES: &[&str] = &["ring_core_", "GFp_", "aws_lc_", "AWSLC_", "BORINGSSL_", "OPENSSL_"];

/// Imported-symbol prefixes that show calls into libcrypto and libssl.
const OPENSSL_PREFIXES: &[&str] = &["EVP_", "SSL_", "OSSL_", "RAND_"];

/// Append the binary section.
pub(crate) fn section(report: &mut Report, binary: Option<&Path>) {
    report.section("Binary");
    if let Err(finding) = assess(report, binary) {
        report.fail(finding);
    }
}

/// Run the binary checks, or return the finding that stops them before they
/// start: no binary, one that cannot be read, or one that is not an ELF file.
fn assess(report: &mut Report, binary: Option<&Path>) -> Result<(), Finding> {
    let binary = binary.ok_or_else(no_binary)?;
    let data = read_binary(binary)?;
    let file = parse_elf(&data).map_err(|reason| not_elf(binary, &reason))?;
    report.info(&format!("path: {}", binary.display()));
    linkage(report, binary);
    defined_symbols(report, &file);
    imports(report, &file);
    openssl_imports(report, &data);
    manifest(report, &file, binary);
    producer(report, &file);
    Ok(())
}

// -----------------------------------------------------------------------------
// The Binary Itself
// -----------------------------------------------------------------------------

/// Why a binary the checks cannot open is a finding rather than a warning.
const UNASSESSED: &str = "the linkage, symbol, manifest and producer checks all run on the binary itself; without \
                          them the report would call a build FIPS-ready without ever inspecting it";

/// Read the binary, refusing anything but a regular file first: reading a FIFO
/// blocks until something writes to it, and a device like /dev/zero never
/// ends.
fn read_binary(binary: &Path) -> Result<Vec<u8>, Finding> {
    let metadata = std::fs::metadata(binary).map_err(|err| unreadable_binary(binary, &err.to_string()))?;
    if !metadata.is_file() {
        return Err(unreadable_binary(binary, "not a regular file"));
    }
    std::fs::read(binary).map_err(|err| unreadable_binary(binary, &err.to_string()))
}

/// Parse `data` as an ELF file, the only format the checks (and a Linux
/// image) deal in.
fn parse_elf(data: &[u8]) -> Result<object::File<'_>, String> {
    let file = object::File::parse(data).map_err(|err| err.to_string())?;
    match file.format() {
        object::BinaryFormat::Elf => Ok(file),
        format => Err(format!("{format:?} format")),
    }
}

/// The finding for a report run without a binary and without --deps-only.
fn no_binary() -> Finding {
    Finding {
        title: "no binary given, so the binary checks did not run".to_owned(),
        why: UNASSESSED.to_owned(),
        location: "the command line: the binary to assess is the BINARY argument".to_owned(),
        fix: "build it with 'make release-fips' and pass its path (as 'make fips-report' does), or pass --deps-only \
              to report on the dependency graph alone"
            .to_owned(),
    }
}

/// The finding for a binary path that cannot be read (missing, not a regular
/// file, no permission).
fn unreadable_binary(binary: &Path, reason: &str) -> Finding {
    Finding {
        title: format!("cannot read the binary at {} ({reason})", binary.display()),
        why: UNASSESSED.to_owned(),
        location: "the BINARY argument (FIPS_BIN for 'make fips-report')".to_owned(),
        fix: "build it with 'make release-fips', or pass the path of an existing, readable binary".to_owned(),
    }
}

/// The finding for a file that is not an ELF binary.
fn not_elf(binary: &Path, reason: &str) -> Finding {
    Finding {
        title: format!("{} is not an ELF file ({reason})", binary.display()),
        why: UNASSESSED.to_owned(),
        location: "the BINARY argument (FIPS_BIN for 'make fips-report')".to_owned(),
        fix: "pass the praxis-extproc executable itself ('make release-fips' writes \
              target/fips/release/praxis-extproc), not a script, archive or other file"
            .to_owned(),
    }
}

// -----------------------------------------------------------------------------
// Dynamic Linkage
// -----------------------------------------------------------------------------

/// Which libcrypto the dynamic loader resolves, according to ldd.
fn linkage(report: &mut Report, binary: &Path) {
    let Ok(output) = Command::new("ldd").arg(binary).output() else {
        report.warn("ldd not found; dynamic linkage not checked");
        return;
    };
    let ldd = String::from_utf8_lossy(&output.stdout);
    if ldd.lines().any(is_system_libcrypto) {
        report.ok("dynamically links the system libcrypto.so.3");
        report.info(&openssl_lines(&ldd));
    } else if ldd.contains("libcrypto") {
        report.fail(Finding {
            title: "links a libcrypto that is not the system one".to_owned(),
            why: "only the OS-provided libcrypto.so.3 (the openssl-libs RPM) contains the validated module".to_owned(),
            location: openssl_lines(&ldd),
            fix: "build against the system OpenSSL (OPENSSL_NO_VENDOR=1) and ship on UBI".to_owned(),
        });
    } else {
        report.fail(missing_libcrypto());
    }
}

/// Whether an ldd line resolves libcrypto to the system library.
fn is_system_libcrypto(line: &str) -> bool {
    line.contains("libcrypto.so.3 => /lib64/") || line.contains("libcrypto.so.3 => /usr/lib64/")
}

/// The ldd lines about libssl and libcrypto, joined on one line.
fn openssl_lines(ldd: &str) -> String {
    ldd.lines()
        .filter(|line| line.contains("libssl") || line.contains("libcrypto"))
        .map(str::trim)
        .collect::<Vec<_>>()
        .join("; ")
}

/// The finding for a binary that does not link libcrypto at all.
fn missing_libcrypto() -> Finding {
    Finding {
        title: "does not link libcrypto.so.3 at all".to_owned(),
        why: "no cryptography can be reaching the RHEL OpenSSL FIPS module; the binary carries its own crypto instead \
              of calling libcrypto"
            .to_owned(),
        location: "src/fips.rs is the only place a provider is chosen; a binary without libcrypto was built without \
                   it (or against a vendored OpenSSL)"
            .to_owned(),
        fix: "build with the rustls-openssl provider src/fips.rs installs and OPENSSL_NO_VENDOR=1, on a host with \
              the OpenSSL headers"
            .to_owned(),
    }
}

// -----------------------------------------------------------------------------
// Symbols
// -----------------------------------------------------------------------------

/// Symbols defined by a bundled crypto backend must be absent.
fn defined_symbols(report: &mut Report, file: &object::File<'_>) {
    let hits = backend_symbols(file);
    if !hits.is_empty() {
        let summary: Vec<String> = hits.iter().map(|(prefix, count)| format!("{count} {prefix}")).collect();
        report.fail(Finding {
            title: format!("defines symbols of a bundled crypto backend: {}", summary.join(" ")),
            why: "ring_core_/GFp_ mean ring, aws_lc_/AWSLC_ mean aws-lc-sys, BORINGSSL_ means boring-sys, OPENSSL_ \
                  means a statically linked or vendored OpenSSL; the scanner fails on any of them"
                .to_owned(),
            location: "the crate that owns the prefix; see the dependency graph section for who pulls it".to_owned(),
            fix: "remove the crate from the release graph (see above)".to_owned(),
        });
    } else if file.section_by_name(".symtab").is_none() {
        report.info("no bundled-crypto symbols in .dynsym; .symtab is stripped, so this is weaker evidence (the scanner sees the same)");
        report.ok("no bundled-crypto symbols exported");
    } else {
        report.ok("no bundled-crypto symbols defined");
    }
}

/// How many defined symbols (static and dynamic tables) carry each backend
/// prefix.
fn backend_symbols(file: &object::File<'_>) -> BTreeMap<&'static str, usize> {
    let mut hits = BTreeMap::new();
    // nm's rule: anything that is not undefined counts, whatever its type.
    for symbol in file.symbols().chain(file.dynamic_symbols()) {
        if symbol.is_undefined() {
            continue;
        }
        let Ok(name) = symbol.name() else {
            continue;
        };
        if let Some(prefix) = BACKEND_PREFIXES.iter().find(|prefix| name.starts_with(*prefix)) {
            *hits.entry(*prefix).or_insert(0) += 1;
        }
    }
    hits
}

/// Calls into libcrypto and libssl must be present: undefined dynamic symbols
/// that the system library resolves.
fn imports(report: &mut Report, file: &object::File<'_>) {
    let count = file.imports().map_or(0, |imports| {
        imports
            .iter()
            .filter(|import| {
                OPENSSL_PREFIXES
                    .iter()
                    .any(|prefix| import.name().starts_with(prefix.as_bytes()))
            })
            .count()
    });
    if count > 0 {
        report.ok(&format!(
            "imports {count} OpenSSL functions from libcrypto/libssl (undefined symbols resolved by the system library)"
        ));
    } else {
        report.fail(Finding {
            title: "imports no OpenSSL functions".to_owned(),
            why: "a binary that never calls into libcrypto performs all of its cryptography elsewhere".to_owned(),
            location: "same as the libcrypto linkage finding".to_owned(),
            fix: "same as the libcrypto linkage finding".to_owned(),
        });
    }
}

// -----------------------------------------------------------------------------
// OpenSSL Symbol Allowlist
// -----------------------------------------------------------------------------

/// The ELF symbol version the system OpenSSL 3 exports its base ABI under.
const OPENSSL_3_0_0_VERSION: &[u8] = b"OPENSSL_3.0.0";

/// The prefix every OpenSSL symbol version node shares. A version under this
/// prefix other than `OPENSSL_3.0.0` names a later OpenSSL ABI the validated
/// 3.0 module may not provide.
const OPENSSL_VERSION_PREFIX: &[u8] = b"OPENSSL_";

/// The OpenSSL-versioned symbols a binary imports, split by whether they bind
/// to the validated `OPENSSL_3.0.0` base ABI or to some other OpenSSL version.
#[derive(Default)]
struct OpensslImports<'a> {
    /// Base names (without the `@OPENSSL_3.0.0` suffix) imported under the base
    /// ABI; matched against the reviewed allowlist.
    base: BTreeSet<&'a str>,
    /// `name@OPENSSL_x.y.z` of every import bound to an OpenSSL version other
    /// than `OPENSSL_3.0.0`.
    other: BTreeSet<String>,
}

/// Every OpenSSL symbol the binary imports must bind to the `OPENSSL_3.0.0`
/// base ABI and be on the reviewed allowlist, so neither a call that needs a
/// later OpenSSL version nor one into a not-yet-vetted function slips past
/// before it ships.
fn openssl_imports(report: &mut Report, data: &[u8]) {
    match openssl_symbols(data) {
        Ok(imported) => {
            check_other_versions(report, &imported.other);
            check_allowlist(report, &imported.base);
        },
        Err(reason) => report.fail(uninspectable_imports(&reason)),
    }
}

/// Fail the report on any OpenSSL symbol bound to a version other than the
/// validated `OPENSSL_3.0.0` base ABI.
fn check_other_versions(report: &mut Report, other: &BTreeSet<String>) {
    if other.is_empty() {
        report.ok("every OpenSSL symbol imported binds to the @OPENSSL_3.0.0 base ABI");
    } else {
        report.fail(other_openssl_version(other));
    }
}

/// Fail the report on any `@OPENSSL_3.0.0` import that is not on the reviewed
/// allowlist.
fn check_allowlist(report: &mut Report, base: &BTreeSet<&str>) {
    let allowed = allowlist();
    let unexpected = unexpected_imports(base, &allowed);
    if unexpected.is_empty() {
        report.ok(&format!(
            "every one of the {} @OPENSSL_3.0.0 symbols imported is on the reviewed allowlist",
            base.len()
        ));
    } else {
        report.fail(unexpected_openssl(&unexpected));
    }
}

/// The undefined OpenSSL-versioned symbols the binary imports, split into the
/// `OPENSSL_3.0.0` base ABI and any other OpenSSL version.
///
/// Errors when the binary carries no GNU symbol version table: its imports
/// would then be unversioned and slip past both checks unchecked, so the caller
/// turns that into a finding rather than a silent pass.
fn openssl_symbols(data: &[u8]) -> Result<OpensslImports<'_>, String> {
    let elf = ElfFile64::<Endianness>::parse(data).map_err(|err| err.to_string())?;
    let endian = elf.endian();
    let symbols = elf.elf_dynamic_symbol_table();
    let versions = elf
        .elf_section_table()
        .versions(endian, data)
        .map_err(|err| err.to_string())?
        .ok_or("no GNU symbol version table (.gnu.version)")?;
    let mut imports = OpensslImports::default();
    for (index, symbol) in symbols.enumerate() {
        if !symbol.is_undefined(endian) {
            continue;
        }
        let version = versions
            .version(versions.version_index(endian, index))
            .map_err(|err| err.to_string())?;
        let Some(version) = version
            .map(Version::name)
            .filter(|name| name.starts_with(OPENSSL_VERSION_PREFIX))
        else {
            continue;
        };
        let name = import_name(symbol.name(endian, symbols.strings()))?;
        if version == OPENSSL_3_0_0_VERSION {
            imports.base.insert(name);
        } else {
            imports.other.insert(other_import(name, version));
        }
    }
    Ok(imports)
}

/// `name@OPENSSL_x.y.z` for an import bound to an OpenSSL version other than the
/// base ABI, the form the finding lists so the offending version is visible.
fn other_import(name: &str, version: &[u8]) -> String {
    format!("{name}@{}", String::from_utf8_lossy(version))
}

/// The UTF-8 name of an OpenSSL-versioned import from its raw string-table
/// entry, or the reason it cannot be one. Both checks read UTF-8 names only (the
/// allowlist holds valid UTF-8 and the other-version list renders it), so an
/// OpenSSL import with an unreadable or non-UTF-8 name could never be matched or
/// listed; failing here keeps such an import from slipping through unchecked.
fn import_name(raw: Result<&[u8], object::read::Error>) -> Result<&str, String> {
    let raw = raw.map_err(|err| format!("an OpenSSL import has an unreadable name: {err}"))?;
    std::str::from_utf8(raw).map_err(|err| {
        format!(
            "an OpenSSL import has a non-UTF-8 name ({err}): {:?}",
            String::from_utf8_lossy(raw)
        )
    })
}

/// The reviewed set of allowed `@OPENSSL_3.0.0` symbols, from the compiled-in
/// asset.
fn allowlist() -> BTreeSet<&'static str> {
    super::assets::OPENSSL_3_0_0_SYMBOLS
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect()
}

/// The imported symbols that are not on the allowlist, sorted.
fn unexpected_imports<'a>(imported: &BTreeSet<&'a str>, allowed: &BTreeSet<&str>) -> Vec<&'a str> {
    imported
        .iter()
        .copied()
        .filter(|name| !allowed.contains(name))
        .collect()
}

/// The finding for a binary importing an OpenSSL symbol nobody reviewed.
fn unexpected_openssl(symbols: &[&str]) -> Finding {
    Finding {
        title: format!(
            "imports @OPENSSL_3.0.0 symbols not on the allowlist: {}",
            symbols.join(" ")
        ),
        why: "the allowlist is every non-deprecated OpenSSL 3.0 export plus the deprecated symbols already in use; a \
              symbol outside it is a deprecated or otherwise non-standard call into libcrypto/libssl that has not been \
              reviewed for this FIPS build"
            .to_owned(),
        location: "xtask/assets/fips/openssl-3.0-nondeprecated-symbols.txt holds the allowed symbols".to_owned(),
        fix: "prefer a non-deprecated replacement; if the call is appropriate for the FIPS build, add its symbol to \
              xtask/assets/fips/openssl-3.0-nondeprecated-symbols.txt (deprecated symbols go in the header block)"
            .to_owned(),
    }
}

/// The finding for a binary importing an OpenSSL symbol bound to a version other
/// than the validated `OPENSSL_3.0.0` base ABI.
fn other_openssl_version(symbols: &BTreeSet<String>) -> Finding {
    let listed: Vec<&str> = symbols.iter().map(String::as_str).collect();
    Finding {
        title: format!(
            "imports OpenSSL symbols bound to a version other than @OPENSSL_3.0.0: {}",
            listed.join(" ")
        ),
        why: "the validated module is RHEL's OpenSSL 3.0.x; a symbol bound to a later version node (OPENSSL_3.1.0, \
              OPENSSL_3.2.0, ...) needs an ABI that module may not provide and ties the binary to a newer, \
              non-validated libcrypto"
            .to_owned(),
        location: "the ELF dynamic symbol table's GNU version entries (.gnu.version / .gnu.version_r)".to_owned(),
        fix: "call an OpenSSL function present in the 3.0.0 base ABI, or build against the system OpenSSL 3.0 headers \
              so the call binds to @OPENSSL_3.0.0"
            .to_owned(),
    }
}

/// The finding for a binary whose OpenSSL imports the check cannot inspect: not
/// a 64-bit ELF, no symbol version table, or an OpenSSL import with an
/// unreadable or non-UTF-8 name.
fn uninspectable_imports(reason: &str) -> Finding {
    Finding {
        title: format!("cannot inspect the binary's OpenSSL symbol imports ({reason})"),
        why: "the allowlist check reads the version and UTF-8 name of every OpenSSL import to match it; a versioned \
              OpenSSL import it cannot read would otherwise slip past the allowlist and ship unchecked"
            .to_owned(),
        location: "the ELF dynamic symbol table and GNU version sections (.gnu.version / .gnu.version_r)".to_owned(),
        fix: "assess a 64-bit ELF built by 'make release-fips'; keep the .gnu.version and .gnu.version_r sections (do \
              not strip them)"
            .to_owned(),
    }
}

// -----------------------------------------------------------------------------
// Manifest and Producer
// -----------------------------------------------------------------------------

/// The cargo-auditable manifest must be present, readable and free of denied
/// crates.
fn manifest(report: &mut Report, file: &object::File<'_>, binary: &Path) {
    let Some(section) = file.section_by_name(".dep-v0") else {
        report.fail(missing_manifest());
        return;
    };
    report.ok("cargo-auditable manifest (.dep-v0) present");
    let manifest = match section.data().map_err(|err| err.to_string()).and_then(parse_manifest) {
        Ok(manifest) => manifest,
        Err(reason) => {
            report.fail(unreadable_manifest(&reason, binary));
            return;
        },
    };
    if manifest.format != PRECURSOR_FORMAT {
        report.fail(metadata_derived(manifest.format, binary));
    }
    if manifest.denied.is_empty() {
        report.ok("manifest lists no denied crate");
    } else {
        report.fail(denied_manifest(&manifest.denied));
    }
}

/// The finding for a binary without a manifest.
fn missing_manifest() -> Finding {
    Finding {
        title: "no cargo-auditable manifest (.dep-v0 section)".to_owned(),
        why: "without it Red Hat's scanner cannot list the crates compiled in and reports the binary as inconclusive, \
              which fails a gated scan"
            .to_owned(),
        location: "the build command".to_owned(),
        fix: "build with 'make release-fips' (cargo auditable with the SBOM precursor) and keep .dep-v0 through \
              stripping"
            .to_owned(),
    }
}

/// The finding for a manifest that cannot be decoded.
fn unreadable_manifest(reason: &str, binary: &Path) -> Finding {
    Finding {
        title: format!("cargo-auditable manifest is unreadable ({reason})"),
        why: "the scanner treats a present but unparseable manifest as corrupt evidence and fails the binary"
            .to_owned(),
        location: format!("the build that produced {}", binary.display()),
        fix: "rebuild with cargo auditable; do not post-process the .dep-v0 section".to_owned(),
    }
}

/// The finding for a manifest that cargo-auditable built from `cargo
/// metadata` rather than cargo's SBOM precursor.
fn metadata_derived(format: u64, binary: &Path) -> Finding {
    Finding {
        title: format!(
            "manifest was derived from 'cargo metadata', not cargo's SBOM precursor (format {format}, expected \
             {PRECURSOR_FORMAT})"
        ),
        why: "a metadata-derived manifest can list crates the build never compiled (weak features, workspace-wide \
              feature unification), so it is not evidence of what is in the binary"
            .to_owned(),
        location: format!("the build command that produced {}", binary.display()),
        fix: "build with 'make release-fips' or the Containerfile (RUSTC_BOOTSTRAP=1 CARGO_BUILD_SBOM=true cargo \
              auditable -Zsbom ...)"
            .to_owned(),
    }
}

/// The finding for a manifest that names denied crates.
fn denied_manifest(listed: &[String]) -> Finding {
    Finding {
        title: format!("manifest lists denied crates: {}", listed.join(" ")),
        why: "this is exactly what the scanner's manifest check reads; it fails on the name alone, whether or not the \
              crate's code was linked"
            .to_owned(),
        location: "the dependency graph section when it has findings; otherwise the manifest was derived from 'cargo \
                   metadata', which lists crates the build never compiled (weak features, workspace-wide feature \
                   unification)"
            .to_owned(),
        fix: "fix the graph findings first; then build with cargo's SBOM precursor the way 'make release-fips' and \
              the Containerfile do (RUSTC_BOOTSTRAP=1 CARGO_BUILD_SBOM=true cargo auditable -Zsbom ...)"
            .to_owned(),
    }
}

/// The manifest's `format` when cargo-auditable built it from cargo's SBOM
/// precursor; `cargo metadata` yields 0 (or no field at all).
const PRECURSOR_FORMAT: u64 = 8;

/// What the report needs from a cargo-auditable manifest.
struct Manifest {
    /// The manifest's `format` field, 0 when absent.
    format: u64,
    /// Denied crates among the runtime packages, sorted. Build and dev
    /// packages are ignored, as the scanner ignores them.
    denied: Vec<String>,
}

/// Decompress and parse a `.dep-v0` section.
fn parse_manifest(compressed: &[u8]) -> Result<Manifest, String> {
    let mut json = Vec::new();
    flate2::read::ZlibDecoder::new(compressed)
        .read_to_end(&mut json)
        .map_err(|err| format!("zlib: {err}"))?;
    let manifest: serde_json::Value = serde_json::from_slice(&json).map_err(|err| format!("json: {err}"))?;
    let packages = manifest
        .get("packages")
        .and_then(serde_json::Value::as_array)
        .ok_or("no packages array")?;
    let mut denied: Vec<String> = packages
        .iter()
        .filter(|package| {
            package
                .get("kind")
                .and_then(serde_json::Value::as_str)
                .is_none_or(|kind| kind == "runtime")
        })
        .filter_map(|package| package.get("name").and_then(serde_json::Value::as_str))
        .filter(|name| DENIED.contains(name))
        .map(str::to_owned)
        .collect();
    denied.sort();
    denied.dedup();
    let format = manifest.get("format").and_then(serde_json::Value::as_u64).unwrap_or(0);
    Ok(Manifest { format, denied })
}

/// The rustc producer string must survive stripping, so the scanner
/// classifies the file as a Rust binary.
fn producer(report: &mut Report, file: &object::File<'_>) {
    let has_rustc = file
        .section_by_name(".comment")
        .and_then(|section| section.data().ok())
        .is_some_and(|data| data.windows(5).any(|window| window == b"rustc"));
    if has_rustc {
        report.ok("rustc producer string present (scanner classifies it as a Rust binary)");
    } else {
        report.fail(Finding {
            title: "no rustc producer string in .comment".to_owned(),
            why: "a stripped binary with neither .comment nor .dep-v0 is scanned as a plain executable and bundled \
                  crypto passes silently"
                .to_owned(),
            location: "the strip step".to_owned(),
            fix: "keep the .comment section (do not strip it) and build with cargo auditable".to_owned(),
        });
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::{io::Write as _, path::PathBuf};

    use openssl::hash::{MessageDigest, hash};

    use super::*;

    /// zlib-compress a manifest the way cargo-auditable stores it.
    fn compressed(manifest: &str) -> Vec<u8> {
        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(manifest.as_bytes()).expect("in-memory write");
        encoder.finish().expect("in-memory finish")
    }

    #[test]
    fn denied_runtime_packages_are_listed_and_build_packages_ignored() {
        let manifest = r#"{"format":8,"packages":[
            {"name":"ring","version":"0.17.14","kind":"runtime"},
            {"name":"sha2","version":"0.10.9","kind":"build"},
            {"name":"hmac","version":"0.12.1"},
            {"name":"serde","version":"1.0.229"},
            {"name":"ring","version":"0.16.20"}
        ]}"#;
        let parsed = parse_manifest(&compressed(manifest)).expect("a valid manifest");
        assert_eq!(
            parsed.denied,
            ["hmac", "ring"],
            "runtime (default kind) denied crates, sorted and de-duplicated"
        );
        assert_eq!(parsed.format, PRECURSOR_FORMAT, "the format field is read");
    }

    #[test]
    fn a_clean_manifest_lists_nothing_and_a_metadata_one_is_flagged() {
        let manifest = r#"{"packages":[{"name":"openssl","version":"0.10.81"}]}"#;
        let parsed = parse_manifest(&compressed(manifest)).expect("a valid manifest");
        assert!(parsed.denied.is_empty(), "nothing denied");
        assert_eq!(parsed.format, 0, "no format field means cargo metadata");
        let finding = metadata_derived(parsed.format, Path::new("praxis-extproc"));
        assert!(
            finding.title.contains("format 0, expected 8"),
            "the finding names both formats: {}",
            finding.title
        );
    }

    /// The binary section's report for `binary`, on its own.
    fn binary_report(binary: Option<&Path>) -> Report {
        let mut report = Report::default();
        section(&mut report, binary);
        report
    }

    #[test]
    fn a_binary_the_checks_cannot_open_fails_the_report() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let script = dir.path().join("praxis-extproc");
        std::fs::write(&script, "#!/bin/sh\n").expect("a temporary file");
        let cases = [
            (None, "no binary given"),
            (Some(dir.path().join("missing")), "cannot read the binary"),
            (Some(dir.path().to_owned()), "not a regular file"),
            // A device is refused before it is read; /dev/null keeps this
            // test from hanging if that guard ever goes.
            (Some(PathBuf::from("/dev/null")), "not a regular file"),
            (Some(script), "is not an ELF file"),
        ];
        for (binary, title) in cases {
            let report = binary_report(binary.as_deref());
            assert!(report.has_finding(title), "{binary:?} is a finding: {title}");
            assert!(
                !report.has_finding("libcrypto"),
                "{binary:?} never reaches ldd, so there is no linkage finding about it"
            );
        }
    }

    #[test]
    fn a_corrupt_manifest_is_an_error() {
        assert!(parse_manifest(b"not zlib").is_err(), "garbage is not zlib");
        assert!(
            parse_manifest(&compressed("[]")).is_err(),
            "JSON without a packages array"
        );
    }

    #[test]
    fn the_test_binary_itself_is_a_rust_elf_and_the_symbol_scan_sees_what_it_links() {
        let me = std::env::current_exe().expect("the test binary has a path");
        let data = std::fs::read(&me).expect("the test binary is readable");
        let file = parse_elf(&data).expect("the test binary is an ELF file");
        let hits = backend_symbols(&file);
        assert!(
            hits.is_empty(),
            "xtask links no bundled crypto backend, and the scan agrees: {hits:?}"
        );
        let mut report = Report::default();
        producer(&mut report, &file);
        assert!(!report.failed(), "a rustc-built binary carries the producer string");
        let digest = hash(MessageDigest::sha256(), b"praxis").expect("the test host has a working libcrypto");
        assert_eq!(
            digest.len(),
            32,
            "the SHA-256 that pulls EVP_sha256 into this binary actually ran"
        );
        let imported = openssl_symbols(&data).expect("the version scan reads a real ELF");
        assert!(
            imported.base.contains("EVP_sha256"),
            "this test hashes through openssl::hash, so the binary imports EVP_sha256 under the base ABI and the scan \
             must find that exact symbol: {:?}",
            imported.base
        );
    }

    #[test]
    fn the_allowlist_parses_symbols_and_ignores_comments_and_blank_lines() {
        let allowed = allowlist();
        assert!(
            allowed.contains("EVP_sha256") && allowed.contains("SSL_new") && allowed.contains("X509_free"),
            "known OpenSSL symbols are on the list"
        );
        assert!(
            !allowed.iter().any(|line| line.is_empty() || line.starts_with('#')),
            "comments and blank lines are not entries: {allowed:?}"
        );
        assert!(
            allowed.len() > 100,
            "the full allowlist is loaded, not a fragment: {}",
            allowed.len()
        );
    }

    #[test]
    fn unexpected_imports_are_only_the_symbols_off_the_allowlist() {
        let allowed = allowlist();
        let imported = BTreeSet::from(["EVP_sha256", "EVP_brandnew", "SSL_new"]);
        assert_eq!(
            unexpected_imports(&imported, &allowed),
            ["EVP_brandnew"],
            "only the symbol the allowlist does not cover is reported"
        );
        let clean = BTreeSet::from(["EVP_sha256", "SSL_new"]);
        assert!(
            unexpected_imports(&clean, &allowed).is_empty(),
            "an all-allowed set has no unexpected imports"
        );
        let finding = unexpected_openssl(&["EVP_brandnew"]);
        assert!(
            finding.title.contains("EVP_brandnew"),
            "the finding names the offending symbol: {}",
            finding.title
        );
    }

    #[test]
    fn an_openssl_symbol_under_another_version_fails_the_report() {
        let mut clean = Report::default();
        check_other_versions(&mut clean, &BTreeSet::new());
        assert!(!clean.failed(), "no other-version imports is a pass, not a finding");

        let other = BTreeSet::from(["EVP_foo@OPENSSL_3.2.0".to_owned()]);
        let mut report = Report::default();
        check_other_versions(&mut report, &other);
        assert!(
            report.failed(),
            "an OpenSSL symbol bound to a version other than 3.0.0 fails the report"
        );
        assert!(
            report.has_finding("EVP_foo@OPENSSL_3.2.0"),
            "the finding names the offending symbol and its version"
        );
        assert!(
            report.has_finding("other than @OPENSSL_3.0.0"),
            "the finding says the version is not the validated base ABI"
        );
    }

    #[test]
    fn an_other_version_import_is_rendered_name_at_version() {
        assert_eq!(
            other_import("EVP_foo", b"OPENSSL_3.2.0"),
            "EVP_foo@OPENSSL_3.2.0",
            "the import is listed as name@version so the offending version is visible"
        );
    }

    #[test]
    fn a_binary_without_readable_symbol_versions_is_a_finding_not_a_pass() {
        let mut header = [0_u8; 64];
        header[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        let mut report = Report::default();
        openssl_imports(&mut report, &header);
        assert!(
            report.has_finding("no GNU symbol version table"),
            "an ELF without .gnu.version fails the report instead of passing zero imports"
        );
    }

    #[test]
    fn a_non_utf8_openssl_import_name_is_an_error_not_a_dropped_symbol() {
        assert_eq!(
            import_name(Ok(b"EVP_sha256")),
            Ok("EVP_sha256"),
            "a valid name reads back"
        );
        let bad = import_name(Ok(&[b'E', b'V', b'P', 0xFF, 0xFE]));
        let reason = bad.expect_err("a non-UTF-8 name is rejected, not silently dropped");
        assert!(
            reason.contains("non-UTF-8 name"),
            "the reason names the problem so it becomes a finding: {reason}"
        );
    }
}
