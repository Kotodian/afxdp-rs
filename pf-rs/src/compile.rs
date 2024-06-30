use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Result};

use crate::error::Error;

pub fn compile(src: &Path, dst: &Path) -> Result<()> {
    let clang = PathBuf::from("clang");
    let mut cmd = Command::new(clang.as_os_str());

    let options = format!("-I{}", "/usr/include");
    cmd.args(options.split_whitespace());

    let arch = match std::env::consts::ARCH {
        "x86_64" => "x86",
        "aarch64" => "arm64",
        _ => std::env::consts::ARCH,
    };

    cmd.arg("-g")
        .arg("-O3")
        .arg("-Wextra")
        .arg("-Wall")
        .arg("-target")
        .arg("bpf")
        .arg("-c")
        .arg(format!("-D__TARGET_ARCH_{}", arch))
        .arg(src.as_os_str())
        .arg("-o")
        .arg(dst);

    let output = cmd.output().map_err(|e| Error::Build(e.to_string()))?;

    if !output.status.success() {
        bail!(Error::Build(format!(
            "clang failed to compile BPF program: {:?}",
            output
        )));
    }

    Ok(())
}
