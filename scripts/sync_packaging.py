#!/usr/bin/env python3
"""
sync_packaging.py - Synchronize package manager manifests for Lantern.

Updates Homebrew formula, Scoop manifest, and AUR PKGBUILD with new version
and sha256 checksums, and optionally pushes updates to remote tap/bucket repositories.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path


def parse_checksums(checksums_path: Path) -> dict:
    """Parse sha256 checksums from GoReleaser checksums.txt file."""
    if not checksums_path.is_file():
        raise FileNotFoundError(f"Checksums file not found at: {checksums_path}")

    hashes = {}
    with open(checksums_path, "r", encoding="utf-8") as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) >= 2:
                file_hash, file_name = parts[0], parts[1].lstrip("*")
                hashes[file_name] = file_hash
    return hashes


def update_homebrew_formula(formula_path: Path, version: str, hashes: dict) -> str:
    """Generate updated Homebrew formula."""
    darwin_arm64 = hashes.get(f"lantern_{version}_darwin_arm64.tar.gz", "")
    darwin_amd64 = hashes.get(f"lantern_{version}_darwin_amd64.tar.gz", "")
    linux_arm64 = hashes.get(f"lantern_{version}_linux_arm64.tar.gz", "")
    linux_amd64 = hashes.get(f"lantern_{version}_linux_amd64.tar.gz", "")

    content = f'''# typed: false
# frozen_string_literal: true

# Homebrew Formula for Lantern (https://github.com/DhyaanKanoja11/Lantern)
class Lantern < Formula
  desc "Local-first developer security tool explaining service reachability causality"
  homepage "https://github.com/DhyaanKanoja11/Lantern"
  version "{version}"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/DhyaanKanoja11/Lantern/releases/download/v{version}/lantern_{version}_darwin_arm64.tar.gz"
      sha256 "{darwin_arm64}"

      def install
        bin.install "lantern"
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/DhyaanKanoja11/Lantern/releases/download/v{version}/lantern_{version}_darwin_amd64.tar.gz"
      sha256 "{darwin_amd64}"

      def install
        bin.install "lantern"
      end
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/DhyaanKanoja11/Lantern/releases/download/v{version}/lantern_{version}_linux_arm64.tar.gz"
      sha256 "{linux_arm64}"

      def install
        bin.install "lantern"
      end
    end
    if Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "https://github.com/DhyaanKanoja11/Lantern/releases/download/v{version}/lantern_{version}_linux_amd64.tar.gz"
      sha256 "{linux_amd64}"

      def install
        bin.install "lantern"
      end
    end
  end

  def caveats
    <<~EOS
      Lantern requires Linux or WSL2 kernel socket interfaces (/proc/net/tcp, ss)
      for full socket discovery and process attribution. On macOS, diagnostic commands
      ('doctor', 'version') operate natively, while live socket inspection is designed
      for Linux and WSL2 development environments.
    EOS
  end

  test do
    assert_match "lantern v#{{version}}", shell_output("#{{bin}}/lantern version")
  end
end
'''
    formula_path.parent.mkdir(parents=True, exist_ok=True)
    with open(formula_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)
    return content


def update_scoop_manifest(scoop_path: Path, version: str, hashes: dict) -> dict:
    """Generate updated Scoop manifest."""
    win_hash = hashes.get(f"lantern_{version}_windows_amd64.zip", "")
    manifest = {
        "version": version,
        "description": "Local-first developer security tool explaining why network services are reachable",
        "homepage": "https://github.com/DhyaanKanoja11/Lantern",
        "license": "MIT",
        "architecture": {
            "64bit": {
                "url": f"https://github.com/DhyaanKanoja11/Lantern/releases/download/v{version}/lantern_{version}_windows_amd64.zip",
                "hash": win_hash
            }
        },
        "bin": "lantern.exe",
        "checkver": "github",
        "autoupdate": {
            "architecture": {
                "64bit": {
                    "url": "https://github.com/DhyaanKanoja11/Lantern/releases/download/v$version/lantern_$version_windows_amd64.zip"
                }
            }
        },
        "notes": "Lantern on native Windows operates in diagnostic mode ('doctor', 'version'). For active socket inspection and process attribution, run Lantern inside WSL2."
    }
    scoop_path.parent.mkdir(parents=True, exist_ok=True)
    with open(scoop_path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")
    return manifest


def update_aur_manifests(aur_dir: Path, version: str, hashes: dict):
    """Update PKGBUILD and .SRCINFO for Arch Linux AUR."""
    linux_amd64 = hashes.get(f"lantern_{version}_linux_amd64.tar.gz", "")
    linux_arm64 = hashes.get(f"lantern_{version}_linux_arm64.tar.gz", "")

    pkgbuild_path = aur_dir / "PKGBUILD"
    if pkgbuild_path.is_file():
        content = pkgbuild_path.read_text(encoding="utf-8")
        content = re.sub(r'pkgver=.*', f'pkgver={version}', content)
        content = re.sub(r'pkgrel=.*', 'pkgrel=1', content)
        if linux_amd64:
            content = re.sub(r"sha256sums_x86_64=\('.*?'\)", f"sha256sums_x86_64=('{linux_amd64}')", content)
        if linux_arm64:
            content = re.sub(r"sha256sums_aarch64=\('.*?'\)", f"sha256sums_aarch64=('{linux_arm64}')", content)
        pkgbuild_path.write_text(content, encoding="utf-8", newline="\n")

    srcinfo_path = aur_dir / ".SRCINFO"
    if srcinfo_path.is_file():
        srcinfo = f'''pkgbase = lantern-bin
\tpkgdesc = Local-first developer security tool explaining configuration causality behind exposed services
\tpkgver = {version}
\tpkgrel = 1
\turl = https://github.com/DhyaanKanoja11/Lantern
\tarch = x86_64
\tarch = aarch64
\tlicense = MIT
\tdepends = iproute2
\toptdepends = docker: for container and Compose correlation
\tprovides = lantern
\tconflicts = lantern
\tsource_x86_64 = https://github.com/DhyaanKanoja11/Lantern/releases/download/v{version}/lantern_{version}_linux_amd64.tar.gz
\tsha256sums_x86_64 = {linux_amd64}
\tsource_aarch64 = https://github.com/DhyaanKanoja11/Lantern/releases/download/v{version}/lantern_{version}_linux_arm64.tar.gz
\tsha256sums_aarch64 = {linux_arm64}

pkgname = lantern-bin
'''
        srcinfo_path.write_text(srcinfo, encoding="utf-8", newline="\n")


def push_to_remote_repo(repo_name: str, target_file_rel: str, source_file: Path, version: str, token: str):
    """Clone remote repo, update target file, commit and push."""
    import tempfile
    with tempfile.TemporaryDirectory() as tmpdir:
        clone_url = f"https://x-access-token:{token}@github.com/{repo_name}.git"
        dest_repo_dir = Path(tmpdir) / "repo"
        print(f"[*] Cloning {repo_name}...")
        res = subprocess.run(["git", "clone", "--depth", "1", clone_url, str(dest_repo_dir)], capture_output=True, text=True)
        if res.returncode != 0:
            print(f"[!] Failed to clone {repo_name}: {res.stderr}")
            return False

        target_path = dest_repo_dir / target_file_rel
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_bytes(source_file.read_bytes())

        subprocess.run(["git", "-C", str(dest_repo_dir), "config", "user.name", "github-actions[bot]"], check=True)
        subprocess.run(["git", "-C", str(dest_repo_dir), "config", "user.email", "github-actions[bot]@users.noreply.github.com"], check=True)
        subprocess.run(["git", "-C", str(dest_repo_dir), "add", target_file_rel], check=True)

        status_res = subprocess.run(["git", "-C", str(dest_repo_dir), "status", "--porcelain"], capture_output=True, text=True, check=True)
        if not status_res.stdout.strip():
            print(f"[*] {repo_name} is already up to date with version {version}.")
            return True

        subprocess.run(["git", "-C", str(dest_repo_dir), "commit", "-m", f"bump: lantern v{version}"], check=True)
        push_res = subprocess.run(["git", "-C", str(dest_repo_dir), "push", "origin", "main"], capture_output=True, text=True)
        if push_res.returncode != 0:
            print(f"[!] Failed to push to {repo_name}: {push_res.stderr}")
            return False

        print(f"[+] Successfully pushed updated manifest to {repo_name}!")
        return True


def main():
    parser = argparse.ArgumentParser(description="Sync package manifests for Lantern")
    parser.add_argument("--version", required=True, help="Release version (e.g. 0.2.1 or v0.2.1)")
    parser.add_argument("--checksums", required=True, help="Path to checksums.txt")
    parser.add_argument("--token", default="", help="GitHub PAT with repo scope for pushing to tap/bucket")
    parser.add_argument("--dry-run", action="store_true", help="Do not push to remote repositories")
    args = parser.parse_args()

    version = args.version.lstrip("v")
    checksums_path = Path(args.checksums)
    repo_root = Path(__file__).resolve().parent.parent

    print(f"[*] Processing packaging manifests for Lantern v{version}...")
    hashes = parse_checksums(checksums_path)
    print(f"[*] Loaded {len(hashes)} file hashes from {checksums_path.name}")

    # 1. Update local packaging files
    homebrew_path = repo_root / "packaging" / "homebrew" / "lantern.rb"
    update_homebrew_formula(homebrew_path, version, hashes)
    print(f"[+] Updated local Homebrew formula: {homebrew_path.relative_to(repo_root)}")

    scoop_path = repo_root / "packaging" / "scoop" / "lantern.json"
    update_scoop_manifest(scoop_path, version, hashes)
    print(f"[+] Updated local Scoop manifest: {scoop_path.relative_to(repo_root)}")

    aur_dir = repo_root / "packaging" / "aur"
    update_aur_manifests(aur_dir, version, hashes)
    print(f"[+] Updated local AUR manifests: {aur_dir.relative_to(repo_root)}")

    # 2. Remote updates
    if args.dry_run or not args.token:
        if not args.token and not args.dry_run:
            print("[*] No GitHub token provided; skipping remote repo synchronization.")
            print("[*] (Set secret RELEASE_PAT in repository settings to enable automatic push).")
        else:
            print("[*] Dry run mode; remote repositories will not be updated.")
        return

    # Update Homebrew Tap repo
    push_to_remote_repo(
        repo_name="DhyaanKanoja11/homebrew-lantern",
        target_file_rel="Formula/lantern.rb",
        source_file=homebrew_path,
        version=version,
        token=args.token
    )

    # Update Scoop Bucket repo
    push_to_remote_repo(
        repo_name="DhyaanKanoja11/scoop-lantern",
        target_file_rel="bucket/lantern.json",
        source_file=scoop_path,
        version=version,
        token=args.token
    )

    print(f"[+] Packaging synchronization for v{version} complete!")


if __name__ == "__main__":
    main()
