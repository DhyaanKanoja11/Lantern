# typed: false
# frozen_string_literal: true

# Homebrew Formula for Lantern (https://github.com/DhyaanKanoja11/Lantern)
class Lantern < Formula
  desc "Local-first developer security tool explaining service reachability causality"
  homepage "https://github.com/DhyaanKanoja11/Lantern"
  version "0.5.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/DhyaanKanoja11/Lantern/releases/download/v0.5.0/lantern_0.5.0_darwin_arm64.tar.gz"
      sha256 "621bb357e01bb9a299530fd23424dbda4963ddd2ee84af15fbe397cfad143d31"

      def install
        bin.install "lantern"
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/DhyaanKanoja11/Lantern/releases/download/v0.5.0/lantern_0.5.0_darwin_amd64.tar.gz"
      sha256 "798d62023f39c087105b490d1951a1c157b35f1bb3ab168469bb60ba5906c084"

      def install
        bin.install "lantern"
      end
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/DhyaanKanoja11/Lantern/releases/download/v0.5.0/lantern_0.5.0_linux_arm64.tar.gz"
      sha256 "ee571dea0302a25ee3bf676ae4f0c3cf4efbe034d719ff369a6aa94eeee78703"

      def install
        bin.install "lantern"
      end
    end
    if Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "https://github.com/DhyaanKanoja11/Lantern/releases/download/v0.5.0/lantern_0.5.0_linux_amd64.tar.gz"
      sha256 "9a77595c5ac0cf62301bd284a430910e280f925091891496c6c8747713d3b9a3"

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
    assert_match "lantern v#{version}", shell_output("#{bin}/lantern version")
  end
end
