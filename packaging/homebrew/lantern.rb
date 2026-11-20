# typed: false
# frozen_string_literal: true

# Homebrew Formula for Lantern (https://github.com/DhyaanKanoja11/Lantern)
class Lantern < Formula
  desc "Local-first developer security tool explaining service reachability causality"
  homepage "https://github.com/DhyaanKanoja11/Lantern"
  version "0.2.1"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/DhyaanKanoja11/Lantern/releases/download/v0.2.1/lantern_0.2.1_darwin_arm64.tar.gz"
      sha256 "8c9d6e4b45006e0f39440c347491022da0c6e37e0fa15b5ee5364f6f321c1ac5"

      def install
        bin.install "lantern"
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/DhyaanKanoja11/Lantern/releases/download/v0.2.1/lantern_0.2.1_darwin_amd64.tar.gz"
      sha256 "9a6784b17005aeae7e138083390484842cdc6f2ea26dae0035b6f701b9523b23"

      def install
        bin.install "lantern"
      end
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/DhyaanKanoja11/Lantern/releases/download/v0.2.1/lantern_0.2.1_linux_arm64.tar.gz"
      sha256 "0ef2c1449c2c6cfd01483bfb08187e03459d9c4de044d4b2f1be5e9a94dbba60"

      def install
        bin.install "lantern"
      end
    end
    if Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "https://github.com/DhyaanKanoja11/Lantern/releases/download/v0.2.1/lantern_0.2.1_linux_amd64.tar.gz"
      sha256 "7d46ba766397657806ff6e94832dff53c926ab350a163596ec4bb78b7063dd3f"

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
