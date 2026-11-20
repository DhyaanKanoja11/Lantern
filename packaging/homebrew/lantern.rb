# typed: false
# frozen_string_literal: true

# Homebrew Formula for Lantern (https://github.com/DhyaanKanoja11/Lantern)
class Lantern < Formula
  desc "Local-first developer security tool explaining service reachability causality"
  homepage "https://github.com/DhyaanKanoja11/Lantern"
  version "0.2.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/DhyaanKanoja11/Lantern/releases/download/v0.2.0/lantern_0.2.0_darwin_arm64.tar.gz"
      sha256 "7d50ef21324081877af0239986060cf3488e3cb45861ad72a660db6fc7b36348"

      def install
        bin.install "lantern"
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/DhyaanKanoja11/Lantern/releases/download/v0.2.0/lantern_0.2.0_darwin_amd64.tar.gz"
      sha256 "b01cc8170e9a3c0c1f838e5f08865e6e91edc1514d67774061a8dcbb67dc431e"

      def install
        bin.install "lantern"
      end
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/DhyaanKanoja11/Lantern/releases/download/v0.2.0/lantern_0.2.0_linux_arm64.tar.gz"
      sha256 "c32dbb1a2de8bd4a76ec1dea52cd83141f25a96566ca2f273cedd93d90eb1275"

      def install
        bin.install "lantern"
      end
    end
    if Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "https://github.com/DhyaanKanoja11/Lantern/releases/download/v0.2.0/lantern_0.2.0_linux_amd64.tar.gz"
      sha256 "3520b2833f13619d5b5435fe7bb2b857e63c98e0fe2bdb91e404b8a7a01ad18d"

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
