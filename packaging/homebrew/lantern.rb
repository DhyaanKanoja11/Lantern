# typed: false
# frozen_string_literal: true

# Homebrew Formula for Lantern (https://github.com/DhyaanKanoja11/Lantern)
class Lantern < Formula
  desc "Local-first developer security tool explaining service reachability causality"
  homepage "https://github.com/DhyaanKanoja11/Lantern"
  version "0.3.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/DhyaanKanoja11/Lantern/releases/download/v0.3.0/lantern_0.3.0_darwin_arm64.tar.gz"
      sha256 "49cae4ec232481857e787e9a737604dd173a1afbf0032b4b224cb87e9badbecf"

      def install
        bin.install "lantern"
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/DhyaanKanoja11/Lantern/releases/download/v0.3.0/lantern_0.3.0_darwin_amd64.tar.gz"
      sha256 "4505f5060c3b76f8a9c88b876ccd1a534cd6bdf32bb000610f92a1b12d2f1285"

      def install
        bin.install "lantern"
      end
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/DhyaanKanoja11/Lantern/releases/download/v0.3.0/lantern_0.3.0_linux_arm64.tar.gz"
      sha256 "4d40ff817b366aef7b446d5238c36cdd3708b545c47732f44ee1eb056a75b723"

      def install
        bin.install "lantern"
      end
    end
    if Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "https://github.com/DhyaanKanoja11/Lantern/releases/download/v0.3.0/lantern_0.3.0_linux_amd64.tar.gz"
      sha256 "73de38fbd25ac3c2ede96b830abbbf59249572b5019b9e5b11b3d8d77a53a752"

      def install
        bin.install "lantern"
      end
    end
  end

  def caveats
    <<~EOS
      Lantern natively discovers listening sockets and performs process and container
      attribution across macOS, Linux, and Windows.
    EOS
  end

  test do
    assert_match "lantern v#{version}", shell_output("#{bin}/lantern version")
  end
end
