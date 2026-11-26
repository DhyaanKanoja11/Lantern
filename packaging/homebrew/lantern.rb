# typed: false
# frozen_string_literal: true

# Homebrew Formula for Lantern (https://github.com/DhyaanKanoja11/Lantern)
class Lantern < Formula
  desc "Local-first developer security tool explaining service reachability causality"
  homepage "https://github.com/DhyaanKanoja11/Lantern"
  version "0.4.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/DhyaanKanoja11/Lantern/releases/download/v0.4.0/lantern_0.4.0_darwin_arm64.tar.gz"
      sha256 "9627c9b2dabb94eb567f1a1c28680e983ac961f8572346cd03a48c066227d2a2"

      def install
        bin.install "lantern"
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/DhyaanKanoja11/Lantern/releases/download/v0.4.0/lantern_0.4.0_darwin_amd64.tar.gz"
      sha256 "6cc58b867987958d976809c0bf026be5d08bb4734dc8de426ade8cf51df13fac"

      def install
        bin.install "lantern"
      end
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/DhyaanKanoja11/Lantern/releases/download/v0.4.0/lantern_0.4.0_linux_arm64.tar.gz"
      sha256 "587ca43fe219ce400a299dbde356257d860b843ea12e5a61306680e5dbffe76c"

      def install
        bin.install "lantern"
      end
    end
    if Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "https://github.com/DhyaanKanoja11/Lantern/releases/download/v0.4.0/lantern_0.4.0_linux_amd64.tar.gz"
      sha256 "99ca82e4b00a2681c8f2da0fc87e1b02eb37244ddaffae8c809e7906aa28c7a8"

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
