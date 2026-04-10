class Agentshield < Formula
  desc "Local-first runtime security gateway for LLM agents"
  homepage "https://github.com/security-researcher-ca/AI_Agent_Shield"
  url "https://github.com/security-researcher-ca/AI_Agent_Shield/archive/v0.2.0.tar.gz"
  sha256 ""
  license "Apache-2.0"
  head "https://github.com/security-researcher-ca/AI_Agent_Shield.git", branch: "main"

  depends_on "go" => :build

  def install
    ldflags = %W[
      -s -w
      -X github.com/security-researcher-ca/agentshield/internal/cli.Version=#{version}
      -X github.com/security-researcher-ca/agentshield/internal/cli.GitCommit=#{tap.user}
      -X github.com/security-researcher-ca/agentshield/internal/cli.BuildDate=#{time.iso8601}
    ]
    system "go", "build", *std_go_args(ldflags:), "./cmd/agentshield"

    # Install wrapper script for IDE agent integration
    (share/"agentshield").install "scripts/agentshield-wrapper.sh"
    chmod 0755, share/"agentshield/agentshield-wrapper.sh"

    # Install default policy packs
    (share/"agentshield/packs").install Dir["packs/*.yaml"]
    (share/"agentshield/packs/mcp").install Dir["packs/community/mcp/*.yaml"]

    # Install default config
    (share/"agentshield").install "configs/default_policy.yaml"
  end

  def caveats
    <<~EOS
      To set up AgentShield for your IDE agent:
        agentshield setup

      To install default policy packs:
        agentshield setup --install

      Wrapper script installed to:
        #{share}/agentshield/agentshield-wrapper.sh
    EOS
  end

  test do
    assert_match "AgentShield", shell_output("#{bin}/agentshield version")
  end
end
