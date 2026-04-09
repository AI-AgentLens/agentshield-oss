/**
 * AgentShield Hook for OpenClaw
 *
 * Injects security-aware bootstrap instructions into the agent context.
 * On agent:bootstrap, adds an AGENTSHIELD.md file that tells the agent
 * a PreToolUse hook will evaluate every command through AgentShield's
 * 7-layer pipeline before the host executes it. The agent does NOT wrap
 * commands — AgentShield is evaluation-only and never executes (see the
 * removed `agentshield run` subcommand: it was taken out after an
 * `agentshield run -- rm -rf /` incident wiped a user's data).
 */

import { readFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { execSync } from "child_process";

// Resolve the directory this handler lives in
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const handler = async (event: any) => {
  if (event.type !== "agent" || event.action !== "bootstrap") {
    return;
  }

  // Verify agentshield is available
  let version = "unknown";
  try {
    version = execSync("agentshield version 2>/dev/null", {
      encoding: "utf8",
      timeout: 5000,
    }).trim();
  } catch {
    console.error(
      "[agentshield] warning: agentshield binary not found in PATH"
    );
    event.messages.push(
      "⚠️ AgentShield hook enabled but binary not found. Install: brew install security-researcher-ca/tap/agentshield"
    );
    return;
  }

  // Load the bootstrap markdown
  let bootstrapContent: string;
  try {
    bootstrapContent = readFileSync(
      join(__dirname, "AGENTSHIELD.md"),
      "utf8"
    );
  } catch {
    // Fallback inline content if file not found
    bootstrapContent = [
      "# AgentShield — Runtime Security",
      "",
      "A PreToolUse hook evaluates every shell command and MCP tool call",
      "through AgentShield's 7-layer pipeline before the host executes it.",
      "Issue commands normally — you do NOT need to wrap or prefix anything.",
      "",
      "If AgentShield blocks a command, do NOT retry or rephrase to bypass it.",
      "Report the block (rule ID + reason) to the user and ask for guidance.",
    ].join("\n");
  }

  // Inject as a bootstrap file
  if (!event.context.bootstrapFiles) {
    event.context.bootstrapFiles = [];
  }

  event.context.bootstrapFiles.push({
    filename: "AGENTSHIELD.md",
    content: bootstrapContent,
    role: "system",
  });

  console.log(`[agentshield] Bootstrap injected (v${version})`);
};

export default handler;
