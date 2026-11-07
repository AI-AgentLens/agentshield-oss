/**
 * AgentShield Hook for OpenClaw
 *
 * Injects a notice into the agent context on agent:bootstrap. This is NOT
 * enforcement: OpenClaw sends no tool call to `agentshield hook`, so no
 * command is evaluated (#4582). The notice says so, rather than telling the
 * agent a hook is checking its commands.
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
      "⚠️ AgentShield hook enabled but binary not found. Install: brew install AI-AgentLens/oss/agentshield"
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
      "# AgentShield — Notice",
      "",
      "AgentShield is installed, but it is NOT evaluating commands in this",
      "OpenClaw session: no shell command or tool call is sent to it.",
      "Do not treat the absence of a block as a safety signal. Ask the user",
      "before running destructive or credential-touching commands.",
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
