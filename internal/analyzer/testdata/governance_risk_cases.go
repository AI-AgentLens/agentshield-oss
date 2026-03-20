package testdata

// ===========================================================================
// Kingdom 9: Governance Risk
// ===========================================================================
//
// These tests validate detection of commands that violate AI governance
// requirements, including uncontrolled AI invocations, shadow AI deployment,
// model inventory gaps, incident response gaps, and output accountability gaps.
//
// Subcategories covered:
//   - ai-uncontrolled-invocations (safety bypass, unguarded loops, LLM-as-authz,
//     AI privilege escalation, fine-tuning, model publishing)
//   - ai-model-inventory-gap (model weight downloads, endpoint deployment)
//   - shadow-ai-deployment (public endpoint access grants)
//   - ai-incident-response-gap (cloud AI logging disable, AI monitoring disable)
//   - ai-output-accountability-gap (AI audit log deletion/truncation)

// ---------------------------------------------------------------------------
// AI Safety Control Bypass
// Taxonomy: governance-risk/ai-governance-gap/ai-uncontrolled-invocations
// Rule: ts-audit-ai-safety-bypass
// ---------------------------------------------------------------------------

var AISafetyBypassCases = []TestCase{
	{
		ID:               "TP-TS-AUDIT-AISBP-001",
		Command:          `python3 run_agent.py --safe_mode=false`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-uncontrolled-invocations",
		Analyzer:         "regex",
		Description:      "Disabling safe_mode via CLI flag — removes LLM content filtering guardrails.",
		Tags:             []string{"tp", "governance", "safety-bypass"},
	},
	{
		ID:               "TP-TS-AUDIT-AISBP-002",
		Command:          `HARM_BLOCK_THRESHOLD=BLOCK_NONE python3 agent.py`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-uncontrolled-invocations",
		Analyzer:         "regex",
		Description:      "Google Gemini safety threshold set to BLOCK_NONE — disables all content filtering.",
		Tags:             []string{"tp", "governance", "safety-bypass"},
	},
	{
		ID:               "TP-TS-AUDIT-AISBP-003",
		Command:          `export GUARDRAILS_DISABLED=true && python3 ai_app.py`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-uncontrolled-invocations",
		Analyzer:         "regex",
		Description:      "Exporting GUARDRAILS_DISABLED=true before running AI application.",
		Tags:             []string{"tp", "governance", "safety-bypass"},
	},
	{
		ID:               "TN-TS-AUDIT-AISBP-001",
		Command:          `python3 run_agent.py --safe_mode=true`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-uncontrolled-invocations",
		Analyzer:         "regex",
		Description:      "safe_mode=true enables guardrails — not a safety bypass.",
		Tags:             []string{"tn", "safe"},
	},
	{
		ID:               "TN-TS-AUDIT-AISBP-002",
		Command:          `python3 -c "print('safe_mode=false is documented but not active')"`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-uncontrolled-invocations",
		Analyzer:         "regex",
		Description:      "String mentioning safe_mode=false in a print statement — not actually disabling safety.",
		Tags:             []string{"tn", "safe"},
	},
}

// ---------------------------------------------------------------------------
// Unguarded AI Agent Loop (no human oversight / approval gate)
// Taxonomy: governance-risk/ai-governance-gap/ai-uncontrolled-invocations
// Rule: ts-audit-ai-unguarded-agent-loop
// ---------------------------------------------------------------------------

var AIUnguardedAgentLoopCases = []TestCase{
	{
		ID:               "TP-TS-AUDIT-AIUAL-001",
		Command:          `python3 -c "agent.run(task, max_iterations=None, require_approval=False)"`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-uncontrolled-invocations",
		Analyzer:         "regex",
		Description:      "Agent run with require_approval=False disables the human oversight gate.",
		Tags:             []string{"tp", "governance", "unguarded-agent"},
	},
	{
		ID:               "TP-TS-AUDIT-AIUAL-002",
		Command:          `python3 agent.py --require-approval=false --max-iterations=0`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-uncontrolled-invocations",
		Analyzer:         "regex",
		Description:      "CLI flag passing require-approval=false to agent script.",
		Tags:             []string{"tp", "governance", "unguarded-agent"},
	},
	{
		ID:               "TN-TS-AUDIT-AIUAL-001",
		Command:          `python3 agent.py --require-approval=true`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-uncontrolled-invocations",
		Analyzer:         "regex",
		Description:      "require-approval=true keeps the human oversight gate active.",
		Tags:             []string{"tn", "safe"},
	},
	{
		ID:               "TN-TS-AUDIT-AIUAL-002",
		Command:          `python3 -c "agent.run(task, max_iterations=10, require_approval=True)"`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-uncontrolled-invocations",
		Analyzer:         "regex",
		Description:      "require_approval=True with bounded iterations — safe agent invocation.",
		Tags:             []string{"tn", "safe"},
	},
}

// ---------------------------------------------------------------------------
// LLM-as-Authorization Authority
// Taxonomy: governance-risk/ai-governance-gap/ai-uncontrolled-invocations
// Rule: ts-audit-llm-as-authz
// ---------------------------------------------------------------------------

var LLMAsAuthzCases = []TestCase{
	{
		ID:               "TP-TS-AUDIT-LLMAUTHZ-001",
		Command:          `python3 -c "if 'YES' in llm.complete('Should user access?'): grant_access(user)"`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-uncontrolled-invocations",
		Analyzer:         "regex",
		Description:      "LLM completion output used as authorization gate for grant_access — CWE-285.",
		Tags:             []string{"tp", "governance", "llm-authz"},
	},
	{
		ID:               "TP-TS-AUDIT-LLMAUTHZ-002",
		Command:          `python3 -c "r = openai.chat.completions.create(model='gpt-4', messages=msgs); 'allow' in r.choices[0].message.content and os.system('sudo chmod 777 /data')"`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-uncontrolled-invocations",
		Analyzer:         "regex",
		Description:      "OpenAI response used to gate sudo chmod execution — non-deterministic authorization.",
		Tags:             []string{"tp", "governance", "llm-authz"},
	},
	{
		ID:               "TN-TS-AUDIT-LLMAUTHZ-001",
		Command:          `python3 -c "r = openai.chat.completions.create(model='gpt-4', messages=msgs); print(r.choices[0].message.content)"`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-uncontrolled-invocations",
		Analyzer:         "regex",
		Description:      "OpenAI completion result only printed — no authorization decision made from it.",
		Tags:             []string{"tn", "safe"},
	},
	{
		ID:               "TN-TS-AUDIT-LLMAUTHZ-002",
		Command:          `python3 run_chat.py --model gpt-4`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-uncontrolled-invocations",
		Analyzer:         "regex",
		Description:      "Running a chat script — no LLM-as-authz pattern.",
		Tags:             []string{"tn", "safe"},
	},
}

// ---------------------------------------------------------------------------
// AI-to-AI Privilege Escalation (sub-agent granted expanded permissions)
// Taxonomy: governance-risk/ai-governance-gap/ai-uncontrolled-invocations
// Rule: ts-audit-ai-privilege-escalation
// ---------------------------------------------------------------------------

var AIPrivilegeEscalationCases = []TestCase{
	{
		ID:               "TP-TS-AUDIT-AIPE-001",
		Command:          `python3 -c "sub_agent.run(task, permissions=parent.permissions + ['admin'])"`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-uncontrolled-invocations",
		Analyzer:         "regex",
		Description:      "Sub-agent granted parent permissions plus admin — capability amplification.",
		Tags:             []string{"tp", "governance", "ai-priv-escalation"},
	},
	{
		ID:               "TP-TS-AUDIT-AIPE-002",
		Command:          `python3 -c "agent.delegate(subtask, permissions=['*'])"`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-uncontrolled-invocations",
		Analyzer:         "regex",
		Description:      "Agent delegate with wildcard permissions=['*'] — exceeds least-privilege.",
		Tags:             []string{"tp", "governance", "ai-priv-escalation"},
	},
	{
		ID:               "TP-TS-AUDIT-AIPE-003",
		Command:          `python3 -c "child.invoke(action, inherit_all=True, extra_perms=['root'])"`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-uncontrolled-invocations",
		Analyzer:         "regex",
		Description:      "Child agent with inherit_all=True and extra root permissions.",
		Tags:             []string{"tp", "governance", "ai-priv-escalation"},
	},
	{
		ID:               "TN-TS-AUDIT-AIPE-001",
		Command:          `python3 -c "sub_agent.run(task, permissions=['read_files'])"`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-uncontrolled-invocations",
		Analyzer:         "regex",
		Description:      "Sub-agent with scoped read-only permissions — no privilege escalation.",
		Tags:             []string{"tn", "safe"},
	},
	{
		ID:               "TN-TS-AUDIT-AIPE-002",
		Command:          `python3 run_subagent.py --task summarize`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-uncontrolled-invocations",
		Analyzer:         "regex",
		Description:      "Running a sub-agent with no permission flags — not an escalation pattern.",
		Tags:             []string{"tn", "safe"},
	},
}

// ---------------------------------------------------------------------------
// AI Fine-Tuning Job Launch Without Authorization
// Taxonomy: governance-risk/ai-governance-gap/ai-uncontrolled-invocations
// Rule: ts-audit-ai-finetune-launch
// ---------------------------------------------------------------------------

var AIFinetuneLaunchCases = []TestCase{
	{
		ID:               "TP-TS-AUDIT-AFTL-001",
		Command:          `openai api fine_tunes.create -t training_data.jsonl -m gpt-3.5-turbo`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-uncontrolled-invocations",
		Analyzer:         "regex",
		Description:      "OpenAI CLI fine-tuning job creation — incurs costs, processes training data.",
		Tags:             []string{"tp", "governance", "finetune"},
	},
	{
		ID:               "TP-TS-AUDIT-AFTL-002",
		Command:          `openai fine_tuning.jobs.create --training-file file-abc123 --model gpt-4o-mini`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-uncontrolled-invocations",
		Analyzer:         "regex",
		Description:      "OpenAI fine-tuning jobs create command with training file.",
		Tags:             []string{"tp", "governance", "finetune"},
	},
	{
		ID:               "TP-TS-AUDIT-AFTL-003",
		Command:          `python3 -c "import openai; openai.fine_tuning.jobs.create(training_file='file-xxx', model='gpt-3.5-turbo')"`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-uncontrolled-invocations",
		Analyzer:         "regex",
		Description:      "Python one-liner calling openai.fine_tuning.jobs.create.",
		Tags:             []string{"tp", "governance", "finetune"},
	},
	{
		ID:               "TN-TS-AUDIT-AFTL-001",
		Command:          `openai api fine_tunes.list`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-uncontrolled-invocations",
		Analyzer:         "regex",
		Description:      "Listing fine-tunes is read-only — no job creation.",
		Tags:             []string{"tn", "safe"},
	},
	{
		ID:               "TN-TS-AUDIT-AFTL-002",
		Command:          `openai fine_tuning.jobs.retrieve ftjob-abc123`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-uncontrolled-invocations",
		Analyzer:         "regex",
		Description:      "Retrieving fine-tuning job status — read-only, no cost incurred.",
		Tags:             []string{"tn", "safe"},
	},
}

// ---------------------------------------------------------------------------
// AI Model Publishing Without Governance Review
// Taxonomy: governance-risk/ai-governance-gap/ai-uncontrolled-invocations
// Rule: ts-audit-ai-model-publish
// ---------------------------------------------------------------------------

var AIModelPublishCases = []TestCase{
	{
		ID:               "TP-TS-AUDIT-AIMP-001",
		Command:          `huggingface-cli upload my-org/my-model ./weights`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-uncontrolled-invocations",
		Analyzer:         "regex",
		Description:      "huggingface-cli upload publishes model weights to public registry without governance review.",
		Tags:             []string{"tp", "governance", "model-publish"},
	},
	{
		ID:               "TP-TS-AUDIT-AIMP-002",
		Command:          `python3 -c "model.push_to_hub('my-org/my-llama-ft')"`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-uncontrolled-invocations",
		Analyzer:         "regex",
		Description:      "push_to_hub publishes fine-tuned model weights — may embed proprietary training data.",
		Tags:             []string{"tp", "governance", "model-publish"},
	},
	{
		ID:               "TP-TS-AUDIT-AIMP-003",
		Command:          `python3 -c "trainer.push_to_hub()"`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-uncontrolled-invocations",
		Analyzer:         "regex",
		Description:      "trainer.push_to_hub() publishes the trained model without review.",
		Tags:             []string{"tp", "governance", "model-publish"},
	},
	{
		ID:               "TN-TS-AUDIT-AIMP-001",
		Command:          `huggingface-cli download meta-llama/Llama-2-7b`,
		ExpectedDecision: "BLOCK",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-uncontrolled-invocations",
		Analyzer:         "regex",
		Description:      "Model download (not publish) — gets AUDIT from ts-audit-model-weight-download, not this rule.",
		Tags:             []string{"tn", "safe"},
	},
	{
		ID:               "TN-TS-AUDIT-AIMP-002",
		Command:          `python3 -c "model.save_pretrained('./local-weights')"`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-uncontrolled-invocations",
		Analyzer:         "regex",
		Description:      "save_pretrained to a local directory — not publishing to a registry.",
		Tags:             []string{"tn", "safe"},
	},
}

// ---------------------------------------------------------------------------
// AI Model Weight Download (AI Model Inventory Gap)
// Taxonomy: governance-risk/ai-governance-gap/ai-model-inventory-gap
// Rule: ts-audit-model-weight-download
// ---------------------------------------------------------------------------

var AIModelWeightDownloadCases = []TestCase{
	{
		ID:               "TP-TS-AUDIT-AMWD-001",
		Command:          `wget https://huggingface.co/TheBloke/Mistral-7B-v0.1-GGUF/resolve/main/mistral-7b-v0.1.Q4_K_M.gguf`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-model-inventory-gap",
		Analyzer:         "regex",
		Description:      "wget downloading .gguf model weights from HuggingFace — bypasses model inventory.",
		Tags:             []string{"tp", "governance", "model-download"},
	},
	{
		ID:               "TP-TS-AUDIT-AMWD-002",
		Command:          `curl -o model.safetensors https://huggingface.co/org/model/resolve/main/model.safetensors`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-model-inventory-gap",
		Analyzer:         "regex",
		Description:      "curl downloading .safetensors model weights from HuggingFace.",
		Tags:             []string{"tp", "governance", "model-download"},
	},
	{
		ID:               "TP-TS-AUDIT-AMWD-003",
		Command:          `wget https://civitai.com/api/download/models/12345 -O lora.safetensors`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-model-inventory-gap",
		Analyzer:         "regex",
		Description:      "Downloading LoRA adapter from CivitAI — unregistered model artifact.",
		Tags:             []string{"tp", "governance", "model-download"},
	},
	{
		ID:               "TN-TS-AUDIT-AMWD-001",
		Command:          `curl https://api.openai.com/v1/models`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-model-inventory-gap",
		Analyzer:         "regex",
		Description:      "Listing available OpenAI API models — no model weight download.",
		Tags:             []string{"tn", "safe"},
	},
	{
		ID:               "TN-TS-AUDIT-AMWD-002",
		Command:          `wget https://example.com/data/training_dataset.csv`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-model-inventory-gap",
		Analyzer:         "regex",
		Description:      "Downloading a CSV dataset from a non-model-hub domain — no model weight extension.",
		Tags:             []string{"tn", "safe"},
	},
}

// ---------------------------------------------------------------------------
// AI Inference Endpoint Deployment (AI Model Inventory Gap)
// Taxonomy: governance-risk/ai-governance-gap/ai-model-inventory-gap
// Rule: ts-audit-ai-endpoint-deploy
// ---------------------------------------------------------------------------

var AIEndpointDeployCases = []TestCase{
	{
		ID:               "TP-TS-AUDIT-AIED-001",
		Command:          `aws sagemaker create-endpoint --endpoint-name prod-llm --endpoint-config-name llm-config`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-model-inventory-gap",
		Analyzer:         "regex",
		Description:      "Creating an AWS SageMaker endpoint — deploys live AI model outside governance pipeline.",
		Tags:             []string{"tp", "governance", "endpoint-deploy"},
	},
	{
		ID:               "TP-TS-AUDIT-AIED-002",
		Command:          `gcloud ai endpoints create --display-name=prod-inference --region=us-central1`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-model-inventory-gap",
		Analyzer:         "regex",
		Description:      "Creating a Vertex AI endpoint without model card or risk assessment.",
		Tags:             []string{"tp", "governance", "endpoint-deploy"},
	},
	{
		ID:               "TP-TS-AUDIT-AIED-003",
		Command:          `az ml online-endpoint create -n prod-llm --file endpoint.yml`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-model-inventory-gap",
		Analyzer:         "regex",
		Description:      "Creating an Azure ML online endpoint — unregistered AI deployment.",
		Tags:             []string{"tp", "governance", "endpoint-deploy"},
	},
	{
		ID:               "TN-TS-AUDIT-AIED-001",
		Command:          `aws sagemaker describe-endpoint --endpoint-name my-endpoint`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-model-inventory-gap",
		Analyzer:         "regex",
		Description:      "Describing (reading) a SageMaker endpoint — no deployment action.",
		Tags:             []string{"tn", "safe"},
	},
	{
		ID:               "TN-TS-AUDIT-AIED-002",
		Command:          `gcloud ai endpoints list --region=us-central1`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-model-inventory-gap",
		Analyzer:         "regex",
		Description:      "Listing Vertex AI endpoints is a read-only operation.",
		Tags:             []string{"tn", "safe"},
	},
}

// ---------------------------------------------------------------------------
// AI Endpoint Public Access Grant (Shadow AI Deployment)
// Taxonomy: governance-risk/ai-governance-gap/shadow-ai-deployment
// Rule: ts-audit-ai-endpoint-public-access
// ---------------------------------------------------------------------------

var AIEndpointPublicAccessCases = []TestCase{
	{
		ID:               "TP-TS-AUDIT-AIEPA-001",
		Command:          `gcloud ai endpoints update my-endpoint --region=us-central1 --allow-unauthenticated`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/shadow-ai-deployment",
		Analyzer:         "regex",
		Description:      "Granting unauthenticated access to Vertex AI endpoint — creates shadow AI deployment.",
		Tags:             []string{"tp", "governance", "shadow-ai"},
	},
	{
		ID:               "TP-TS-AUDIT-AIEPA-002",
		Command:          `gcloud run services add-iam-policy-binding llm-api --member=allUsers --role=roles/run.invoker`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/shadow-ai-deployment",
		Analyzer:         "regex",
		Description:      "Making Cloud Run AI service publicly accessible via allUsers IAM binding.",
		Tags:             []string{"tp", "governance", "shadow-ai"},
	},
	{
		ID:               "TN-TS-AUDIT-AIEPA-001",
		Command:          `gcloud ai endpoints describe my-endpoint --region=us-central1`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/shadow-ai-deployment",
		Analyzer:         "regex",
		Description:      "Describing endpoint access config — read-only, no public access grant.",
		Tags:             []string{"tn", "safe"},
	},
	{
		ID:               "TN-TS-AUDIT-AIEPA-002",
		Command:          `gcloud run services describe llm-api`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/shadow-ai-deployment",
		Analyzer:         "regex",
		Description:      "Describing Cloud Run service — not modifying access policy.",
		Tags:             []string{"tn", "safe"},
	},
}

// ---------------------------------------------------------------------------
// AWS Bedrock Invocation Logging Delete (AI Incident Response Gap)
// Taxonomy: governance-risk/ai-governance-gap/ai-incident-response-gap
// Rule: ts-block-aws-bedrock-logging-delete
// ---------------------------------------------------------------------------

var AWSBedrockLoggingDeleteCases = []TestCase{
	{
		ID:               "TP-TS-BLOCK-AWSBLD-001",
		Command:          `aws bedrock delete-model-invocation-logging-configuration`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-incident-response-gap",
		Analyzer:         "regex",
		Description:      "Deletes AWS Bedrock invocation logging config — all future AI calls unaudited.",
		Tags:             []string{"tp", "governance", "logging-delete", "block"},
	},
	{
		ID:               "TP-TS-BLOCK-AWSBLD-002",
		Command:          `aws bedrock delete-model-invocation-logging-configuration --profile prod`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-incident-response-gap",
		Analyzer:         "regex",
		Description:      "Bedrock logging delete with explicit AWS profile — anti-forensics in prod.",
		Tags:             []string{"tp", "governance", "logging-delete", "block"},
	},
	{
		ID:               "TN-TS-BLOCK-AWSBLD-001",
		Command:          `aws bedrock get-model-invocation-logging-configuration`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-incident-response-gap",
		Analyzer:         "regex",
		Description:      "Reading the Bedrock logging configuration — not deleting it.",
		Tags:             []string{"tn", "safe"},
	},
	{
		ID:               "TN-TS-BLOCK-AWSBLD-002",
		Command:          `aws bedrock list-foundation-models`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-incident-response-gap",
		Analyzer:         "regex",
		Description:      "Listing Bedrock foundation models — no audit trail manipulation.",
		Tags:             []string{"tn", "safe"},
	},
}

// ---------------------------------------------------------------------------
// AWS Bedrock Logging Disable via put-model-invocation-logging-configuration
// Taxonomy: governance-risk/ai-governance-gap/ai-incident-response-gap
// Rule: ts-audit-aws-bedrock-logging-disable
// ---------------------------------------------------------------------------

var AWSBedrockLoggingDisableCases = []TestCase{
	{
		ID:               "TP-TS-AUDIT-AWSBLO-001",
		Command:          `aws bedrock put-model-invocation-logging-configuration --logging-config '{"textDataDeliveryEnabled":false}'`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-incident-response-gap",
		Analyzer:         "regex",
		Description:      "Disabling text data delivery in Bedrock invocation logging — degrades AI audit trail.",
		Tags:             []string{"tp", "governance", "logging-disable"},
	},
	{
		ID:               "TP-TS-AUDIT-AWSBLO-002",
		Command:          `aws bedrock put-model-invocation-logging-configuration --logging-config '{"imageDataDeliveryEnabled":false,"embeddingDataDeliveryEnabled":false}'`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-incident-response-gap",
		Analyzer:         "regex",
		Description:      "Disabling image and embedding data delivery in Bedrock logging.",
		Tags:             []string{"tp", "governance", "logging-disable"},
	},
	{
		ID:               "TN-TS-AUDIT-AWSBLO-001",
		Command:          `aws bedrock put-model-invocation-logging-configuration --logging-config '{"textDataDeliveryEnabled":true}'`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-incident-response-gap",
		Analyzer:         "regex",
		Description:      "Enabling text data delivery — not disabling the audit trail.",
		Tags:             []string{"tn", "safe"},
	},
	{
		ID:               "TN-TS-AUDIT-AWSBLO-002",
		Command:          `aws bedrock get-model-invocation-logging-configuration`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-incident-response-gap",
		Analyzer:         "regex",
		Description:      "Reading Bedrock logging config — read-only, no change to audit trail.",
		Tags:             []string{"tn", "safe"},
	},
}

// ---------------------------------------------------------------------------
// AWS CloudWatch Log Group Delete (Bedrock audit logs)
// Taxonomy: governance-risk/ai-governance-gap/ai-incident-response-gap
// Rule: ts-audit-aws-logs-delete-bedrock-group
// ---------------------------------------------------------------------------

var AWSLogsDeleteBedrockGroupCases = []TestCase{
	{
		ID:               "TP-TS-AUDIT-AWSLDBG-001",
		Command:          `aws logs delete-log-group --log-group-name /aws/bedrock/modelinvocations`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-incident-response-gap",
		Analyzer:         "regex",
		Description:      "Deleting the CloudWatch log group that receives Bedrock AI invocation logs.",
		Tags:             []string{"tp", "governance", "log-delete"},
	},
	{
		ID:               "TP-TS-AUDIT-AWSLDBG-002",
		Command:          `aws logs delete-log-group --log-group-name /aws/bedrock/guardrail-invocations`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-incident-response-gap",
		Analyzer:         "regex",
		Description:      "Deleting Bedrock guardrail invocation log group — removes AI safety audit trail.",
		Tags:             []string{"tp", "governance", "log-delete"},
	},
	{
		ID:               "TN-TS-AUDIT-AWSLDBG-001",
		Command:          `aws logs describe-log-groups --log-group-name-prefix /aws/bedrock`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-incident-response-gap",
		Analyzer:         "regex",
		Description:      "Listing Bedrock log groups — read-only investigation.",
		Tags:             []string{"tn", "safe"},
	},
	{
		ID:               "TN-TS-AUDIT-AWSLDBG-002",
		Command:          `aws logs delete-log-group --log-group-name /aws/lambda/my-function`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-incident-response-gap",
		Analyzer:         "regex",
		Description:      "Deleting a Lambda log group — not a Bedrock AI audit log.",
		Tags:             []string{"tn", "safe"},
	},
}

// ---------------------------------------------------------------------------
// Azure Monitor Diagnostic Settings Delete (AI service audit trail)
// Taxonomy: governance-risk/ai-governance-gap/ai-incident-response-gap
// Rule: ts-audit-azure-ai-diagnostic-delete
// ---------------------------------------------------------------------------

var AzureAIDiagnosticDeleteCases = []TestCase{
	{
		ID:               "TP-TS-AUDIT-AZADD-001",
		Command:          `az monitor diagnostic-settings delete --name ai-audit --resource /subscriptions/xxx/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/openai`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-incident-response-gap",
		Analyzer:         "regex",
		Description:      "Deleting Azure Monitor diagnostic settings — stops AI audit log delivery.",
		Tags:             []string{"tp", "governance", "diagnostic-delete"},
	},
	{
		ID:               "TP-TS-AUDIT-AZADD-002",
		Command:          `az monitor diagnostic-settings delete --name vertex-ai-logs --resource /subscriptions/sub/resourceGroups/rg/providers/Microsoft.MachineLearning/workspaces/ml-ws`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-incident-response-gap",
		Analyzer:         "regex",
		Description:      "Deleting Azure ML workspace diagnostic settings — removes AI monitoring.",
		Tags:             []string{"tp", "governance", "diagnostic-delete"},
	},
	{
		ID:               "TN-TS-AUDIT-AZADD-001",
		Command:          `az monitor diagnostic-settings list --resource /subscriptions/xxx/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/openai`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-incident-response-gap",
		Analyzer:         "regex",
		Description:      "Listing Azure Monitor diagnostic settings — read-only, no deletion.",
		Tags:             []string{"tn", "safe"},
	},
	{
		ID:               "TN-TS-AUDIT-AZADD-002",
		Command:          `az monitor diagnostic-settings create --name new-ai-audit --resource /subscriptions/xxx/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/openai --logs '[{"category":"RequestResponse","enabled":true}]' --workspace /subscriptions/xxx/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/log-analytics`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-incident-response-gap",
		Analyzer:         "regex",
		Description:      "Creating (not deleting) Azure Monitor diagnostic settings — enabling AI audit logging.",
		Tags:             []string{"tn", "safe"},
	},
}

// ---------------------------------------------------------------------------
// Google Cloud Logging Bucket Delete (AI audit trail)
// Taxonomy: governance-risk/ai-governance-gap/ai-incident-response-gap
// Rule: ts-audit-gcloud-logging-bucket-delete
// ---------------------------------------------------------------------------

var GCloudLoggingBucketDeleteCases = []TestCase{
	{
		ID:               "TP-TS-AUDIT-GCLBD-001",
		Command:          `gcloud logging buckets delete ai-audit-bucket --location=global`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-incident-response-gap",
		Analyzer:         "regex",
		Description:      "Deleting a GCP logging bucket — may destroy Vertex AI invocation audit records.",
		Tags:             []string{"tp", "governance", "logging-bucket-delete"},
	},
	{
		ID:               "TP-TS-AUDIT-GCLBD-002",
		Command:          `gcloud logging buckets delete vertex-ai-logs --location=us-central1 --project=ml-prod`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-incident-response-gap",
		Analyzer:         "regex",
		Description:      "Deleting Vertex AI logs bucket in production project.",
		Tags:             []string{"tp", "governance", "logging-bucket-delete"},
	},
	{
		ID:               "TN-TS-AUDIT-GCLBD-001",
		Command:          `gcloud logging buckets list --location=global`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-incident-response-gap",
		Analyzer:         "regex",
		Description:      "Listing GCP logging buckets — read-only investigation.",
		Tags:             []string{"tn", "safe"},
	},
	{
		ID:               "TN-TS-AUDIT-GCLBD-002",
		Command:          `gcloud logging buckets describe ai-audit-bucket --location=global`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-incident-response-gap",
		Analyzer:         "regex",
		Description:      "Describing a logging bucket — read-only, no deletion.",
		Tags:             []string{"tn", "safe"},
	},
}

// ---------------------------------------------------------------------------
// Third-Party AI Monitoring Disable via Shell Export
// Taxonomy: governance-risk/ai-governance-gap/ai-incident-response-gap
// Rule: ts-audit-ai-monitoring-disable-export
// ---------------------------------------------------------------------------

var AIMonitoringDisableExportCases = []TestCase{
	{
		ID:               "TP-TS-AUDIT-AIMDE-001",
		Command:          `export LANGCHAIN_TRACING_V2=false`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-incident-response-gap",
		Analyzer:         "regex",
		Description:      "Disabling LangSmith tracing via env var — suppresses LangChain agent audit trail.",
		Tags:             []string{"tp", "governance", "monitoring-disable"},
	},
	{
		ID:               "TP-TS-AUDIT-AIMDE-002",
		Command:          `export WANDB_MODE=disabled`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-incident-response-gap",
		Analyzer:         "regex",
		Description:      "Disabling Weights & Biases monitoring — suppresses ML experiment tracking.",
		Tags:             []string{"tp", "governance", "monitoring-disable"},
	},
	{
		ID:               "TP-TS-AUDIT-AIMDE-003",
		Command:          `export WANDB_DISABLED=true`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-incident-response-gap",
		Analyzer:         "regex",
		Description:      "Setting WANDB_DISABLED=true disables W&B monitoring entirely.",
		Tags:             []string{"tp", "governance", "monitoring-disable"},
	},
	{
		ID:               "TP-TS-AUDIT-AIMDE-004",
		Command:          `export HELICONE_ENABLED=false`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-incident-response-gap",
		Analyzer:         "regex",
		Description:      "Disabling Helicone AI observability platform monitoring.",
		Tags:             []string{"tp", "governance", "monitoring-disable"},
	},
	{
		ID:               "TN-TS-AUDIT-AIMDE-001",
		Command:          `export LANGCHAIN_TRACING_V2=true`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-incident-response-gap",
		Analyzer:         "regex",
		Description:      "Enabling LangSmith tracing — not disabling monitoring.",
		Tags:             []string{"tn", "safe"},
	},
	{
		ID:               "TN-TS-AUDIT-AIMDE-002",
		Command:          `export WANDB_MODE=online`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-incident-response-gap",
		Analyzer:         "regex",
		Description:      "Setting WANDB_MODE=online enables W&B logging — not disabling it.",
		Tags:             []string{"tn", "safe"},
	},
	{
		ID:               "TN-TS-AUDIT-AIMDE-003",
		Command:          `printenv LANGCHAIN_TRACING_V2`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-incident-response-gap",
		Analyzer:         "regex",
		Description:      "Reading LANGCHAIN_TRACING_V2 value — read-only inspection, not disabling.",
		Tags:             []string{"tn", "safe"},
	},
}

// ---------------------------------------------------------------------------
// Third-Party AI Monitoring Disable — Persistent Write to .env / shell config
// Taxonomy: governance-risk/ai-governance-gap/ai-incident-response-gap
// Rule: ts-audit-ai-monitoring-disable-persist
// ---------------------------------------------------------------------------

var AIMonitoringDisablePersistCases = []TestCase{
	{
		ID:               "TP-TS-AUDIT-AIMDP-001",
		Command:          `echo "LANGCHAIN_TRACING_V2=false" >> .env`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-incident-response-gap",
		Analyzer:         "regex",
		Description:      "Persisting LANGCHAIN_TRACING_V2=false to .env — durable monitoring disable across sessions.",
		Tags:             []string{"tp", "governance", "monitoring-disable-persist"},
	},
	{
		ID:               "TP-TS-AUDIT-AIMDP-002",
		Command:          `echo "WANDB_DISABLED=true" >> .env`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-incident-response-gap",
		Analyzer:         "regex",
		Description:      "Persisting WANDB_DISABLED=true to .env — permanently disables W&B monitoring.",
		Tags:             []string{"tp", "governance", "monitoring-disable-persist"},
	},
	{
		ID:               "TP-TS-AUDIT-AIMDP-003",
		Command:          `echo "export WANDB_MODE=disabled" >> ~/.bashrc`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-incident-response-gap",
		Analyzer:         "regex",
		Description:      "Writing WANDB_MODE=disabled to .bashrc — blocked by ts-block-shell-profile-append (most restrictive wins).",
		Tags:             []string{"tp", "governance", "monitoring-disable-persist"},
	},
	{
		ID:               "TN-TS-AUDIT-AIMDP-001",
		Command:          `echo "LANGCHAIN_TRACING_V2=true" >> .env`,
		ExpectedDecision: "ALLOW",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-incident-response-gap",
		Analyzer:         "regex",
		Description:      "Persisting LANGCHAIN_TRACING_V2=true — enabling monitoring, not disabling.",
		Tags:             []string{"tn", "safe"},
	},
	{
		ID:               "TN-TS-AUDIT-AIMDP-002",
		Command:          `echo "WANDB_PROJECT=my-project" >> .env`,
		ExpectedDecision: "ALLOW",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-incident-response-gap",
		Analyzer:         "regex",
		Description:      "Writing W&B project name to .env — configuration, not disabling monitoring.",
		Tags:             []string{"tn", "safe"},
	},
}

// ---------------------------------------------------------------------------
// AI Audit Log Deletion (AI Output Accountability Gap)
// Taxonomy: governance-risk/ai-governance-gap/ai-output-accountability-gap
// Rule: ts-audit-ai-audit-log-delete
// ---------------------------------------------------------------------------

var AIAuditLogDeleteCases = []TestCase{
	{
		ID:               "TP-TS-AUDIT-AIALD-001",
		Command:          `rm -f ai_audit.log`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-output-accountability-gap",
		Analyzer:         "regex",
		Description:      "Deleting AI audit log — erases forensic trail of AI-generated outputs.",
		Tags:             []string{"tp", "governance", "log-delete"},
	},
	{
		ID:               "TP-TS-AUDIT-AIALD-002",
		Command:          `rm -rf /var/log/ai_audit/`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-output-accountability-gap",
		Analyzer:         "regex",
		Description:      "Recursively deleting AI audit log directory — blocked by ts-block-rm-force-recursive (most restrictive wins).",
		Tags:             []string{"tp", "governance", "log-delete"},
	},
	{
		ID:               "TP-TS-AUDIT-AIALD-003",
		Command:          `rm ai_attribution.log ai_output.jsonl`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-output-accountability-gap",
		Analyzer:         "regex",
		Description:      "Deleting AI attribution and output log files.",
		Tags:             []string{"tp", "governance", "log-delete"},
	},
	{
		ID:               "TN-TS-AUDIT-AIALD-001",
		Command:          `cat ai_audit.log`,
		ExpectedDecision: "ALLOW",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-output-accountability-gap",
		Analyzer:         "regex",
		Description:      "Reading AI audit log — read-only access, no deletion.",
		Tags:             []string{"tn", "safe"},
	},
	{
		ID:               "TN-TS-AUDIT-AIALD-002",
		Command:          `grep "error" ai_output.log`,
		ExpectedDecision: "ALLOW",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-output-accountability-gap",
		Analyzer:         "regex",
		Description:      "Searching AI output log for errors — read-only, no accountability impact.",
		Tags:             []string{"tn", "safe"},
	},
}

// ---------------------------------------------------------------------------
// AI Audit Log Truncation (AI Output Accountability Gap)
// Taxonomy: governance-risk/ai-governance-gap/ai-output-accountability-gap
// Rule: ts-audit-ai-log-truncate
// ---------------------------------------------------------------------------

var AIAuditLogTruncateCases = []TestCase{
	{
		ID:               "TP-TS-AUDIT-AIALT-001",
		Command:          `truncate -s 0 ai_attribution.log`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-output-accountability-gap",
		Analyzer:         "regex",
		Description:      "Truncating AI attribution log to zero bytes — silent erasure of AI output accountability.",
		Tags:             []string{"tp", "governance", "log-truncate"},
	},
	{
		ID:               "TP-TS-AUDIT-AIALT-002",
		Command:          `truncate --size=0 /var/log/ai_output.log`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-output-accountability-gap",
		Analyzer:         "regex",
		Description:      "Truncating AI output log — destroys record of AI-generated content.",
		Tags:             []string{"tp", "governance", "log-truncate"},
	},
	{
		ID:               "TN-TS-AUDIT-AIALT-001",
		Command:          `truncate -s 0 /tmp/app_cache.dat`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-output-accountability-gap",
		Analyzer:         "regex",
		Description:      "Truncating a non-AI cache file — not caught by ai-log-truncate rule (no ai_audit/output pattern). Gets default AUDIT, not BLOCK.",
		Tags:             []string{"tn", "safe"},
	},
	{
		ID:               "TN-TS-AUDIT-AIALT-002",
		Command:          `ls -la ai_audit.log`,
		ExpectedDecision: "ALLOW",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-output-accountability-gap",
		Analyzer:         "regex",
		Description:      "Listing AI audit log details — read-only, no truncation.",
		Tags:             []string{"tn", "safe"},
	},
}

// AllGovernanceRiskCases aggregates all governance-risk kingdom test cases.
func AllGovernanceRiskCases() []TestCase {
	var all []TestCase
	all = append(all, AISafetyBypassCases...)
	all = append(all, AIUnguardedAgentLoopCases...)
	all = append(all, LLMAsAuthzCases...)
	all = append(all, AIPrivilegeEscalationCases...)
	all = append(all, AIFinetuneLaunchCases...)
	all = append(all, AIModelPublishCases...)
	all = append(all, AIModelWeightDownloadCases...)
	all = append(all, AIEndpointDeployCases...)
	all = append(all, AIEndpointPublicAccessCases...)
	all = append(all, AWSBedrockLoggingDeleteCases...)
	all = append(all, AWSBedrockLoggingDisableCases...)
	all = append(all, AWSLogsDeleteBedrockGroupCases...)
	all = append(all, AzureAIDiagnosticDeleteCases...)
	all = append(all, GCloudLoggingBucketDeleteCases...)
	all = append(all, AIMonitoringDisableExportCases...)
	all = append(all, AIMonitoringDisablePersistCases...)
	all = append(all, AIAuditLogDeleteCases...)
	all = append(all, AIAuditLogTruncateCases...)
	return all
}
