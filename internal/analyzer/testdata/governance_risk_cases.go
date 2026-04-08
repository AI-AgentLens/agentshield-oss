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
		Classification:   "TP",
		TaxonomyRef:      "supply-chain/model-poisoning/checkpoint-substitution",
		Analyzer:         "regex",
		Description:      "huggingface-cli download — blocked by sc-block-hf-cli-download (pickle-exploit risk in untrusted model repos).",
		Tags:             []string{"tp", "supply-chain", "model-download"},
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

// ---------------------------------------------------------------------------
// Kubernetes/Helm AI Workload Deployment (Shadow AI Deployment)
// Taxonomy: governance-risk/ai-governance-gap/shadow-ai-deployment
// Rules: ts-audit-k8s-llm-helm-install, ts-audit-k8s-llm-workload-create
// Issue: #612
// ---------------------------------------------------------------------------

var K8sLLMHelmInstallCases = []TestCase{
	{
		ID:               "TP-TS-AUDIT-K8SHELM-001",
		Command:          "helm install ollama ollama-helm/ollama --namespace ai-apps",
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/shadow-ai-deployment",
		Analyzer:         "regex",
		Description:      "helm installing Ollama LLM inference chart — creates unregistered AI workload in cluster without governance review.",
		Tags:             []string{"tp", "helm", "k8s", "shadow-ai", "governance"},
	},
	{
		ID:               "TP-TS-AUDIT-K8SHELM-002",
		Command:          "helm upgrade --install vllm-svc vllm/vllm-inference-server --set gpu.enabled=true",
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/shadow-ai-deployment",
		Analyzer:         "regex",
		Description:      "helm upgrading vLLM inference server chart with GPU — deploys AI inference outside governance process.",
		Tags:             []string{"tp", "helm", "k8s", "vllm", "shadow-ai"},
	},
	{
		ID:               "TP-TS-AUDIT-K8SHELM-003",
		Command:          "helm install kubeai kubeai/kubeai --namespace kubeai-system",
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/shadow-ai-deployment",
		Analyzer:         "regex",
		Description:      "helm installing KubeAI — dedicated Kubernetes AI inference platform deployed without governance approval.",
		Tags:             []string{"tp", "helm", "k8s", "kubeai", "shadow-ai"},
	},
	{
		ID:               "TN-TS-AUDIT-K8SHELM-001",
		Command:          "helm list --all-namespaces",
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/shadow-ai-deployment",
		Analyzer:         "regex",
		Description:      "helm listing installed charts — read-only operation, no deployment. Default AUDIT is correct.",
		Tags:             []string{"tn", "safe"},
	},
	{
		ID:               "TN-TS-AUDIT-K8SHELM-002",
		Command:          "helm search repo ollama",
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/shadow-ai-deployment",
		Analyzer:         "regex",
		Description:      "helm searching chart repositories — read-only, no workload deployed. Default AUDIT is correct.",
		Tags:             []string{"tn", "safe"},
	},
	{
		ID:               "TN-TS-AUDIT-K8SHELM-003",
		Command:          "helm install nginx bitnami/nginx --namespace web",
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/shadow-ai-deployment",
		Analyzer:         "regex",
		Description:      "helm installing a non-AI chart (nginx) — no LLM inference workload. Default AUDIT is correct.",
		Tags:             []string{"tn", "safe"},
	},
}

var K8sLLMWorkloadCreateCases = []TestCase{
	{
		ID:               "TP-TS-AUDIT-K8SWKLD-001",
		Command:          "kubectl create deployment llm-svc --image=ollama/ollama:latest",
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/shadow-ai-deployment",
		Analyzer:         "regex",
		Description:      "kubectl creating deployment with Ollama image — direct LLM workload deployment without helm governance layer.",
		Tags:             []string{"tp", "kubectl", "k8s", "shadow-ai", "governance"},
	},
	{
		ID:               "TP-TS-AUDIT-K8SWKLD-002",
		Command:          "kubectl run vllm-pod --image=vllm/vllm-openai:latest --restart=Never -- --model meta-llama/Llama-3-8B",
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/shadow-ai-deployment",
		Analyzer:         "regex",
		Description:      "kubectl run with vLLM OpenAI-compatible image — creates ad-hoc LLM inference pod without governance.",
		Tags:             []string{"tp", "kubectl", "k8s", "vllm", "shadow-ai"},
	},
	{
		ID:               "TP-TS-AUDIT-K8SWKLD-003",
		Command:          "kubectl create deployment tgi --image=ghcr.io/huggingface/text-generation-inference:latest",
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/shadow-ai-deployment",
		Analyzer:         "regex",
		Description:      "kubectl creating HuggingFace TGI deployment — deploys LLM inference service without model card or governance review.",
		Tags:             []string{"tp", "kubectl", "k8s", "tgi", "shadow-ai"},
	},
	{
		ID:               "TN-TS-AUDIT-K8SWKLD-001",
		Command:          "kubectl get deployments -n ai-apps",
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/shadow-ai-deployment",
		Analyzer:         "regex",
		Description:      "kubectl listing deployments — read-only, no workload created. Default AUDIT is correct.",
		Tags:             []string{"tn", "safe"},
	},
	{
		ID:               "TN-TS-AUDIT-K8SWKLD-002",
		Command:          "kubectl create deployment api-server --image=python:3.11-slim",
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/shadow-ai-deployment",
		Analyzer:         "regex",
		Description:      "kubectl creating non-AI deployment (python slim) — not an LLM inference workload. Default AUDIT is correct.",
		Tags:             []string{"tn", "safe"},
	},
}

// ===========================================================================
// Shadow AI: Local AI Inference Server Public Exposure via Tunneling
// ===========================================================================
//
// Rules: ts-audit-ngrok-ai-inference-port, ts-audit-tunnel-ai-inference-port
// Taxonomy: governance-risk/ai-governance-gap/shadow-ai-deployment

// NgrокAIInferencePortCases tests ts-audit-ngrok-ai-inference-port.
var NgrokAIInferencePortCases = []TestCase{
	{
		ID:               "TP-TS-AUDIT-NGROK-AI-PORT-001",
		Command:          `ngrok http 11434`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/shadow-ai-deployment",
		Analyzer:         "regex",
		Description:      "ngrok http tunneling Ollama default port (11434) — creates a public, unauthenticated AI inference endpoint outside governance review.",
		Tags:             []string{"tp", "governance", "shadow-ai", "tunnel"},
	},
	{
		ID:               "TP-TS-AUDIT-NGROK-AI-PORT-002",
		Command:          `ngrok http 1234`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/shadow-ai-deployment",
		Analyzer:         "regex",
		Description:      "ngrok http tunneling LM Studio default port (1234) — exposes local LLM inference server to internet without organizational governance.",
		Tags:             []string{"tp", "governance", "shadow-ai", "tunnel"},
	},
	{
		ID:               "TP-TS-AUDIT-NGROK-AI-PORT-003",
		Command:          `ngrok http 7860`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/shadow-ai-deployment",
		Analyzer:         "regex",
		Description:      "ngrok http tunneling text-generation-webui / Gradio port (7860) — public exposure of AI inference UI without governance review.",
		Tags:             []string{"tp", "governance", "shadow-ai", "tunnel"},
	},
	{
		ID:               "TN-TS-AUDIT-NGROK-AI-PORT-001",
		Command:          `ngrok http 3000`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/shadow-ai-deployment",
		Analyzer:         "regex",
		Description:      "ngrok http on port 3000 (generic web app, not a known AI inference port) — governance-risk AI tunnel rule must NOT trigger. Gets AUDIT from ne-audit-ngrok-http only.",
		Tags:             []string{"tn", "safe"},
	},
	{
		ID:               "TN-TS-AUDIT-NGROK-AI-PORT-002",
		Command:          `ngrok version`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/shadow-ai-deployment",
		Analyzer:         "regex",
		Description:      "ngrok version check — read-only command, no tunnel created. Gets default AUDIT decision (not ALLOW) since default policy is AUDIT. AI inference port rule must not trigger.",
		Tags:             []string{"tn", "safe"},
	},
}

// TunnelAIInferencePortCases tests ts-audit-tunnel-ai-inference-port.
var TunnelAIInferencePortCases = []TestCase{
	{
		ID:               "TP-TS-AUDIT-TUNNEL-AI-PORT-001",
		Command:          `bore local 11434 --to bore.pub`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/shadow-ai-deployment",
		Analyzer:         "regex",
		Description:      "bore tunneling Ollama port (11434) — already BLOCKed by ne-block-bore-local; governance-risk rule adds compliance context.",
		Tags:             []string{"tp", "governance", "shadow-ai", "tunnel"},
	},
	{
		ID:               "TP-TS-AUDIT-TUNNEL-AI-PORT-002",
		Command:          `bore local 1234 --to bore.pub`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/shadow-ai-deployment",
		Analyzer:         "regex",
		Description:      "bore tunneling LM Studio port (1234) — BLOCKed by ne-block-bore-local; confirms AI inference port is also flagged by governance rule.",
		Tags:             []string{"tp", "governance", "shadow-ai", "tunnel"},
	},
	{
		ID:               "TN-TS-AUDIT-TUNNEL-AI-PORT-001",
		Command:          `bore local 3000 --to bore.pub`,
		ExpectedDecision: "BLOCK",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/shadow-ai-deployment",
		Analyzer:         "regex",
		Description:      "bore tunneling non-AI port (3000) — BLOCKed by ne-block-bore-local (C2 rule), but ts-audit-tunnel-ai-inference-port must NOT add a second hit. Most restrictive wins (BLOCK either way).",
		Tags:             []string{"tn", "safe"},
	},
	{
		ID:               "TN-TS-AUDIT-TUNNEL-AI-PORT-002",
		Command:          `cloudflared tunnel list`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/shadow-ai-deployment",
		Analyzer:         "regex",
		Description:      "cloudflared tunnel list is read-only — no AI inference port exposed, must not trigger tunnel-ai-inference-port rule.",
		Tags:             []string{"tn", "safe"},
	},
}

// ---------------------------------------------------------------------------
// AI Model Attestation Gap — Unpinned Model Alias
// Taxonomy: governance-risk/ai-governance-gap/ai-model-attestation-gap
// Rule: ts-audit-unpinned-model-alias (issue #439)
// ---------------------------------------------------------------------------

var AIUnpinnedModelAliasCases = []TestCase{
	// --- TRUE POSITIVES ---
	{
		ID:               "TP-TS-AUDIT-UNPINNED-MODEL-001",
		Command:          `curl -d '{"model":"gpt-4"}' https://api.openai.com/v1/chat/completions`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-model-attestation-gap",
		Analyzer:         "regex",
		Description:      "curl API call with unpinned gpt-4 alias in JSON body — silent model substitution risk (EU AI Act Art.13, OWASP LLM05).",
		Tags:             []string{"tp", "governance", "model-attestation"},
	},
	{
		ID:               "TP-TS-AUDIT-UNPINNED-MODEL-002",
		Command:          `export OPENAI_MODEL=latest`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-model-attestation-gap",
		Analyzer:         "regex",
		Description:      "OPENAI_MODEL env var set to 'latest' alias — no model version pinning, any provider update silently changes behavior.",
		Tags:             []string{"tp", "governance", "model-attestation"},
	},
	{
		ID:               "TP-TS-AUDIT-UNPINNED-MODEL-003",
		Command:          `claude --model claude-3-sonnet`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-model-attestation-gap",
		Analyzer:         "regex",
		Description:      "claude CLI with unversioned claude-3-sonnet alias — no date suffix means model version can silently change.",
		Tags:             []string{"tp", "governance", "model-attestation"},
	},
	{
		ID:               "TP-TS-AUDIT-UNPINNED-MODEL-004",
		Command:          `ANTHROPIC_MODEL=claude-3-opus python3 run_agent.py`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-model-attestation-gap",
		Analyzer:         "regex",
		Description:      "ANTHROPIC_MODEL env var using unversioned claude-3-opus alias — must be pinned to a dated version for compliance.",
		Tags:             []string{"tp", "governance", "model-attestation"},
	},

	// --- TRUE NEGATIVES ---
	// Note: all TNs get AUDIT from the default policy or other rules (curl monitoring,
	// default AUDIT decision). The key assertion is that ts-audit-unpinned-model-alias
	// itself must NOT fire on these commands.
	{
		ID:               "TN-TS-AUDIT-UNPINNED-MODEL-001",
		Command:          `curl -d '{"model":"gpt-4-0125-preview"}' https://api.openai.com/v1/chat/completions`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-model-attestation-gap",
		Analyzer:         "regex",
		Description:      "curl with fully-versioned gpt-4-0125-preview model — date suffix present, ts-audit-unpinned-model-alias must not fire. Gets AUDIT from curl monitoring rules (ne-audit-curl, ne-audit-ai-vendor-api-call).",
		Tags:             []string{"tn", "safe", "governance"},
	},
	{
		ID:               "TN-TS-AUDIT-UNPINNED-MODEL-002",
		Command:          `export OPENAI_MODEL=gpt-4-0125-preview`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-model-attestation-gap",
		Analyzer:         "regex",
		Description:      "OPENAI_MODEL set to versioned gpt-4-0125-preview — explicit date pin, ts-audit-unpinned-model-alias must not fire. Gets default AUDIT.",
		Tags:             []string{"tn", "safe", "governance"},
	},
	{
		ID:               "TN-TS-AUDIT-UNPINNED-MODEL-003",
		Command:          `claude --model claude-3-5-sonnet-20241022`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-model-attestation-gap",
		Analyzer:         "regex",
		Description:      "claude CLI with fully-versioned claude-3-5-sonnet-20241022 — date suffix present, ts-audit-unpinned-model-alias must not fire. Gets default AUDIT.",
		Tags:             []string{"tn", "safe", "governance"},
	},
	{
		ID:               "TN-TS-AUDIT-UNPINNED-MODEL-004",
		Command:          `git commit -m 'switch to gpt-4 for inference docs'`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-model-attestation-gap",
		Analyzer:         "regex",
		Description:      "git commit message mentioning gpt-4 — no --model flag or env var, ts-audit-unpinned-model-alias must not fire. Gets default AUDIT.",
		Tags:             []string{"tn", "safe", "governance"},
	},
}

// AllGovernanceRiskCases aggregates all governance-risk kingdom test cases.
// AIProvenanceStrippingCases tests gov-audit-strip-ai-coauthor and
// gov-audit-strip-ai-coauthor-reverse (issue #187).
var AIProvenanceStrippingCases = []TestCase{
	{
		ID:               "TP-GOV-PROV-STRIP-001",
		Command:          "sed -i '/Co-Authored-By.*Claude/d' .git/COMMIT_EDITMSG",
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-output-provenance-manipulation",
		Analyzer:         "regex",
		Description:      "sed deleting Co-Authored-By Claude line — AI provenance stripping, must AUDIT (issue #187)",
		Tags:             []string{"tp", "governance", "provenance", "ai-attribution"},
	},
	{
		ID:               "TP-GOV-PROV-STRIP-002",
		Command:          `sed -i 's/Co-Authored-By.*Copilot.*//g' CHANGELOG.md`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-output-provenance-manipulation",
		Analyzer:         "regex",
		Description:      "sed stripping Co-Authored-By Copilot from changelog — AI attribution removal, must AUDIT (issue #187)",
		Tags:             []string{"tp", "governance", "provenance", "ai-attribution"},
	},
	{
		ID:               "TP-GOV-PROV-STRIP-003",
		Command:          "sed -i '/AI-generated/d' README.md",
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-output-provenance-manipulation",
		Analyzer:         "regex",
		Description:      "sed deleting AI-generated marker lines — provenance marker removal, must AUDIT (issue #187)",
		Tags:             []string{"tp", "governance", "provenance", "ai-attribution"},
	},
	{
		ID:               "TN-GOV-PROV-STRIP-001",
		Command:          "git commit -m 'fix: typo' --trailer 'Co-Authored-By: Claude <noreply@anthropic.com>'",
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-output-provenance-manipulation",
		Analyzer:         "regex",
		Description:      "git commit adding Co-Authored-By (not removing) — gov-audit-strip-ai-coauthor must NOT fire; default AUDIT applies (issue #187)",
		Tags:             []string{"tn", "safe", "git", "provenance"},
	},
	{
		ID:               "TN-GOV-PROV-STRIP-002",
		Command:          "git log --format='%an'",
		ExpectedDecision: "ALLOW",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-output-provenance-manipulation",
		Analyzer:         "regex",
		Description:      "git log reading history — read-only, must ALLOW (issue #187)",
		Tags:             []string{"tn", "safe", "git"},
	},
}

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
	all = append(all, K8sLLMHelmInstallCases...)
	all = append(all, K8sLLMWorkloadCreateCases...)
	all = append(all, NgrokAIInferencePortCases...)
	all = append(all, TunnelAIInferencePortCases...)
	all = append(all, AIProvenanceStrippingCases...)
	all = append(all, LLMDirectedIaCApplyCases...)
	all = append(all, ComplianceReportAutoSubmitCases...)
	all = append(all, AIComplianceArtifactFabricationCases...)
	all = append(all, AIUnpinnedModelAliasCases...)
	return all
}

// LLMDirectedIaCApplyCases tests ts-audit-pulumi-up and ts-audit-aws-cfn-deploy
// (issue #204 — orphaned taxonomy: llm-directed-iac-apply)
var LLMDirectedIaCApplyCases = []TestCase{
	{
		ID:               "TP-TS-AUDIT-IAC-PULUMI-001",
		Command:          "pulumi up",
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "unauthorized-execution/ai-content-integrity/llm-directed-iac-apply",
		Analyzer:         "structural",
		Description:      "pulumi up applies all pending stack changes — ts-audit-pulumi-up should fire.",
		Tags:             []string{"tp", "iac", "pulumi"},
	},
	{
		ID:               "TP-TS-AUDIT-IAC-PULUMI-002",
		Command:          "pulumi up --stack prod",
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "unauthorized-execution/ai-content-integrity/llm-directed-iac-apply",
		Analyzer:         "structural",
		Description:      "pulumi up targeting prod stack — ts-audit-pulumi-up must fire regardless of stack name.",
		Tags:             []string{"tp", "iac", "pulumi"},
	},
	{
		ID:               "TN-TS-AUDIT-IAC-PULUMI-001",
		Command:          "pulumi preview",
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "unauthorized-execution/ai-content-integrity/llm-directed-iac-apply",
		Analyzer:         "structural",
		Description:      "pulumi preview is read-only — must not trigger ts-audit-pulumi-up (subcommand is 'preview' not 'up').",
		Tags:             []string{"tn", "safe", "iac", "pulumi"},
	},
	{
		ID:               "TN-TS-AUDIT-IAC-PULUMI-FP-001",
		Command:          "gh issue create --body \"pulumi up failed with 'resource already exists' error\"",
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "unauthorized-execution/ai-content-integrity/llm-directed-iac-apply",
		Analyzer:         "structural",
		Description:      "FP regression: gh issue create with 'pulumi up' in body — structural rule must NOT fire because executable is 'gh'. (ts-audit-pulumi-up)",
		Tags:             []string{"tn", "fp-regression", "iac", "pulumi"},
	},
	{
		ID:               "TP-TS-AUDIT-IAC-CFN-001",
		Command:          "aws cloudformation deploy --template-file template.yaml --stack-name my-stack",
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "unauthorized-execution/ai-content-integrity/llm-directed-iac-apply",
		Analyzer:         "regex",
		Description:      "aws cloudformation deploy without --no-execute-changeset — ts-audit-aws-cfn-deploy must fire.",
		Tags:             []string{"tp", "iac", "cloudformation"},
	},
	{
		ID:               "TP-TS-AUDIT-IAC-CFN-002",
		Command:          "sam deploy",
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "unauthorized-execution/ai-content-integrity/llm-directed-iac-apply",
		Analyzer:         "regex",
		Description:      "sam deploy applies SAM/CloudFormation stack changes — ts-audit-aws-cfn-deploy must fire.",
		Tags:             []string{"tp", "iac", "sam", "cloudformation"},
	},
	{
		ID:               "TN-TS-AUDIT-IAC-CFN-001",
		Command:          "aws cloudformation deploy --template-file t.yaml --stack-name s --no-execute-changeset",
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "unauthorized-execution/ai-content-integrity/llm-directed-iac-apply",
		Analyzer:         "regex",
		Description:      "aws cloudformation deploy with --no-execute-changeset only creates the changeset for review — ts-audit-aws-cfn-deploy excluded, gets general aws-cli AUDIT.",
		Tags:             []string{"tn", "safe", "iac", "cloudformation"},
	},
}

// ComplianceReportAutoSubmitCases tests ts-audit-compliance-report-auto-submit
// (issue #204 — orphaned taxonomy: ai-generated-compliance-report-injection)
var ComplianceReportAutoSubmitCases = []TestCase{
	{
		ID:               "TP-TS-AUDIT-COMPLIANCE-SUBMIT-001",
		Command:          "aws audit-manager create-assessment --name \"SOC2 Assessment\" --framework-id xyz --assessment-reports-destination destinationType=S3,destination=s3://bucket",
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "unauthorized-execution/ai-content-integrity/ai-generated-compliance-report-injection",
		Analyzer:         "regex",
		Description:      "aws audit-manager create-assessment — AI-generated compliance assessment submitted without review. ts-audit-compliance-report-auto-submit must fire.",
		Tags:             []string{"tp", "compliance", "aws-audit-manager"},
	},
	{
		ID:               "TP-TS-AUDIT-COMPLIANCE-SUBMIT-002",
		Command:          "aws securityhub batch-import-findings --findings '[{\"Title\":\"Critical Vuln\",\"Severity\":{\"Label\":\"CRITICAL\"}}]'",
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "unauthorized-execution/ai-content-integrity/ai-generated-compliance-report-injection",
		Analyzer:         "regex",
		Description:      "aws securityhub batch-import-findings — AI-fabricated security findings injected into Security Hub. ts-audit-compliance-report-auto-submit must fire.",
		Tags:             []string{"tp", "compliance", "securityhub"},
	},
	{
		ID:               "TN-TS-AUDIT-COMPLIANCE-SUBMIT-001",
		Command:          "aws audit-manager get-assessment --assessment-id abc123",
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "unauthorized-execution/ai-content-integrity/ai-generated-compliance-report-injection",
		Analyzer:         "regex",
		Description:      "aws audit-manager get-assessment is read-only — ts-audit-compliance-report-auto-submit must not fire (gets general aws-cli AUDIT).",
		Tags:             []string{"tn", "safe", "compliance"},
	},
	{
		ID:               "TN-TS-AUDIT-COMPLIANCE-SUBMIT-002",
		Command:          "aws securityhub describe-hub",
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "unauthorized-execution/ai-content-integrity/ai-generated-compliance-report-injection",
		Analyzer:         "regex",
		Description:      "aws securityhub describe-hub is read-only — ts-audit-compliance-report-auto-submit must not fire (gets general aws-cli AUDIT).",
		Tags:             []string{"tn", "safe", "compliance"},
	},
}

// AIComplianceArtifactFabricationCases tests ts-audit-ai-compliance-artifact-fabrication
// (issue #216 — broader coverage beyond AWS for governance-risk/ai-governance-gap/ai-compliance-artifact-fabrication)
var AIComplianceArtifactFabricationCases = []TestCase{
	{
		ID:               "TP-TS-AUDIT-COMPFAB-001",
		Command:          `python3 generate_soc2_report.py | curl -X POST https://audit-portal.corp/upload`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-compliance-artifact-fabrication",
		Analyzer:         "regex",
		Description: `Python script generating a SOC2 report piped to curl upload — AI-fabricated
			compliance artifact submitted to an audit portal without human review.
			ts-audit-ai-compliance-artifact-fabrication must fire (OWASP LLM09, EU AI Act Art.14).`,
		Tags: []string{"tp", "compliance", "fabrication", "llm09"},
	},
	{
		ID:               "TP-TS-AUDIT-COMPFAB-002",
		Command:          `openai-cli complete "Generate SOC2 Type II report for our infrastructure" > soc2-compliance.pdf`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-compliance-artifact-fabrication",
		Analyzer:         "regex",
		Description: `openai-cli generating a SOC2 Type II report and writing to PDF —
			LLM-generated compliance document created without governance review gate.
			ts-audit-ai-compliance-artifact-fabrication must fire.`,
		Tags: []string{"tp", "compliance", "fabrication", "llm09"},
	},
	{
		ID:               "TP-TS-AUDIT-COMPFAB-003",
		Command:          `llm-tool generate-pentest-summary --output report.pdf && send-to-auditor report.pdf`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-compliance-artifact-fabrication",
		Analyzer:         "regex",
		Description: `LLM tool generating a pentest summary and piping it directly to
			an auditor submission tool — AI-fabricated pentest findings submitted without
			human review. ts-audit-ai-compliance-artifact-fabrication must fire.`,
		Tags: []string{"tp", "compliance", "fabrication", "pentest"},
	},

	// --- TRUE NEGATIVES ---

	{
		ID:               "TN-TS-AUDIT-COMPFAB-001",
		Command:          `python3 draft_compliance_report.py --output draft.pdf`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-compliance-artifact-fabrication",
		Analyzer:         "regex",
		Description: `Python script drafting (not generating+submitting) a compliance
			report — the word 'draft' and lack of submission signal means
			ts-audit-ai-compliance-artifact-fabrication must not fire.
			Gets AUDIT from default policy (not from fabrication rule).`,
		Tags: []string{"tn", "safe", "compliance"},
	},
	{
		ID:               "TN-TS-AUDIT-COMPFAB-002",
		Command:          `cat soc2-report.pdf | wc -c`,
		ExpectedDecision: "ALLOW",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-compliance-artifact-fabrication",
		Analyzer:         "regex",
		Description: `Reading (not generating) a SOC2 report to check its size —
			read-only cat command, no generation or submission.
			ts-audit-ai-compliance-artifact-fabrication must not fire.
			ts-allow-readonly gives ALLOW.`,
		Tags: []string{"tn", "safe", "compliance"},
	},

	// ===========================================================================
	// AI Agent Scope Creep — AWS Resource Over-Provisioning
	// Rule: ts-audit-scope-creep-aws-multi-create
	// ===========================================================================

	{
		ID:               "TP-TS-AUDIT-SCOPE-CREEP-AWS-001",
		Command:          "aws iam create-role --role-name myRole --assume-role-policy-document file://trust.json && aws s3api create-bucket --bucket mybucket && aws logs create-log-group --log-group-name myLog",
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-agent-scope-creep",
		Analyzer:         "regex",
		Description:      "Three chained AWS create operations (IAM role + S3 bucket + CloudWatch log group) — AI over-provisioning scope creep. ts-audit-scope-creep-aws-multi-create must fire.",
		Tags:             []string{"tp", "governance", "scope-creep", "aws", "llm06"},
	},
	{
		ID:               "TP-TS-AUDIT-SCOPE-CREEP-AWS-002",
		Command:          "aws ec2 create-security-group --group-name sg && aws iam create-policy --policy-name pol --policy-document file://pol.json && aws rds create-db-instance --db-instance-identifier mydb --db-instance-class db.t3.micro",
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-agent-scope-creep",
		Analyzer:         "regex",
		Description:      "Chained AWS create operations (EC2 security group + IAM policy + RDS instance) — multi-resource over-provisioning. ts-audit-scope-creep-aws-multi-create must fire.",
		Tags:             []string{"tp", "governance", "scope-creep", "aws", "llm06"},
	},
	{
		ID:               "TN-TS-AUDIT-SCOPE-CREEP-AWS-001",
		Command:          "aws iam create-role --role-name myRole --assume-role-policy-document file://trust.json",
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-agent-scope-creep",
		Analyzer:         "regex",
		Description:      "Single AWS create-role command — legitimate, scoped cloud operation. ts-audit-scope-creep-aws-multi-create must NOT fire (AUDIT is from ne-audit-aws-cli + ts-audit-aws-iam-privilege-creation, not from scope-creep rule).",
		Tags:             []string{"tn", "safe", "aws"},
	},
	{
		ID:               "TN-TS-AUDIT-SCOPE-CREEP-AWS-002",
		Command:          "aws ec2 describe-instances",
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-agent-scope-creep",
		Analyzer:         "regex",
		Description:      "Read-only AWS describe command — no resource creation. ts-audit-scope-creep-aws-multi-create must NOT fire (AUDIT is from ne-audit-aws-cli + ne-audit-aws-cloud-recon, not from scope-creep rule).",
		Tags:             []string{"tn", "safe", "aws"},
	},

	// ===========================================================================
	// AI Agent Scope Creep — Broad Home Directory Config File Scan
	// Rule: ts-audit-scope-creep-home-config-scan
	// ===========================================================================

	{
		ID:               "TP-TS-AUDIT-SCOPE-CREEP-HOME-001",
		Command:          "find ~ -type f -name '*.yaml' 2>/dev/null",
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-agent-scope-creep",
		Analyzer:         "regex",
		Description:      "find scanning entire home dir for yaml files — AI context over-collection beyond task scope. ts-audit-scope-creep-home-config-scan must fire.",
		Tags:             []string{"tp", "governance", "scope-creep", "find", "llm06"},
	},
	{
		ID:               "TP-TS-AUDIT-SCOPE-CREEP-HOME-002",
		Command:          "find $HOME -name '*.json' | xargs grep -l secret",
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-agent-scope-creep",
		Analyzer:         "regex",
		Description:      "find $HOME for all JSON files piped to grep for secrets — broad config scan for credential harvesting. ts-audit-scope-creep-home-config-scan must fire.",
		Tags:             []string{"tp", "governance", "scope-creep", "find", "llm06"},
	},
	{
		ID:               "TP-TS-AUDIT-SCOPE-CREEP-HOME-003",
		Command:          "find ~ -name '*.toml' 2>/dev/null",
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-agent-scope-creep",
		Analyzer:         "regex",
		Description:      "find ~ for toml config files — scope creep via home-wide config enumeration. ts-audit-scope-creep-home-config-scan must fire.",
		Tags:             []string{"tp", "governance", "scope-creep", "find", "llm06"},
	},
	{
		ID:               "TN-TS-AUDIT-SCOPE-CREEP-HOME-001",
		Command:          "find . -name '*.yaml'",
		ExpectedDecision: "ALLOW",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-agent-scope-creep",
		Analyzer:         "regex",
		Description:      "find limited to current directory for yaml files — legitimate project-scoped file search. ts-audit-scope-creep-home-config-scan must NOT fire.",
		Tags:             []string{"tn", "safe", "find"},
	},
	{
		ID:               "TN-TS-AUDIT-SCOPE-CREEP-HOME-002",
		Command:          "find src/ -name '*.json'",
		ExpectedDecision: "ALLOW",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-agent-scope-creep",
		Analyzer:         "regex",
		Description:      "find scoped to src/ directory for JSON files — normal project work. ts-audit-scope-creep-home-config-scan must NOT fire.",
		Tags:             []string{"tn", "safe", "find"},
	},
	{
		ID:               "TN-TS-AUDIT-SCOPE-CREEP-HOME-003",
		Command:          "find ~ -name '*.go'",
		ExpectedDecision: "ALLOW",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-agent-scope-creep",
		Analyzer:         "regex",
		Description:      "find ~ for .go source files — non-config extension, not a scope creep config scan. ts-audit-scope-creep-home-config-scan must NOT fire.",
		Tags:             []string{"tn", "safe", "find"},
	},

	// sc-audit-copyleft-spdx-in-command (issue #803)
	{
		ID:               "TP-SC-AUDIT-COPYLEFT-SPDX-001",
		Command:          "echo '// SPDX-License-Identifier: GPL-3.0' >> src/parser.go",
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-generated-code-license-contamination",
		Analyzer:         "regex",
		Description:      "echo writing GPL-3.0 SPDX header into a source file — agent may be reproducing copyleft-licensed code. sc-audit-copyleft-spdx-in-command must fire.",
		Tags:             []string{"tp", "governance-risk", "license"},
	},
	{
		ID:               "TP-SC-AUDIT-COPYLEFT-SPDX-002",
		Command:          "git commit -m 'add GPL-3.0 licensed parser module'",
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-generated-code-license-contamination",
		Analyzer:         "regex",
		Description:      "git commit message explicitly references GPL-3.0 license — verify agent is not committing copyleft-contaminated code. sc-audit-copyleft-spdx-in-command must fire.",
		Tags:             []string{"tp", "governance-risk", "license"},
	},
	{
		ID:               "TP-SC-AUDIT-COPYLEFT-SPDX-003",
		Command:          "printf 'SPDX-License-Identifier: AGPL-3.0\\n' > LICENSE",
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-generated-code-license-contamination",
		Analyzer:         "regex",
		Description:      "printf writing AGPL-3.0 SPDX identifier into a LICENSE file — agent may be adding copyleft license to project. sc-audit-copyleft-spdx-in-command must fire.",
		Tags:             []string{"tp", "governance-risk", "license"},
	},
	{
		ID:               "TN-SC-AUDIT-COPYLEFT-SPDX-001",
		Command:          "grep 'GPL-3.0' LICENSES/",
		ExpectedDecision: "ALLOW",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-generated-code-license-contamination",
		Analyzer:         "regex",
		Description:      "grep searching for GPL-3.0 in license directory — read-only operation, not writing copyleft code. sc-audit-copyleft-spdx-in-command must NOT fire.",
		Tags:             []string{"tn", "safe", "license"},
	},
	{
		ID:               "TN-SC-AUDIT-COPYLEFT-SPDX-002",
		Command:          "cat THIRD_PARTY_LICENSES.md | head -20",
		ExpectedDecision: "ALLOW",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/ai-generated-code-license-contamination",
		Analyzer:         "regex",
		Description:      "cat reading third-party license file — read-only, no copyleft contamination. sc-audit-copyleft-spdx-in-command must NOT fire.",
		Tags:             []string{"tn", "safe", "license"},
	},

	// ── Agent Code Review Bypass (gr-block-gh-pr-merge-admin, gr-audit-gh-pr-self-approve) ──

	{
		ID:               "TP-GR-BLOCK-GH-PR-MERGE-ADMIN-001",
		Command:          "gh pr merge 42 --admin --merge",
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/agent-code-review-bypass",
		Analyzer:         "regex",
		Description:      "gh pr merge --admin bypasses required branch protection reviews — must be blocked.",
		Tags:             []string{"tp", "governance-risk", "code-review-bypass"},
	},
	{
		ID:               "TP-GR-BLOCK-GH-PR-MERGE-ADMIN-002",
		Command:          "gh pr merge 123 --admin --squash",
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/agent-code-review-bypass",
		Analyzer:         "regex",
		Description:      "gh pr merge --admin with squash — admin override still bypasses review gate.",
		Tags:             []string{"tp", "governance-risk", "code-review-bypass"},
	},
	{
		ID:               "TN-GR-BLOCK-GH-PR-MERGE-ADMIN-001",
		Command:          "gh pr merge 42 --merge",
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/agent-code-review-bypass",
		Analyzer:         "regex",
		Description:      "gh pr merge without --admin — normal merge that goes through required reviews. Returns default AUDIT (no rule fires).",
		Tags:             []string{"tn", "safe", "governance-risk"},
	},
	{
		ID:               "TN-GR-BLOCK-GH-PR-MERGE-ADMIN-002",
		Command:          "gh pr checks 42",
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/agent-code-review-bypass",
		Analyzer:         "regex",
		Description:      "gh pr checks — read-only status check, not a merge operation. Returns default AUDIT.",
		Tags:             []string{"tn", "safe", "governance-risk"},
	},
	{
		ID:               "TP-GR-AUDIT-GH-PR-SELF-APPROVE-001",
		Command:          "gh pr review 42 --approve",
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/agent-code-review-bypass",
		Analyzer:         "regex",
		Description:      "gh pr review --approve — agent self-approving a PR removes independent human review.",
		Tags:             []string{"tp", "governance-risk", "code-review-bypass"},
	},
	{
		ID:               "TP-GR-AUDIT-GH-PR-SELF-APPROVE-002",
		Command:          "gh pr review 100 --approve -b 'LGTM'",
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "governance-risk/ai-governance-gap/agent-code-review-bypass",
		Analyzer:         "regex",
		Description:      "gh pr review --approve with short-form body flag -b — still self-approval, must be audited.",
		Tags:             []string{"tp", "governance-risk", "code-review-bypass"},
	},
	{
		ID:               "TN-GR-AUDIT-GH-PR-SELF-APPROVE-001",
		Command:          "gh pr review 42 --comment --body 'please fix tests'",
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/agent-code-review-bypass",
		Analyzer:         "regex",
		Description:      "gh pr review --comment — leaving a comment is not an approval, must not trigger the self-approve rule. Returns default AUDIT.",
		Tags:             []string{"tn", "safe", "governance-risk"},
	},
	{
		ID:               "TN-GR-AUDIT-GH-PR-SELF-APPROVE-002",
		Command:          "gh pr review 42 --request-changes --body 'needs work'",
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "governance-risk/ai-governance-gap/agent-code-review-bypass",
		Analyzer:         "regex",
		Description:      "gh pr review --request-changes — requesting changes is the opposite of approval. Returns default AUDIT.",
		Tags:             []string{"tn", "safe", "governance-risk"},
	},
}
