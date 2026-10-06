# Phase 7 — Grounded LLM Investigator

## Goal

Add an LLM investigation layer that explains a validated incident without allowing the model to become the detection or authorization authority.

Pipeline:

Validated incident
→ sealed evidence packet
→ grounded LLM
→ structured findings
→ deterministic grounding validator
→ investigator report

## Evidence boundary

The LLM receives only the validated incident, reconstruction, ATT&CK enrichment, stage evidence, and incident timeline.

Raw external content is placed inside an explicit untrusted-evidence boundary. Instructions inside logs, filenames, resources, metadata or other telemetry are data, not instructions.

## Grounding contract

Every fact, inference and recommendation claim must cite one or more exact event IDs from the incident timeline.

The validator rejects:
- unknown evidence IDs;
- factual/inferential/recommendation claims without evidence IDs;
- invalid confidence values;
- empty reports;
- oversized claim sets.

Summary references such as [EVT-1001] are also checked against the incident event set.

## Provider model

Production uses an OpenAI-compatible chat-completions endpoint configured by:
- `LLM_BASE_URL`;
- `LLM_MODEL`;
- optional `LLM_API_KEY`;
- optional `LLM_PROVIDER`;
- optional `LLM_TIMEOUT`.

Ollama and other OpenAI-compatible local servers can therefore be used without changing the application code.

There is **no synthetic fallback**. Missing provider configuration fails closed.

## LLM permissions

The investigator is read-only. It has no tools, no shell, no arbitrary network actions and no authority to change incidents.

Recommendations are explanatory only. Any future automated response must be implemented outside the LLM and guarded by deterministic authorization.

## API

`POST /api/investigate`

Request:

```json
{
  "events": [/* normalized security events */],
  "incident_id": "optional specific incident",
  "question": "What happened and what evidence supports it?"
}
```

The endpoint first runs the deterministic analyzer. Investigation is refused when no validated incident exists.

## Phase 7 gate

The phase passes only when:
1. a sealed evidence packet is produced from a validated incident;
2. untrusted telemetry is explicitly separated from investigator instructions;
3. grounded provider responses are accepted;
4. unknown evidence references are rejected;
5. uncited factual/inferential/recommendation claims are rejected;
6. missing LLM provider configuration fails closed;
7. Phase 1–6 regression suites remain green;
8. the LLM cannot directly create, validate, suppress or mutate an incident.

## Security basis

OWASP's current LLM guidance identifies prompt injection as a major risk and recommends constrained behavior, defined output formats and deterministic validation. It also notes that RAG does not fully solve prompt injection, so the application must validate outputs outside the model.

## Research sources

- https://genai.owasp.org/llmrisk/llm01-prompt-injection/
- https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html
- https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/