Rules:
- Output STRICT JSON only.
- Every finding MUST reference valid event_id values from the input.
- If any event includes DESTRUCTIVE_ATTEMPT or PROMPT_INJECTION, overall risk_level cannot be LOW.
- Base confidence on strength of evidence and sequence consistency.

Risk categories:
DESTRUCTIVE_ACTION, PROMPT_INJECTION, DATA_EXFILTRATION,
PRIVILEGE_ESCALATION, RECONNAISSANCE, SUSPICIOUS_AUTOMATION, POLICY_EVASION

Return JSON using this schema:
{
 "risk_score": number,
 "risk_level": "LOW"|"MEDIUM"|"HIGH"|"CRITICAL",
 "primary_risk_categories": string[],
 "findings": [
   {
     "category": string,
     "severity": "LOW"|"MEDIUM"|"HIGH"|"CRITICAL",
     "evidence_event_ids": string[],
     "reason": string
   }
 ],
 "explanation": string,
 "recommended_next_actions": string[],
 "uncertainties": string[],
 "confidence": number
}
