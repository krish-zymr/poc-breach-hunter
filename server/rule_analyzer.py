"""
Static rule-based risk analyzer for Breach Hunter.
Deterministic evaluation without network calls.
"""
import json
import os
import re
import sys
from typing import Dict, List, Optional, Any
from pathlib import Path
from datetime import datetime, timezone


class RuleFinding:
    """Represents a single rule match finding."""
    
    def __init__(
        self,
        rule_id: str,
        rule_name: str,
        severity: str,
        category: str,
        risk_score: int,
        description: str,
        matched_conditions: Dict[str, Any]
    ):
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.severity = severity
        self.category = category
        self.risk_score = risk_score
        self.description = description
        self.matched_conditions = matched_conditions


class RuleAnalyzer:
    """Analyzes actions against static rules."""
    
    def __init__(self, rules_file: str = "rules.json"):
        self.rules_file = rules_file
        self.rules_config = self._load_rules()
        self.allowed_file_operations = self.rules_config.get("allowed_file_operations", [])
    
    def _load_rules(self) -> Dict[str, Any]:
        """Load rules from JSON configuration file."""
        try:
            rules_path = Path(__file__).parent / self.rules_file
            if not rules_path.exists():
                print(
                    f"[RuleAnalyzer] Rules file not found: {rules_path}, using empty rules",
                    file=sys.stderr,
                    flush=True,
                )
                return {"rules": [], "decision_policy": {}}
            
            with open(rules_path, "r", encoding="utf-8") as f:
                config = json.load(f)
            print(
                f"[RuleAnalyzer] Loaded {len(config.get('rules', []))} rules from {rules_path}",
                file=sys.stdout,
                flush=True,
            )
            return config
        except Exception as e:
            print(
                f"[RuleAnalyzer] Error loading rules: {e}",
                file=sys.stderr,
                flush=True,
            )
            return {"rules": [], "decision_policy": {}}
    
    def _normalize_path(self, path: str) -> str:
        """Normalize file path for matching."""
        if not path:
            return ""
        # Expand ~ to home directory
        path = os.path.expanduser(path)
        # Normalize separators
        path = os.path.normpath(path)
        # Ensure absolute paths start with / (Unix) or have drive letter (Windows)
        # For security rules, we care about Unix-style paths
        if path and not path.startswith("/") and not (len(path) > 1 and path[1] == ":"):
            # If it's a relative path that should be absolute (like etc/passwd -> /etc/passwd)
            # Don't auto-convert, but we'll handle matching separately
            pass
        return path
    
    def _match_url_pattern(self, url: str, pattern: str) -> bool:
        """Check if URL matches a pattern (supports wildcards)."""
        if "*" in pattern:
            # Convert glob pattern to regex
            escaped = pattern.replace(".", "\\.").replace("+", "\\+").replace("?", "\\?")
            escaped = escaped.replace("*", ".*")
            regex_pattern = "^" + escaped
            return bool(re.match(regex_pattern, url))
        return url.startswith(pattern) or pattern in url
    
    def _match_path_pattern(self, file_path: str, patterns: List[str]) -> bool:
        """Check if file path matches any pattern."""
        normalized_path = self._normalize_path(file_path)
        
        # Ensure absolute paths start with /
        if not normalized_path.startswith("/") and not normalized_path.startswith("~"):
            # For relative paths, try to match against patterns that might match relative paths
            # But also check if the pattern would match if we prepend /
            pass
        
        for pattern in patterns:
            # Handle exact paths
            if pattern.startswith("/") and "*" not in pattern:
                if normalized_path == pattern or normalized_path.startswith(pattern + "/"):
                    return True
                # Also check if normalized_path without leading / matches
                if not normalized_path.startswith("/") and normalized_path == pattern.lstrip("/"):
                    return True
            
            # Handle wildcard patterns
            if "*" in pattern:
                # Convert glob pattern to regex with proper escaping
                # Escape special regex chars except * and /
                escaped = pattern.replace(".", "\\.").replace("+", "\\+").replace("?", "\\?")
                escaped = escaped.replace("*", ".*")
                # Use ^ to match from start, $ for end (but allow trailing content after *)
                if pattern.endswith("*"):
                    regex_pattern = "^" + escaped.rstrip(".*") + ".*"
                else:
                    regex_pattern = "^" + escaped + "$"
                
                if re.match(regex_pattern, normalized_path):
                    return True
                # Also try matching without leading / for relative paths
                if not normalized_path.startswith("/") and pattern.startswith("/"):
                    # Try matching relative path against pattern without leading /
                    relative_pattern = pattern.lstrip("/")
                    if "*" in relative_pattern:
                        rel_escaped = relative_pattern.replace(".", "\\.").replace("+", "\\+").replace("?", "\\?")
                        rel_escaped = rel_escaped.replace("*", ".*")
                        if relative_pattern.endswith("*"):
                            rel_regex = "^" + rel_escaped.rstrip(".*") + ".*"
                        else:
                            rel_regex = "^" + rel_escaped + "$"
                        if re.match(rel_regex, normalized_path):
                            return True
            
            # Handle extension patterns like *.pem
            if pattern.startswith("*."):
                if normalized_path.endswith(pattern[1:]):
                    return True
        
        return False
    
    def _check_rule_conditions(self, rule: Dict[str, Any], action_type: str, action_details: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check if action matches rule conditions. Returns matched conditions or None."""
        conditions = rule.get("conditions", {})
        matched = {}
        
        # Check action_type
        if "action_type" in conditions:
            if action_type != conditions["action_type"]:
                return None
            matched["action_type"] = action_type
        
        # Check command
        if "command" in conditions:
            command = action_details.get("command", "")
            if isinstance(conditions["command"], list):
                if command not in conditions["command"]:
                    return None
            elif command != conditions["command"]:
                return None
            matched["command"] = command
        
        # Check command_not_in
        if "command_not_in" in conditions:
            command = action_details.get("command", "")
            if command in conditions["command_not_in"]:
                return None
        
        # Check command_patterns
        if "command_patterns" in conditions:
            command = action_details.get("command", "")
            matched_pattern = False
            for pattern in conditions["command_patterns"]:
                if pattern in command.lower():
                    matched_pattern = True
                    matched["command_pattern"] = pattern
                    break
            if not matched_pattern:
                return None
        
        # Check path patterns OR exact paths (OR logic, not AND)
        file_path = action_details.get("file_path") or ""
        
        # For command_execution, try to extract path from command string
        if not file_path and action_type == "command_execution":
            command_str = action_details.get("command", "")
            # Try to extract file paths from common commands (chmod, chown, etc.)
            # Look for paths that start with / or ~
            path_matches = re.findall(r'[/~][^\s]+', command_str)
            if path_matches:
                # Use the last path found (usually the target file)
                file_path = path_matches[-1]
        
        path_matched = False
        
        if "path_patterns" in conditions:
            if file_path and self._match_path_pattern(file_path, conditions["path_patterns"]):
                matched["path_pattern"] = file_path
                path_matched = True
        
        if "exact_paths" in conditions:
            if file_path:
                normalized_path = self._normalize_path(file_path)
                # Check exact match
                if normalized_path in conditions["exact_paths"]:
                    matched["exact_path"] = normalized_path
                    path_matched = True
                # Also check if path contains critical password files (for security)
                elif any(critical_file in normalized_path for critical_file in ["/etc/passwd", "/etc/shadow", "/etc/sudoers"]):
                    matched["exact_path"] = normalized_path
                    path_matched = True
        
        # If either path_patterns or exact_paths is specified, at least one must match
        if ("path_patterns" in conditions or "exact_paths" in conditions) and not path_matched:
            return None
        
        # Check path_contains
        if "path_contains" in conditions:
            if not file_path:  # Handle None or empty file_path
                return None
            found = False
            for pattern in conditions["path_contains"]:
                if pattern in file_path:
                    found = True
                    matched["path_contains"] = pattern
                    break
            if not found:
                return None
        
        # Check URL patterns (for api_call actions)
        if "url_patterns" in conditions:
            url = action_details.get("url", "")
            if not url:
                return None
            url_matched = False
            for pattern in conditions["url_patterns"]:
                if self._match_url_pattern(url, pattern):
                    matched["url_pattern"] = pattern
                    url_matched = True
                    break
            if not url_matched:
                return None
        
        # Check method (for api_call actions)
        if "method" in conditions:
            method = action_details.get("method", "")
            if isinstance(conditions["method"], list):
                if method not in conditions["method"]:
                    return None
            elif method != conditions["method"]:
                return None
            matched["method"] = method
        
        return matched if matched else {"matched": True}
    
    def analyze(self, action_type: str, action_details: Dict[str, Any]) -> List[RuleFinding]:
        """Analyze action against all rules and return findings."""
        findings = []
        rules = self.rules_config.get("rules", [])
        
        for rule in rules:
            if not rule.get("enabled", True):
                continue
            
            matched_conditions = self._check_rule_conditions(rule, action_type, action_details)
            if matched_conditions:
                # Calculate risk score (use max for now, could be more sophisticated)
                risk_score_config = rule.get("risk_score", {})
                risk_score = risk_score_config.get("max", 50)
                
                # Generate description
                description = f"{rule.get('name', rule.get('id'))}: Matched conditions: {matched_conditions}"
                
                finding = RuleFinding(
                    rule_id=rule.get("id", "unknown"),
                    rule_name=rule.get("name", "Unknown Rule"),
                    severity=rule.get("severity", "MEDIUM"),
                    category=rule.get("category", "UNKNOWN"),
                    risk_score=risk_score,
                    description=description,
                    matched_conditions=matched_conditions
                )
                findings.append(finding)
                print(
                    f"[RuleAnalyzer] Rule matched: {rule.get('id')} (severity={rule.get('severity')}, "
                    f"action_type={action_type}, file_path={action_details.get('file_path', 'N/A')}, "
                    f"command={action_details.get('command', 'N/A')})",
                    file=sys.stdout,
                    flush=True,
                )
        
        if not findings:
            print(
                f"[RuleAnalyzer] No rules matched for action_type={action_type}, "
                f"file_path={action_details.get('file_path', 'N/A')}, "
                f"command={action_details.get('command', 'N/A')}",
                file=sys.stdout,
                flush=True,
            )
        
        return findings


class AnalysisResult:
    """Result of static rule analysis."""
    
    def __init__(
        self,
        findings: List[RuleFinding],
        risk_score: int,
        decision: str,
        enforcement_action: str,
        risk_level: str,
        intent: str,
        description: str,
        should_use_llm: bool
    ):
        self.findings = findings
        self.risk_score = risk_score
        self.decision = decision
        self.enforcement_action = enforcement_action
        self.risk_level = risk_level
        self.intent = intent
        self.description = description
        self.should_use_llm = should_use_llm


class AnalysisAggregator:
    """Aggregates results from multiple analyzers."""
    
    def __init__(self, rules_file: str = "rules.json"):
        self.rule_analyzer = RuleAnalyzer(rules_file)
        self.rules_config = self.rule_analyzer.rules_config
        self.decision_policy = self.rules_config.get("decision_policy", {})
    
    def aggregate(self, action_type: str, action_details: Dict[str, Any]) -> AnalysisResult:
        """Run all analyzers and aggregate results."""
        # Run rule analyzer
        findings = self.rule_analyzer.analyze(action_type, action_details)
        
        # Calculate aggregate risk score
        risk_score = 0
        if findings:
            # Sum all risk scores, cap at 100
            risk_score = min(sum(f.risk_score for f in findings), 100)
        else:
            risk_score = 0
        
        # Determine highest severity
        severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        max_severity = "LOW"
        if findings:
            max_severity = max(
                findings,
                key=lambda f: severity_order.get(f.severity, 0)
            ).severity
        
        # Apply decision policy
        decision, enforcement_action, risk_level, should_use_llm = self._apply_decision_policy(
            findings, risk_score, action_type, action_details
        )
        
        # Generate intent and description
        intent, description = self._generate_static_response(findings, action_type, action_details)
        
        return AnalysisResult(
            findings=findings,
            risk_score=risk_score,
            decision=decision,
            enforcement_action=enforcement_action,
            risk_level=risk_level,
            intent=intent,
            description=description,
            should_use_llm=should_use_llm
        )
    
    def _apply_decision_policy(
        self,
        findings: List[RuleFinding],
        risk_score: int,
        action_type: str,
        action_details: Dict[str, Any]
    ) -> tuple:
        """Apply decision policy to determine action."""
        # Check for soft rules (SAFE operations) - ALLOW immediately, no LLM call
        if self.decision_policy.get("allow_safe_operations", True):
            # Get rules config to check for soft rules
            rules = self.rules_config.get("rules", [])
            soft_rule_ids = {r.get("id") for r in rules if r.get("rule_type") == "soft" and r.get("enabled", True)}
            soft_findings = [f for f in findings if f.rule_id in soft_rule_ids]
            
            if soft_findings:
                # Check if ONLY soft rules matched (no hard rules)
                hard_findings = [f for f in findings if f.rule_id not in soft_rule_ids]
                if not hard_findings:
                    print(
                        f"[RuleAnalyzer] Safe operation detected: {len(soft_findings)} soft rule(s) matched. "
                        f"ALLOWING action - skipping LLM evaluation.",
                        file=sys.stdout,
                        flush=True,
                    )
                    return ("ALLOW", "NONE", "LOW", False)
        
        # Check for CRITICAL severity - BLOCK immediately, no LLM call
        if self.decision_policy.get("block_critical", True):
            critical_findings = [f for f in findings if f.severity == "CRITICAL"]
            if critical_findings:
                print(
                    f"[RuleAnalyzer] CRITICAL severity detected: {len(critical_findings)} finding(s). "
                    f"BLOCKING action - skipping LLM evaluation.",
                    file=sys.stdout,
                    flush=True,
                )
                return ("BLOCK", "DENY", "CRITICAL", False)
        
        # Check risk score threshold - BLOCK if score too high, no LLM call
        block_threshold = self.decision_policy.get("block_risk_threshold", 80)
        if risk_score >= block_threshold:
            print(
                f"[RuleAnalyzer] Risk score {risk_score} >= threshold {block_threshold}. "
                f"BLOCKING action - skipping LLM evaluation.",
                file=sys.stdout,
                flush=True,
            )
            return ("BLOCK", "DENY", "HIGH", False)
        
        # Check for meaningful rule match
        meaningful_match = len(findings) > 0 and any(
            f.category != "UNKNOWN_OPERATION" for f in findings
        )
        
        # Check for missing required fields
        missing_fields = self._check_missing_fields(action_type, action_details)
        
        # Determine if uncertain
        if self.decision_policy.get("uncertain_on_no_rule_match", True) and not meaningful_match:
            return ("UNCERTAIN", "REVIEW", "UNKNOWN", True)
        
        if self.decision_policy.get("uncertain_on_missing_fields", True) and missing_fields:
            return ("UNCERTAIN", "REVIEW", "UNKNOWN", True)
        
        # Default: ALLOW
        return ("ALLOW", "NONE", "LOW" if risk_score < 30 else "MEDIUM", True)
    
    def _check_missing_fields(self, action_type: str, action_details: Dict[str, Any]) -> bool:
        """Check if required fields are missing for classification."""
        if action_type == "file_operation":
            if not action_details.get("file_path") and not action_details.get("command"):
                return True
        elif action_type == "command_execution":
            if not action_details.get("command"):
                return True
        elif action_type == "api_call":
            if not action_details.get("url"):
                return True
        return False
    
    def _generate_static_response(
        self,
        findings: List[RuleFinding],
        action_type: str,
        action_details: Dict[str, Any]
    ) -> tuple:
        """Generate static intent and description without LLM."""
        if not findings:
            intent = f"{action_type} operation"
            description = f"Standard {action_type} operation with no rule violations detected."
            return (intent, description)
        
        # Check if these are soft rules (safe operations)
        rules = self.rules_config.get("rules", [])
        soft_rule_ids = {r.get("id") for r in rules if r.get("rule_type") == "soft" and r.get("enabled", True)}
        soft_findings = [f for f in findings if f.rule_id in soft_rule_ids]
        hard_findings = [f for f in findings if f.rule_id not in soft_rule_ids]
        
        if soft_findings and not hard_findings:
            # Safe operation - positive framing
            intent = f"Safe {action_type} operation"
            description_parts = [
                f"Static analysis confirmed safe operation matching {len(soft_findings)} safe rule(s):"
            ]
            for finding in soft_findings:
                description_parts.append(
                    f"- {finding.rule_name}: {finding.description}"
                )
            description = " ".join(description_parts)
            return (intent, description)
        
        # Aggregate findings into description (for violations)
        categories = [f.category for f in findings]
        severities = [f.severity for f in findings]
        
        intent = f"{action_type} operation with {len(findings)} rule violation(s)"
        
        description_parts = [
            f"Static analysis detected {len(findings)} rule violation(s):"
        ]
        for finding in findings:
            description_parts.append(
                f"- {finding.rule_name} ({finding.severity}): {finding.description}"
            )
        
        description = " ".join(description_parts)
        return (intent, description)


# Import sys for error handling
import sys

