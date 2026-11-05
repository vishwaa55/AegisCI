# AegisCI Experiment Report

**Date / Time**: `YYYY-MM-DD HH:MM:SS UTC`  
**Experiment ID**: `exp-...`  
**Scenario Name**: `...`  
**Scenario Type**: `[ Functional | Security ]`  
**Target Repository / Fixture**: `...`  

---

## 1. Baseline State & Input

- **Initial Failure Mode**: `[ Unit Test Failure | Logic Bug | Syntax Error | Missing Dependency | SQLi | CWE-... ]`
- **Error Log / Semgrep Finding**:
  ```text
  <paste raw error summary or Semgrep finding rule_id>
  ```
- **Affected File(s)**: `...`

---

## 2. Agent Diagnosis & Attacker Assessment

- **Diagnosed Category**: `...` (Expected: `...`)
- **Diagnosis Accuracy**: `[ Match | Partial | Mismatch ]`
- **Attacker Threat Model** *(Security Scenarios)*:
  - **Exploitability**: `[ unlikely | plausible | confirmed ]`
  - **Attack Vector**: `...`
  - **Inputs Controlled**: `...`

---

## 3. Patch Generation & Multi-Agent Debate

- **Defender Proposals**:
  - **Defender A Strategy**: `...`
  - **Defender B Strategy**: `...`
- **Rejection Memory Influence**:
  - Retrieved entries: `N`
  - Distance: `0.XXX`
  - Did memory prevent repeating past failed patches? `[ Yes | No | N/A ]`
- **Judge Decision / Reviewer Verdict**:
  - Winning Proposal: `[ Defender A | Defender B | Single Fix-Proposer ]`
  - Judge Rationale: `...`

---

## 4. Sandbox Validation & Execution

- **Sandbox Type**: `[ Docker Container | Isolated Process Directory ]`
- **Attempts Made**: `N / 3`
- **Sandbox Exit Code**: `0`
- **Tests Passed**: `[ True | False ]`
- **Semgrep Finding Cleared**: `[ True | False | N/A ]`
- **Regression Detected**: `[ None | Detected ]`

---

## 5. Final Outcome & PR Audit Trail

- **Final Status**: `[ pr_opened | security_pr_opened | escalated | security_escalated ]`
- **Remediation Branch**: `agent-fix/...` or `security-fix/...`
- **Pull Request URL**: `https://github.com/.../pull/...`
- **Human Approval Status**: `[ Pending Developer Review ]` *(Mandatory before merge)*
- **Execution Duration**: `XX.XX seconds`

---

## 6. Observations & Lessons Learned

- **Strengths Observed**:
- **Edge Cases Encountered**:
- **Follow-up Adjustments**:
