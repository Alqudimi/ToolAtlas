# Latest gap research — 2026-08-20

## Sources

1. GitHub SARIF support: https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support
   - GitHub uses stable rule IDs, consistent filepaths, and partialFingerprints to match alerts across runs and avoid duplicates.
   - Physical locations improve pull-request display and targeted remediation.

2. Microsoft Agent Package Manager security model: https://microsoft.github.io/apm/enterprise/security/
   - Agent context is a build-time supply chain: prompts, instructions, skills, hooks, and MCP declarations.
   - Defended properties include reproducibility, integrity, provenance, and pre-deploy content safety.
   - APM explicitly does not sandbox runtime MCP servers or provide package signing/SLSA provenance.

3. Cloud Security Alliance Agentic MCP Security Best Practices: https://labs.cloudsecurityalliance.org/agentic/agentic-mcp-security-best-practices-v1/
   - Draft guide frames MCP as critical infrastructure and recommends defense in depth across authentication, tool integrity, session management, supply chain validation, isolation, and monitoring.
   - It describes tool poisoning, supply-chain risks, and the need for policy and validation controls.

4. OWASP Agentic Skills Top 10: https://github.com/OWASP/www-project-agentic-skills-top-10
   - Identifies malicious skills, supply-chain compromise, over-privilege, insecure metadata, untrusted instructions, weak isolation, update drift, poor scanning, lack of governance, and cross-platform reuse.

5. MCP authorization docs: https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/authorization
   - Remote MCP authorization follows OAuth 2.1 conventions and uses protected-resource metadata, authorization-server discovery, client registration, PKCE, scopes, and audience constraints.
   - Authorization is optional but recommended for user data and administrative actions.

## Decision context

ToolAtlas already has repository scanning, lockfile, baseline, SARIF physical locations/fingerprints, and configurable resource bounds. Candidate next gaps include policy-as-code evaluation, signed provenance, SBOM export, and authorization metadata linting. A new enhancement must avoid duplicating runtime gateways (ToolHive) or framework documents (OWASP), and should remain deterministic/offline in the core.
