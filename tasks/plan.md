# Implementation Plan: ToolAtlas Agent Supply-Chain Gate

## Overview

سنحوّل ToolAtlas من محلل JSON capability صغير إلى بوابة محلية لفحص سلسلة توريد سياق الوكلاء. ستظل النواة offline-first، لكن ستفحص مجلدات repositories بحثًا عن agent manifests وMCP configurations وprompt/skill files، وتنتج manifest وlockfile حتميًا، وتكشف hidden Unicode وتسرب الأسرار والتعليمات الخطرة، وتربط المخاطر عبر عدة ملفات، وتوفر baseline enforcement وGitHub Action.

لن نكسر أو نعيد تعريف أوامر `scan` و`policy` و`diff`. ستضاف أوامر جديدة (`repo-scan`, `lock`, `baseline`) وتظل كل عمليات التشغيل والـ network خارج المسار الافتراضي.

## Architecture decisions

| القرار | السبب |
|---|---|
| الاستمرار في Python بلا runtime dependencies | يحافظ على سهولة التثبيت، قابلية التشغيل offline، وسطح هجوم صغير. |
| Repository scanner يقرأ الملفات فقط | يمنع تشغيل scripts أو MCP servers غير موثوقة أثناء الفحص. |
| Lockfile يحفظ SHA-256 وrelative paths وschema version | يثبت reproducibility والتغيرات دون ادعاء provenance cryptographic للناشر. |
| Findings لها source path وline/column اختياريان | يجعل النتائج قابلة للمراجعة وSARIF/GitHub Code Scanning. |
| Correlation engine منفصل عن atomic rules | يسمح بكشف سلاسل مثل secret-read + network-send دون خلطها بقواعد منفردة. |
| Baseline صريح ومراجعته fail-closed عند corruption | يمنع إخفاء findings جديدة أو stale suppressions. |
| Plugin/adapters contract | يمكّن MCP/OpenAPI/A2A adapters مستقبلًا دون إعادة كتابة domain. |

## Implementation phases

### Phase 1: Contract and repository model

Define `RepositoryTarget`, `SourceFile`, `FileDigest`, `RepositoryManifest`, and versioned lockfile models. Add safe path traversal with symlink policy, file-size limits, extension allowlists, and deterministic sorting.

### Phase 2: Static repository scanners

Add scanners for hidden Unicode/bidi/variation selectors, secret-like literals, dangerous lifecycle commands, MCP server configuration fields, agent instruction files, and capability declarations. Each finding must include stable rule ID, severity, source path, evidence, remediation, and confidence.

### Phase 3: Correlation and lockfile

Build cross-file correlation rules and lock generation. The lock must include relative file path, bytes digest, normalized capability digest, scanner version, and generated-at-independent canonical content. A lock verification command must detect modified, added, removed, and unexpected files.

### Phase 4: Baseline and GitHub integration

Add baseline create/check commands and a turnkey GitHub Action that emits SARIF with physical locations, JSON summary, and exit codes. Add examples for a clean repository and a deliberately unsafe fixture.

### Phase 5: Quality and release

Extend unit, integration, security, property-style deterministic tests, benchmarks, docs, CI, CodeQL/SARIF validation, package build, fresh-clone smoke test, version bump, release, and final maintainer review.

## Acceptance criteria

1. `toolatlas repo-scan examples/agent-repo` completes without executing any file or contacting the network.
2. `toolatlas lock examples/agent-repo --output toolatlas.lock.json` is byte-for-byte deterministic across two runs.
3. `toolatlas lock verify examples/agent-repo --lock toolatlas.lock.json` returns 0 for unchanged content and 4 for changed content.
4. Hidden Unicode and secret-like content produce findings with valid relative paths and line numbers.
5. A cross-file correlation fixture produces one explainable high/critical finding from multiple low-level signals.
6. Baseline creation and checking catch new findings and stale suppressions.
7. SARIF upload validation accepts generated output with physical locations.
8. Existing public commands and tests remain backward-compatible.
9. CI passes lint, format, strict type checking, tests with at least 85% coverage, build, dependency audit, and security scan.

## Risks and mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Scope grows into a duplicate of Repo Forensics | High | Keep ToolAtlas focused on reproducible manifest/lock/baseline governance and capability correlation, not 27 malware scanners. |
| Malicious fixture triggers execution | Critical | Never import, spawn, evaluate, or fetch; only read bounded text/JSON/YAML-like files. |
| False positives reduce adoption | High | Explainable evidence, confidence, baseline, severity threshold, and explicit rule IDs. |
| Symlink/path traversal leaks host files | Critical | Resolve paths under target root, reject escaping symlinks, and test adversarial layouts. |
| Lockfile gives false provenance confidence | Medium | Document that SHA-256 proves content consistency, not publisher identity or signed provenance. |

## Checkpoints

After the repository model: tests and deterministic lock generation pass. After scanners: all security fixtures and path-safety tests pass. After baseline/GitHub integration: SARIF validates and the sample workflow passes. Before release: fresh clone, clean virtualenv install, full quality gate, and GitHub Actions success are required.
