# AI-Assisted Contribution Guidelines

AI-assisted contributions must disclose their AI involvement via an `Assisted-by` tag at the end of the commit message (after the sign-off line, if present):

```
Assisted-by: AGENT_NAME:MODEL_VERSION [TOOL1] [TOOL2]
```

- `AGENT_NAME` — the AI tool/framework used (e.g. Claude, OpenClaw, Copilot)
- `MODEL_VERSION` — the model version **without** provider prefix: `deepseek-v4-flash`, not `deepseek/deepseek-v4-flash`
- `[TOOL1] [TOOL2]` — optional specialized analysis tools that significantly contributed (e.g. coccinelle, sparse, clang-tidy). Do **not** list everyday tools such as git, gcc, make, or text editors

Multiple tags are allowed when different AI tools were used for different parts of the contribution:

```
Assisted-by: Claude:claude-3-opus coccinelle sparse
Assisted-by: OpenClaw:gemini-3.1-pro-preview
```

**Why it matters:** transparency and attribution for reviewers, appropriate review standards, and a clear audit trail of how each contribution was made.

**Scope:** applies to code changes, configuration files, build scripts, and substantially AI-generated documentation. Exempt: minor typo fixes, pure formatting changes, and changes made entirely without AI assistance.
