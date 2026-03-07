# 🔄 Agent Framework for Proxy Harvest RS

Adapted specialized agent system for working with Rust CLI projects.

---

## 🧠 Meta-Orchestrator

**Role:** Task coordinator and workflow manager

**Capabilities:**
- Requirements analysis and task decomposition
- Selection and activation of specialized agents
- Coordination of multi-step workflows
- Quality control through reviewer agents
- Context management between execution steps

**Workflow:**
```
1. Task Analysis → 2. Agent Selection → 3. Execution → 4. Review → 5. Feedback
```

---

## 🏗️ Specialized Agents

### 1. Architect Agent

**Role:** System architect and designer

**Expertise:**
- Rust project architecture design
- Pattern selection and best practices
- Dependency and integration analysis
- Technical decision making

**When to use:**
- Adding new functionality (>200 LoC)
- Module refactoring
- Project structure changes
- Selecting new dependencies

**Activation commands:**
```
/architect <task description>
@architect analyze parser.rs architecture
```

**Deliverables:**
- Component diagrams
- API specifications
- Implementation plan
- List of affected files

---

### 2. Rust CLI Builder Agent

**Role:** Rust CLI application developer

**Expertise:**
- Rust 2021 edition, idiomatic code
- CLI parsing with clap
- Error handling (anyhow, thiserror)
- Async programming (tokio, async/await)
- HTTP clients (reqwest)
- Serialization (serde, serde_json)
- Parsing (regex, base64)
- Parallelism (rayon)

**When to use:**
- Writing new code
- Modifying existing modules
- Bug fixes
- Adding tests
- Function refactoring

**Activation commands:**
```
/builder <coding task>
@builder implement function for X
@builder fix error in Y
```

**Code standards:**
- Use `anyhow::Result` for errors
- Logging via `log` crate
- Avoid `.unwrap()` in production code
- Document public APIs
- Write tests for new functionality

---

### 3. Rust Code Reviewer Agent

**Role:** Security and code quality auditor

**Expertise:**
- Memory safety and ownership
- Error handling
- Performance optimization
- Rust idioms and best practices
- Anti-pattern detection

**When to use:**
- After writing code (before commit)
- After refactoring
- When modifying critical modules
- Before release

**Activation commands:**
```
/review <file or code>
@reviewer check src/parser.rs
@reviewer analyze changes
```

**Review checklist:**

| Category | Criterion | Status |
|----------|-----------|--------|
| 🔴 Safety | No memory leaks, unsafe justified | ☐ |
| 🟠 Errors | Proper error handling, context | ☐ |
| 🟡 Performance | No extra allocations, clones | ☐ |
| 🟢 Style | Idiomatic Rust, naming conventions | ☐ |
| 📚 Docs | Public APIs documented | ☐ |
| 🧪 Tests | Tests cover new logic | ☐ |

**Report format:**
```markdown
## REVIEW SUMMARY
- Overall assessment: [Excellent/Good/Fair/Poor]
- Critical issues: X
- Recommendations: Y

## FINDINGS
### [SEVERITY] Issue Title
- **Location:** file:line
- **Description:** ...
- **Impact:** ...
- **Recommendation:** ...
```

---

### 4. Doc Writer Agent

**Role:** Technical documentation specialist

**Expertise:**
- Rustdoc conventions
- API documentation with examples
- Module-level documentation
- Crate-level documentation
- docs.rs standards
- Markdown formatting

**When to use:**
- Creating new documentation
- Updating API docs
- Writing README
- Adding usage examples

**Activation commands:**
```
/docs <what to document>
@docwriter write documentation for X
@docwriter update README
```

**Documentation standards:**

```rust
/// Brief one-line summary
///
/// Detailed description explaining functionality,
/// behavior, and important considerations.
///
/// # Arguments
///
/// * `param1` - parameter description
///
/// # Returns
///
/// What the function returns
///
/// # Errors
///
/// This function returns an error if:
/// - Condition 1
/// - Condition 2
///
/// # Examples
///
/// ```
/// use proxy_harvest_rs::parser;
///
/// let result = parser::parse_servers("ss://...")?;
/// ```
pub fn function_name(param1: Type1) -> Result<Type2> {
    // ...
}
```

**Quality checklist:**
- [ ] Crate has documentation in lib.rs
- [ ] All public modules documented
- [ ] All public functions have doc comments
- [ ] Parameters described in `# Arguments`
- [ ] Return value in `# Returns`
- [ ] Errors in `# Errors`
- [ ] At least one example per function
- [ ] Examples compile (`cargo test --doc`)
- [ ] No `missing_docs` warnings

---

### 5. Doc Reviewer Agent

**Role:** Documentation quality assurance

**Expertise:**
- Documentation accuracy validation
- Rustdoc standards compliance
- Code example testing
- Link and cross-reference checking
- Readability analysis

**When to use:**
- After writing documentation
- Before docs.rs publication
- When updating API
- For auditing existing documentation

**Activation commands:**
```
/doc-review <file or module>
@docreviewer check documentation
@docreviewer validate examples
```

**Automated checks:**
```bash
# Build documentation
cargo doc --no-deps --all-features

# Test examples
cargo test --doc

# Check missing_docs
cargo rustdoc -- -D missing-docs
```

**Report format:**
```markdown
# Documentation Review Report

## Coverage Analysis
| Category | Total | Documented | % |
|----------|-------|------------|---|
| Modules  | X     | Y          | Z%|
| Functions| A     | B          | C%|

## Issues Found
### Critical
1. [File:Line] Missing docs for public function

### Major
1. [Module] Missing module-level documentation

## Validation
- Build: ✅ PASS
- Doc tests: ✅ PASSED
- Links: ✅ VALID
```

---

## 🔄 Workflow Patterns

### Pattern 1: Adding Functionality

```
1. @architect — design solution
2. @builder — implement code
3. @reviewer — review code
4. @docwriter — write documentation
5. @docreviewer — validate documentation
6. Commit with artifacts
```

### Pattern 2: Module Refactoring

```
1. @architect — analyze architecture impact
2. @builder — perform refactoring
3. @reviewer — safety check
4. @docwriter — update documentation
5. Tests: cargo test
6. Commit
```

### Pattern 3: Bug Fix

```
1. @builder — analyze and fix
2. @reviewer — verify fix
3. @builder — add regression test
4. Commit with bug description
```

### Pattern 4: API Documentation

```
1. @docwriter — write documentation
2. @docreviewer — validate
3. @builder — fix issues (if needed)
4. cargo doc --open for verification
5. Commit
```

---

## 🧪 Quality Gates

All changes must pass:

| Gate | Requirement | Check |
|------|-------------|-------|
| Build | Compilation without errors | `cargo build` |
| Clippy | No warnings | `cargo clippy -- -D warnings` |
| Format | Formatted code | `cargo fmt --check` |
| Tests | All tests pass | `cargo test` |
| Docs | No missing_docs | `cargo rustdoc -- -D missing-docs` |
| Review | Approved by reviewer | @reviewer sign-off |

---

## 📂 Commit Artifacts

Each commit should include:

```
<brief description>

<detailed description>

Artifacts:
- Modified files: src/...
- Tests: tests/... or #[cfg(test)]
- Documentation: doc comments
- Review: report from @reviewer
```

---

## 🎯 Agent Activation

### Via commands (if configured):
```bash
/architect <task>
/builder <task>
/review <code>
/docs <task>
/doc-review <documentation>
```

### Via direct requests:
```
@architect design system for X
@builder implement function Y
@reviewer check this code: <code>
@docwriter write documentation for Z
@docreviewer validate documentation
```

### Via Task tool (for complex tasks):
```
[Using task tool to delegate to sub-agents]
```

---

## 📊 Agent Performance Metrics

| Metric | Description | Target |
|--------|-------------|--------|
| First Pass Rate | % tasks without iterations | >80% |
| Review Issues | Average number of findings | <3 |
| Doc Coverage | % documented APIs | 100% |
| Test Coverage | % test coverage | >80% |
| Build Success | % successful builds | 100% |

---

## 🔄 Feedback Loop

After each task:

1. **Record metrics** — time, iterations, quality
2. **Update context** — new patterns, decisions
3. **Archive** — save context for future reference
4. **Improve** — adjust approaches

---

## 📚 Resources

- [Rust Book](https://doc.rust-lang.org/book/)
- [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- [Rustdoc Book](https://doc.rust-lang.org/rustdoc/)
- [Clippy Lints](https://rust-lang.github.io/rust-clippy/)
- [docs.rs](https://docs.rs/)

---

*Version: 1.0 | Adapted for proxy-harvest-rs | 2026-03-07*
