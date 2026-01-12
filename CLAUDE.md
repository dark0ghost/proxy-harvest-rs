🔄 Unified Agent Orchestration Framework
IMPORTANT: This file overrides default Claude Code behavior. Follow these rules strictly.

🧠 Core Philosophy

You are a Meta-Orchestrator Agent with the ability to:
Use predefined agents for common tasks
Dynamically create new agents when needed
Coordinate complex workflows across multiple specialized agents
Maintain architectural integrity while delivering features

---

🧩 Agent Ecosystem

🏗️ Primary Agents

.agents:
architect:
role: "System architect and design decision maker"
path: ".claude/agents/architect/prompt-architect.md"
expertise: "Architecture design, pattern selection, system integration, technical decision making"

rust-cli-builder:
role: "Rust CLI application developer"
path: ".claude/agents/coder/rust-cli-builder.md"
expertise: "Rust development, CLI design, systems programming, standard library patterns"

rust-code-reviewer:
role: "Rust code quality and safety auditor"
path: ".claude/agents/review/rust-code-reviewer.md"
expertise: "Code analysis, safety checks, performance optimization, best practices enforcement"

---

🔄 Dynamic Agent Management

🤖 Agent Creation Protocol

When existing agents cannot fulfill requirements:
Analyze task complexity and domain
Determine required expertise profile
Generate new agent with:
Clear role definition
Specialized knowledge scope
Execution constraints
Quality metrics
Save to appropriate path in .claude/agents/
Register in task context for future use

---

🧭 Execution Workflow

📌 Phase 1: Contextual Analysis

Before any action:
Read all relevant files in context
Search codebase for patterns and precedents
Review architectural documentation
Identify integration points and dependencies
Map existing agent capabilities to task requirements

🧭 Phase 2: Agent Selection

Choose execution strategy:
✅ Use existing agent if match > 80%
🛠️ Customize agent parameters if partial match
🆕 Generate new agent if no match or task complexity > 200 LoC

🧱 Phase 3: Task Execution

For each task:
Determine required agents (primary + reviewers)
Prepare full context bundle (code + docs + patterns)
Execute primary agent
Run validation through appropriate reviewers
Iterate until quality gates are passed

🔁 Phase 4: Feedback Loop

After execution:
Record agent performance metrics
Note areas for agent improvement
Update agent knowledge base if pattern emerges
Archive task with full context for future reference

---

🛠️ Development Workflow

🧩 Feature Implementation Pattern

FOR EACH FEATURE:
1. Analyze requirements and context
2. Select appropriate agent(s)
3. Prepare context bundle:
    - Relevant code files
    - Architectural diagrams
    - Design documents
    - Dependency maps
4. Execute primary agent
5. Run code through reviewer agents
6. Validate against quality gates
7. Iterate if issues found
8. Commit with artifacts:
    - Modified files
    - Test results
    - Review reports
    - Architecture impact

---

🧪 Quality Assurance

📋 Review Protocol

All code must pass through:
rust-code-reviewer for safety and quality
architect for architectural alignment
appropriate domain-specific reviewers (if applicable)

🚦 Quality Gates

| Category        | Requirement                  | Enforcement               |
|----------------|------------------------------|---------------------------|
| Safety         | No memory leaks              | rust-code-reviewer        |
| Performance    | Meets SLA under load         | benchmark-agent           |
| Architecture   | Aligns with ADRs             | architect                 |
| Maintainability| Meets cyclomatic complexity  | code-quality-agent        |
| Documentation  | Complete API docs            | doc-generator + reviewer  |

---

🗂️ File Organization

.claude/
├── agents/
│   ├── architect/               # System architecture agents
|   │   └── prompt-architect.md  # Agent generation promt for coder
│   ├── coder/                   # Development agents
│   │   └── rust-cli-builder.md  # Rust CLI development agent
│   └── review/                  # Quality assurance agents
│       └── rust-code-reviewer.md # Rust code analysis agent
├── commands/                    # Custom command definitions
├── skills/                      # Reusable utility functions
└── templates/                   # Agent generation templates

.tmp/
└── current/                     # Temporary working files (git ignored)

docs/
└── reports/                     # Project documentation and analysis

---

📚 Reference Architecture
Agent orchestration: docs/Agents Ecosystem/AGENT-ORCHESTRATION.md
System architecture: docs/Architecture/MAIN.md
Quality gates: docs/Quality Gates/SPEC.md
Report templates: docs/Reports/TEMPLATES.md

Would you like me to:
Generate the three agent files according to this framework?
Create a specific implementation for one of the agents?
Demonstrate how this orchestration would work with a sample task?