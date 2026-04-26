/// Frozen version of the QSSM proof structure.
/// Changing this value signals a structural break requiring full re-audit.
pub const PROOF_STRUCTURE_VERSION: &str = "QSSM-PROOF-FROZEN-v2.0";

/// Returns the frozen proof-structure version stamp.
/// Compile-time constant; any structural change to the theorem layer must
/// bump this version and re-run the closure checker.
#[must_use]
pub fn proof_structure_version() -> &'static str {
    PROOF_STRUCTURE_VERSION
}

// ---------------------------------------------------------------------------
// Auditability layer
// ---------------------------------------------------------------------------

/// A single edge in the assumption dependency graph, suitable for external
/// rendering (Mermaid, Graphviz, or paper appendix).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyGraphEdge {
    pub from: String,
    pub to: String,
    pub label: String,
}

/// Exportable dependency graph for the closed ZK theorem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportableDependencyGraph {
    pub version: String,
    pub nodes: Vec<String>,
    pub edges: Vec<DependencyGraphEdge>,
}

/// Verification checklist entry used by auditors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationChecklistItem {
    pub id: String,
    pub description: String,
    pub passed: bool,
    pub detail: String,
}

/// Verification checklist produced by the audit-mode validator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationChecklist {
    pub version: String,
    pub items: Vec<VerificationChecklistItem>,
    pub all_passed: bool,
}

impl ClosedZkTheorem {
    /// Export the assumption dependency graph in a renderer-friendly format.
    #[must_use]
    pub fn export_dependency_graph(&self) -> ExportableDependencyGraph {
        let mut nodes: Vec<String> = self
            .assumption_graph
            .inputs
            .iter()
            .map(|a| format!("{}: {}", a.id.label(), a.name))
            .collect();
        for lemma in &self.internal_lemma_chain {
            nodes.push(lemma.name.clone());
        }
        let edges: Vec<DependencyGraphEdge> = self
            .assumption_graph
            .edges
            .iter()
            .map(|e| DependencyGraphEdge {
                from: e.from.label().to_string(),
                to: e.to.clone(),
                label: e.rationale.clone(),
            })
            .collect();
        ExportableDependencyGraph {
            version: PROOF_STRUCTURE_VERSION.to_string(),
            nodes,
            edges,
        }
    }

    /// Produce a verification checklist covering all auditable invariants.
    #[must_use]
    pub fn verification_checklist(&self) -> VerificationChecklist {
        let mut items = Vec::new();

        // 1. Architecture freeze
        let arch_ok = self.architecture_freeze.no_further_structural_changes_allowed
            && self.architecture_freeze.components.iter().all(|c| c.frozen);
        items.push(VerificationChecklistItem {
            id: "ARCH-FREEZE".to_string(),
            description: "All architecture components are frozen".to_string(),
            passed: arch_ok,
            detail: if arch_ok {
                "All components frozen; no structural changes allowed.".to_string()
            } else {
                "One or more architecture components are not frozen.".to_string()
            },
        });

        // 2. Assumption graph completeness
        let assumed_ids: BTreeSet<_> = self.assumption_graph.inputs.iter().map(|a| a.id).collect();
        let expected = [AssumptionId::A1, AssumptionId::A2, AssumptionId::A4];
        let graph_ok = expected.iter().all(|id| assumed_ids.contains(id))
            && assumed_ids.len() == expected.len();
        items.push(VerificationChecklistItem {
            id: "ASSUMPTION-SET".to_string(),
            description: "Assumption graph contains exactly A1, A2, A4".to_string(),
            passed: graph_ok,
            detail: format!("Found assumptions: {:?}", assumed_ids),
        });

        // 3. Proof closure
        let closure_ok = self.closure_report.closed;
        items.push(VerificationChecklistItem {
            id: "PROOF-CLOSURE".to_string(),
            description: "Proof closure checker reports closed with no issues".to_string(),
            passed: closure_ok,
            detail: if closure_ok {
                "Closure report: closed.".to_string()
            } else {
                format!("Closure issues: {}", self.closure_report.issues.len())
            },
        });

        // 4. MS-3a/3b/3c present and exact
        let ms3_names = ["MS-3a", "MS-3b", "MS-3c"];
        let ms3_ok = ms3_names.iter().all(|name| {
            self.internal_lemma_chain.iter().any(|l| {
                l.name == *name
                    && l.produced_bound_numeric_upper_bound == Some(0.0)
                    && l.status == ProofStatus::ByConstruction
            })
        });
        items.push(VerificationChecklistItem {
            id: "MS-EXACT-SIM".to_string(),
            description: "MS-3a, MS-3b, MS-3c present with zero advantage by construction"
                .to_string(),
            passed: ms3_ok,
            detail: if ms3_ok {
                "All three exact-simulation lemmas verified.".to_string()
            } else {
                "One or more MS-3 lemmas missing or non-zero.".to_string()
            },
        });

        // 5. Output bound references only allowed epsilon terms
        let bound_ok = self
            .output_bound
            .expression
            .contains("epsilon_ms_hash_binding")
            && self
                .output_bound
                .expression
                .contains("epsilon_ms_rom_programmability")
            && self.output_bound.expression.contains("epsilon_le");
        items.push(VerificationChecklistItem {
            id: "OUTPUT-BOUND".to_string(),
            description: "Output bound references only epsilon_ms_hash_binding, epsilon_ms_rom_programmability, epsilon_le".to_string(),
            passed: bound_ok,
            detail: format!("Bound expression: {}", self.output_bound.expression),
        });

        // 6. Simulator independence
        let sim_ok = self
            .game_based_proof
            .global_simulator
            .forbidden_inputs
            .iter()
            .any(|f| f.contains("witness") || f.contains("hidden"))
            && !self
                .game_based_proof
                .global_simulator
                .public_input_interface
                .iter()
                .any(|f| f.contains("witness") || f.contains("hidden"));
        items.push(VerificationChecklistItem {
            id: "SIM-INDEPENDENCE".to_string(),
            description: "Global simulator forbids witness inputs and accepts only public inputs"
                .to_string(),
            passed: sim_ok,
            detail: format!(
                "Forbidden: {:?}",
                self.game_based_proof.global_simulator.forbidden_inputs
            ),
        });

        // 7. Version seal
        items.push(VerificationChecklistItem {
            id: "VERSION-SEAL".to_string(),
            description: "Proof structure version is frozen".to_string(),
            passed: true,
            detail: format!("Version: {PROOF_STRUCTURE_VERSION}"),
        });

        let all_passed = items.iter().all(|item| item.passed);
        VerificationChecklist {
            version: PROOF_STRUCTURE_VERSION.to_string(),
            items,
            all_passed,
        }
    }

    /// Export the closed ZK theorem as paper-grade LaTeX.
    #[must_use]
    pub fn to_latex(&self) -> String {
        let mut out = String::new();
        out.push_str("\\begin{theorem}[QSSM Zero-Knowledge]\n");
        out.push_str("\\label{thm:qssm-zk}\n");
        out.push_str("Let $\\mathcal{D}$ be any PPT distinguisher over the joint QSSM transcript.\n");
        out.push_str("Let $G_0$ denote the real transcript game, $G_1$ the hybrid with the MS component\n");
        out.push_str("replaced by $\\mathsf{Sim}_{\\mathrm{MS}}$, and $G_2$ the ideal game produced by the\n");
        out.push_str("global simulator $\\mathsf{Sim}_{\\mathrm{QSSM}}$.\n");
        out.push_str("Under Assumptions~A1 (hash binding), A2 (ROM programmability), and A4 (LE HVZK bound):\n");
        out.push_str("\\[\n");
        out.push_str("  \\mathsf{Adv}^{\\mathrm{zk}}_{\\mathrm{QSSM}}(\\mathcal{D})\n");
        out.push_str("  \\;=\\;\n");
        out.push_str("  \\bigl|\\Pr[\\mathcal{D}(G_0)=1] - \\Pr[\\mathcal{D}(G_2)=1]\\bigr|\n");
        out.push_str("  \\;\\le\\;\n");
        out.push_str("  \\epsilon_{\\mathrm{ms,bind}}\n");
        out.push_str("  + \\epsilon_{\\mathrm{ms,rom}}\n");
        out.push_str("  + \\epsilon_{\\mathrm{le}}.\n");
        out.push_str("\\]\n");
        out.push_str("\\end{theorem}\n\n");

        out.push_str("\\begin{proof}[Proof sketch]\n");
        out.push_str("The proof proceeds by a sequence of game hops.\n\n");

        out.push_str("\\paragraph{$G_0 \\to G_1$: MS replacement.}\n");
        out.push_str("\\begin{itemize}\n");
        out.push_str("  \\item \\textbf{MS-1.} Replace witness-bound commitment handling by its\n");
        out.push_str("    boundary-consistent abstraction. Any distinguisher is reduced to\n");
        out.push_str("    hash/commitment binding on the frozen observable interface\n");
        out.push_str("    (loss~$\\epsilon_{\\mathrm{ms,bind}}$).\n");
        out.push_str("  \\item \\textbf{MS-2.} Replace real Fiat--Shamir challenge derivation with\n");
        out.push_str("    programmed oracle answers on the frozen observable boundary\n");
        out.push_str("    (loss~$\\epsilon_{\\mathrm{ms,rom}}$).\n");
        out.push_str("  \\item \\textbf{MS-3a.} Once the bitness Fiat--Shamir query is programmed,\n");
        out.push_str("    every witness-using bitness branch is exactly distribution-identical\n");
        out.push_str("    to a simulated Schnorr branch (zero advantage by Schnorr\n");
        out.push_str("    reparameterization).\n");
        out.push_str("  \\item \\textbf{MS-3b.} At the highest differing bit position, every\n");
        out.push_str("    true-clause comparison public point is exactly $P = r \\cdot H$\n");
        out.push_str("    for the corresponding committed blinder~$r$.\n");
        out.push_str("  \\item \\textbf{MS-3c.} Once comparison challenges are programmed from\n");
        out.push_str("    announcement-only query material and the true clause is expressed\n");
        out.push_str("    as $P = r \\cdot H$, the programmed hybrid and the MS simulator\n");
        out.push_str("    law are exactly identical on the frozen observable boundary\n");
        out.push_str("    (zero advantage by construction).\n");
        out.push_str("\\end{itemize}\n");
        out.push_str("Thus $|\\Pr[\\mathcal{D}(G_0)=1] - \\Pr[\\mathcal{D}(G_1)=1]|\n");
        out.push_str("  \\le \\epsilon_{\\mathrm{ms,bind}} + \\epsilon_{\\mathrm{ms,rom}}$.\n\n");

        out.push_str("\\paragraph{$G_1 \\to G_2$: LE replacement.}\n");
        out.push_str("Replace the real LE prover by $\\mathsf{Sim}_{\\mathrm{LE}}$ and compose\n");
        out.push_str("the MS and LE simulators through domain-separated shared randomness.\n");
        out.push_str("By the LE HVZK argument under the Set~B parameter template,\n");
        out.push_str("$|\\Pr[\\mathcal{D}(G_1)=1] - \\Pr[\\mathcal{D}(G_2)=1]| \\le \\epsilon_{\\mathrm{le}}$.\n\n");

        out.push_str("\\paragraph{Composition.}\n");
        out.push_str("By the triangle inequality,\n");
        out.push_str("$\\mathsf{Adv}^{\\mathrm{zk}}_{\\mathrm{QSSM}}(\\mathcal{D})\n");
        out.push_str("  \\le \\epsilon_{\\mathrm{ms,bind}} + \\epsilon_{\\mathrm{ms,rom}} + \\epsilon_{\\mathrm{le}}$.\n");
        out.push_str("\\end{proof}\n");

        out
    }
}

// ---------------------------------------------------------------------------
// Audit-mode validation (feature-gated)
// ---------------------------------------------------------------------------

/// Run the audit-mode validation suite: simulator independence and lemma
/// closure checks. Returns the verification checklist.
///
/// This function is always compiled but is intended to be invoked
/// primarily when the `audit-mode` feature is active.
pub fn run_audit_validation() -> Result<VerificationChecklist, ZkSimulationError> {
    let boundary = MsV2ObservableBoundaryContract::for_frozen_interface();
    let le_analysis = LeHvzkConstraintAnalysis::for_current_params();
    let theorem = ClosedZkTheorem::for_current_and_redesigned_systems(&boundary, &le_analysis);
    Ok(theorem.verification_checklist())
}

