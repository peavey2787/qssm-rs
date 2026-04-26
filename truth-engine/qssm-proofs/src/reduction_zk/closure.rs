fn collect_theorem_path_entries(
    architecture_freeze: &FrozenArchitectureSeal,
    assumption_graph: &AssumptionDependencyGraph,
    game_based_proof: &GameBasedZkProof,
    premise_contracts: &[String],
    output_bound: &AdvantageBound,
    theorem_statement: &str,
) -> Vec<(String, String)> {
    let mut entries = vec![
        ("architecture_freeze.statement".to_string(), architecture_freeze.statement.clone()),
        ("game_based_proof.security_definition".to_string(), game_based_proof.security_definition.clone()),
        ("game_based_proof.exact_claim".to_string(), game_based_proof.exact_claim.clone()),
        ("game_based_proof.theorem_statement".to_string(), game_based_proof.theorem_statement.clone()),
        ("game_based_proof.global_simulator.shared_randomness_model".to_string(), game_based_proof.global_simulator.shared_randomness_model.clone()),
        ("closed_theorem.output_bound.expression".to_string(), output_bound.expression.clone()),
        ("closed_theorem.output_bound.justification".to_string(), output_bound.justification.clone()),
        ("closed_theorem.theorem_statement".to_string(), theorem_statement.to_string()),
    ];

    for assumption in &assumption_graph.inputs {
        entries.push((
            format!("assumption_graph.{}", assumption.id.label()),
            assumption.statement.clone(),
        ));
    }
    for contract in premise_contracts {
        entries.push(("closed_theorem.premise_contract".to_string(), contract.clone()));
    }
    for game in &game_based_proof.games {
        entries.push((format!("{} transcript_distribution", game.name), game.transcript_distribution.clone()));
        entries.push((format!("{} theorem_role", game.name), game.theorem_role.clone()));
    }
    for transition in &game_based_proof.transitions {
        entries.push((format!("{} theorem_statement", transition.name), transition.theorem_statement.clone()));
        entries.push((format!("{} explicit_simulator", transition.name), transition.explicit_simulator.clone()));
        entries.push((format!("{} bound.justification", transition.name), transition.bound.justification.clone()));
    }
    entries
}

fn collect_theorem_path_bounds<'a>(
    game_based_proof: &'a GameBasedZkProof,
    output_bound: &'a AdvantageBound,
) -> Vec<(String, &'a AdvantageBound)> {
    let mut bounds = Vec::new();
    for transition in &game_based_proof.transitions {
        bounds.push((transition.name.clone(), &transition.bound));
    }
    bounds.push((
        "game_based_proof.final_bound".to_string(),
        &game_based_proof.final_bound,
    ));
    bounds.push(("closed_theorem.output_bound".to_string(), output_bound));
    bounds
}

fn residual_ms_epsilon_tokens(text: &str) -> Vec<String> {
    let allowed = ["epsilon_ms_hash_binding", "epsilon_ms_rom_programmability"];
    let mut tokens = BTreeSet::new();
    for token in text.split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_')) {
        if token.starts_with("epsilon_ms_") && !allowed.contains(&token) {
            tokens.insert(token.to_string());
        }
    }
    tokens.into_iter().collect()
}

fn validate_exact_ms_simulation_lemmas(
    internal_lemma_chain: &[TheoremLemmaReference],
    issues: &mut Vec<ProofClosureIssue>,
) {
    for lemma in internal_lemma_chain.iter().filter(|lemma| lemma.name.starts_with("MS-")) {
        if lemma.name.starts_with("MS-3") {
            if !lemma.assumption_dependencies.is_empty()
                || lemma.produced_bound_numeric_upper_bound != Some(0.0)
                || lemma.status != ProofStatus::ByConstruction
            {
                issues.push(ProofClosureIssue {
                    kind: ProofClosureIssueKind::ExactSimulationLemmaViolation,
                    location: lemma.name.clone(),
                    detail: format!(
                        "{} must be assumption-free, exact, and by-construction, but found assumptions {:?}, numeric bound {:?}, status {:?}.",
                        lemma.name,
                        lemma.assumption_dependencies,
                        lemma.produced_bound_numeric_upper_bound,
                        lemma.status
                    ),
                });
            }
            if lemma
                .assumption_dependencies
                .iter()
                .any(|dependency| !matches!(dependency, AssumptionId::A1 | AssumptionId::A2))
            {
                issues.push(ProofClosureIssue {
                    kind: ProofClosureIssueKind::ForbiddenMsResidualAssumption,
                    location: lemma.name.clone(),
                    detail: format!(
                        "{} depends on an MS assumption outside A1/A2.",
                        lemma.name
                    ),
                });
            }
        }
    }

    let Some(ms_3a) = internal_lemma_chain.iter().find(|lemma| lemma.name == "MS-3a") else {
        issues.push(ProofClosureIssue {
            kind: ProofClosureIssueKind::ExactSimulationLemmaViolation,
            location: "MS-3a".to_string(),
            detail: "Missing exact bitness simulation lemma MS-3a.".to_string(),
        });
        return;
    };
    let Some(ms_3b) = internal_lemma_chain.iter().find(|lemma| lemma.name == "MS-3b") else {
        issues.push(ProofClosureIssue {
            kind: ProofClosureIssueKind::ExactSimulationLemmaViolation,
            location: "MS-3b".to_string(),
            detail: "Missing true-clause correctness lemma MS-3b.".to_string(),
        });
        return;
    };
    let Some(ms_3c) = internal_lemma_chain.iter().find(|lemma| lemma.name == "MS-3c") else {
        issues.push(ProofClosureIssue {
            kind: ProofClosureIssueKind::ExactSimulationLemmaViolation,
            location: "MS-3c".to_string(),
            detail: "Missing exact comparison simulation lemma MS-3c.".to_string(),
        });
        return;
    };

    if !ms_3a
        .premise_contracts
        .iter()
        .any(|item| item == MS_BITNESS_QUERY_ANNOUNCEMENT_ONLY_CONTRACT)
    {
        issues.push(ProofClosureIssue {
            kind: ProofClosureIssueKind::ExactSimulationLemmaViolation,
            location: "MS-3a".to_string(),
            detail:
                "MS-3a must explicitly require that bitness_query_digest hashes announcements only."
                    .to_string(),
        });
    }
    if !ms_3a
        .premise_contracts
        .iter()
        .any(|item| item == MS_SCHNORR_REPARAMETERIZATION_CONTRACT)
    {
        issues.push(ProofClosureIssue {
            kind: ProofClosureIssueKind::ExactSimulationLemmaViolation,
            location: "MS-3a".to_string(),
            detail: "MS-3a must record the exact Schnorr transcript reparameterization premise."
                .to_string(),
        });
    }
    if !ms_3b
        .premise_contracts
        .iter()
        .any(|item| item == MS_TRUE_CLAUSE_PUBLIC_POINT_CONTRACT)
    {
        issues.push(ProofClosureIssue {
            kind: ProofClosureIssueKind::ExactSimulationLemmaViolation,
            location: "MS-3b".to_string(),
            detail:
                "MS-3b must explicitly require the true-clause public-point characterization P = r * H."
                    .to_string(),
        });
    }
    if !ms_3c
        .premise_contracts
        .iter()
        .any(|item| item == MS_COMPARISON_QUERY_ANNOUNCEMENT_ONLY_CONTRACT)
    {
        issues.push(ProofClosureIssue {
            kind: ProofClosureIssueKind::ExactSimulationLemmaViolation,
            location: "MS-3c".to_string(),
            detail:
                "MS-3c must explicitly require that comparison_query_digest hashes announcements only."
                    .to_string(),
        });
    }
    if !ms_3c.lemma_dependencies.iter().any(|item| item == "MS-3a")
        || !ms_3c.lemma_dependencies.iter().any(|item| item == "MS-3b")
    {
        issues.push(ProofClosureIssue {
            kind: ProofClosureIssueKind::ExactSimulationLemmaViolation,
            location: "MS-3c".to_string(),
            detail: "MS-3c must depend explicitly on MS-3a and MS-3b.".to_string(),
        });
    }
}

fn symbol_closes_recursively(
    symbol: &str,
    bound_map: &BTreeMap<String, Vec<&AdvantageBound>>,
    assumption_terms: &BTreeSet<String>,
    visiting: &mut BTreeSet<String>,
) -> bool {
    if assumption_terms.contains(symbol) {
        return true;
    }

    if !visiting.insert(symbol.to_string()) {
        return false;
    }

    let result = if let Some(bounds) = bound_map.get(symbol) {
        bounds.iter().any(|bound| {
            if bound.numeric_upper_bound.is_some() {
                return true;
            }
            if bound.epsilon_dependencies.is_empty() {
                return assumption_terms.contains(symbol);
            }
            bound.epsilon_dependencies.iter().all(|dep| {
                dep == symbol || symbol_closes_recursively(dep, bound_map, assumption_terms, visiting)
            })
        })
    } else {
        false
    };

    visiting.remove(symbol);
    result
}

fn proof_closure_report_for_closed_theorem(
    architecture_freeze: &FrozenArchitectureSeal,
    assumption_graph: &AssumptionDependencyGraph,
    internal_lemma_chain: &[TheoremLemmaReference],
    game_based_proof: &GameBasedZkProof,
    premise_contracts: &[String],
    output_bound: &AdvantageBound,
    theorem_statement: &str,
) -> ProofClosureReport {
    let mut issues = Vec::new();
    let checked_properties = vec![
        "no empirical metrics in theorem path".to_string(),
        "all lemma assumption dependencies resolve into A1/A2/A4".to_string(),
        "all epsilon terms are defined and bounded".to_string(),
        "composition uses only declared lemma bounds".to_string(),
        "all MS residual terms reduce to A1/A2 or exact simulation".to_string(),
        "architecture freeze seal is active".to_string(),
    ];

    if !architecture_freeze.no_further_structural_changes_allowed {
        issues.push(ProofClosureIssue {
            kind: ProofClosureIssueKind::ArchitectureNotFrozen,
            location: "architecture_freeze".to_string(),
            detail: "The closed theorem requires every architecture component to be frozen and no further structural changes to be allowed.".to_string(),
        });
    }

    let assumption_ids: BTreeSet<_> = assumption_graph.inputs.iter().map(|item| item.id).collect();
    let valid_targets: BTreeSet<_> = internal_lemma_chain
        .iter()
        .map(|item| item.name.clone())
        .collect();

    for edge in &assumption_graph.edges {
        if !assumption_ids.contains(&edge.from) || !valid_targets.contains(&edge.to) {
            issues.push(ProofClosureIssue {
                kind: ProofClosureIssueKind::MissingAssumptionReference,
                location: format!("assumption_graph edge {} -> {}", edge.from.label(), edge.to),
                detail: "The dependency graph references a missing assumption or theorem-internal lemma target.".to_string(),
            });
        }
    }

    for transition in &game_based_proof.transitions {
        for dependency in &transition.assumption_dependencies {
            if !assumption_ids.contains(dependency) {
                issues.push(ProofClosureIssue {
                    kind: ProofClosureIssueKind::MissingAssumptionReference,
                    location: transition.name.clone(),
                    detail: format!(
                        "{} references undeclared assumption {}.",
                        transition.name,
                        dependency.label()
                    ),
                });
            }
        }
    }
    for lemma in internal_lemma_chain {
        for dependency in &lemma.assumption_dependencies {
            if !assumption_ids.contains(dependency) {
                issues.push(ProofClosureIssue {
                    kind: ProofClosureIssueKind::MissingAssumptionReference,
                    location: lemma.name.clone(),
                    detail: format!(
                        "{} references undeclared assumption {}.",
                        lemma.name,
                        dependency.label()
                    ),
                });
            }
        }
    }

    let forbidden_tokens = [
        "empirical",
        "alignment",
        "total_variation",
        "jensen_shannon",
        "divergence",
        "conditional_leakage",
        "simulator_gap",
        "entropy_gap",
    ];
    for (location, text) in collect_theorem_path_entries(
        architecture_freeze,
        assumption_graph,
        game_based_proof,
        premise_contracts,
        output_bound,
        theorem_statement,
    ) {
        let lower = text.to_ascii_lowercase();
        if forbidden_tokens.iter().any(|token| lower.contains(token)) {
            issues.push(ProofClosureIssue {
                kind: ProofClosureIssueKind::EmpiricalReferenceInTheoremPath,
                location: location.clone(),
                detail: text.clone(),
            });
        }
        for token in residual_ms_epsilon_tokens(&text) {
            issues.push(ProofClosureIssue {
                kind: ProofClosureIssueKind::ForbiddenMsResidualAssumption,
                location: location.clone(),
                detail: format!(
                    "The theorem path still references residual MS epsilon term {} beyond A1/A2.",
                    token
                ),
            });
        }
    }

    let theorem_bounds = collect_theorem_path_bounds(game_based_proof, output_bound);
    let mut bound_map: BTreeMap<String, Vec<&AdvantageBound>> = BTreeMap::new();
    for (_, bound) in &theorem_bounds {
        bound_map
            .entry(bound.symbol.clone())
            .or_default()
            .push(*bound);
    }
    let assumption_terms: BTreeSet<_> = assumption_graph
        .inputs
        .iter()
        .flat_map(|item| item.provided_terms.iter().cloned())
        .collect();

    for (location, bound) in &theorem_bounds {
        for token in residual_ms_epsilon_tokens(&bound.symbol) {
            issues.push(ProofClosureIssue {
                kind: ProofClosureIssueKind::ForbiddenMsResidualAssumption,
                location: location.clone(),
                detail: format!(
                    "The theorem bound symbol {} still references residual MS epsilon term {} beyond A1/A2.",
                    bound.symbol,
                    token
                ),
            });
        }
        for token in residual_ms_epsilon_tokens(&bound.expression) {
            issues.push(ProofClosureIssue {
                kind: ProofClosureIssueKind::ForbiddenMsResidualAssumption,
                location: location.clone(),
                detail: format!(
                    "The theorem bound expression {} still references residual MS epsilon term {} beyond A1/A2.",
                    bound.expression,
                    token
                ),
            });
        }
        for dependency in &bound.epsilon_dependencies {
            for token in residual_ms_epsilon_tokens(dependency) {
                issues.push(ProofClosureIssue {
                    kind: ProofClosureIssueKind::ForbiddenMsResidualAssumption,
                    location: location.clone(),
                    detail: format!(
                        "{} still depends on residual MS epsilon term {} beyond A1/A2.",
                        bound.symbol,
                        token
                    ),
                });
            }
            if !bound_map.contains_key(dependency) && !assumption_terms.contains(dependency) {
                issues.push(ProofClosureIssue {
                    kind: ProofClosureIssueKind::UndefinedEpsilonTerm,
                    location: location.clone(),
                    detail: format!(
                        "{} references undefined epsilon term {}.",
                        bound.symbol,
                        dependency
                    ),
                });
            }
        }
    }

    validate_exact_ms_simulation_lemmas(internal_lemma_chain, &mut issues);

    for symbol in bound_map.keys() {
        if !symbol_closes_recursively(symbol, &bound_map, &assumption_terms, &mut BTreeSet::new()) {
            issues.push(ProofClosureIssue {
                kind: ProofClosureIssueKind::UnboundedEpsilonTerm,
                location: symbol.clone(),
                detail: format!(
                    "{} does not close to a leaf assumption-backed or numerically bounded epsilon term.",
                    symbol
                ),
            });
        }
    }

    for transition in &game_based_proof.transitions {
        let produced_by_dependencies: BTreeSet<_> = transition
            .internal_lemma_dependencies
            .iter()
            .filter_map(|dependency_name| {
                internal_lemma_chain
                    .iter()
                    .find(|item| item.name == *dependency_name)
                    .map(|item| item.produced_bound.clone())
            })
            .collect();

        for dependency in &transition.bound.epsilon_dependencies {
            if !produced_by_dependencies.contains(dependency) && !assumption_terms.contains(dependency) {
                issues.push(ProofClosureIssue {
                    kind: ProofClosureIssueKind::CompositionUsesUndeclaredBound,
                    location: transition.name.clone(),
                    detail: format!(
                        "{} consumes {} without declaring a supporting internal lemma output or assumption leaf.",
                        transition.name,
                        dependency
                    ),
                });
            }
        }
    }

    ProofClosureReport {
        closed: issues.is_empty(),
        checked_properties,
        issues,
    }
}
