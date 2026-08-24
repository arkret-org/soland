use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;

const GUARDED_PACKAGES: &[&str] = &[
    "soland",
    "soland-http",
    "soland-services",
    "soland-storage-postgres",
    "soland-storage-memory",
    "soland-storage",
    "soland-domain",
    "soland-contracts",
];

const ALLOWED: &[(&str, &str)] = &[
    ("soland", "soland-http"),
    ("soland", "soland-services"),
    ("soland", "soland-storage-postgres"),
    ("soland-http", "soland-services"),
    ("soland-http", "soland-contracts"),
    ("soland-http", "arkret-sdk"),
    ("soland-services", "soland-domain"),
    ("soland-services", "soland-storage"),
    ("soland-services", "arkret-sdk"),
    ("soland-storage-postgres", "soland-storage"),
    ("soland-storage-memory", "soland-storage"),
    ("soland-storage", "soland-domain"),
    ("soland-storage", "arkret-sdk"),
    ("soland-domain", "arkret-sdk"),
    ("soland-contracts", "arkret-sdk"),
];

const BANNED: &[(&str, &[&str])] = &[
    (
        "soland-domain",
        &[
            "salvo",
            "diesel",
            "diesel-async",
            "tokio",
            "reqwest",
            "object_store",
        ],
    ),
    ("soland-storage", &["salvo", "diesel", "diesel-async"]),
    ("soland-storage-memory", &["diesel", "diesel-async"]),
    (
        "soland-services",
        &[
            "salvo",
            "diesel",
            "diesel-async",
            "object_store",
            "deadpool",
        ],
    ),
    (
        "soland-http",
        &["diesel", "diesel-async", "tokio-postgres", "object_store"],
    ),
];

fn main() {
    let output = Command::new(env!("CARGO"))
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .output()
        .expect("failed to run cargo metadata");
    if !output.status.success() {
        eprintln!(
            "cargo metadata failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        std::process::exit(1);
    }

    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("cargo metadata returned invalid JSON");
    let packages = metadata["packages"]
        .as_array()
        .expect("cargo metadata did not contain packages");
    let workspace_names = packages
        .iter()
        .filter_map(|package| package["name"].as_str())
        .collect::<BTreeSet<_>>();
    let guarded = GUARDED_PACKAGES.iter().copied().collect::<BTreeSet<_>>();
    let allowed = ALLOWED.iter().copied().collect::<BTreeSet<_>>();
    let mut graph = BTreeMap::<String, BTreeSet<String>>::new();
    let mut errors = Vec::new();

    for package in packages {
        let name = package["name"]
            .as_str()
            .expect("package name must be a string");
        if !guarded.contains(name) {
            continue;
        }
        graph.entry(name.to_owned()).or_default();
        let dependencies = package["dependencies"]
            .as_array()
            .expect("package dependencies must be an array");
        for dependency in dependencies {
            if dependency["kind"]
                .as_str()
                .is_some_and(|kind| kind != "normal")
            {
                continue;
            }
            let dependency_name = dependency["name"]
                .as_str()
                .expect("dependency name must be a string");
            let dependency_package = dependency["rename"].as_str().unwrap_or(dependency_name);
            if workspace_names.contains(dependency_package) && guarded.contains(dependency_package)
            {
                graph
                    .entry(name.to_owned())
                    .or_default()
                    .insert(dependency_package.to_owned());
                if !allowed.contains(&(name, dependency_package)) {
                    errors.push(format!(
                        "illegal workspace dependency: {name} -> {dependency_package}"
                    ));
                }
            }
            if BANNED
                .iter()
                .find(|(package_name, _)| *package_name == name)
                .is_some_and(|(_, banned)| banned.contains(&dependency_package))
            {
                errors.push(format!("banned dependency: {name} -> {dependency_package}"));
            }
        }
    }

    let mut visited = BTreeSet::new();
    let mut active = BTreeSet::new();
    let mut path = Vec::new();
    for node in graph.keys() {
        detect_cycle(
            node,
            &graph,
            &mut visited,
            &mut active,
            &mut path,
            &mut errors,
        );
    }

    if errors.is_empty() {
        println!("layering check passed");
    } else {
        for error in errors {
            eprintln!("{error}");
        }
        std::process::exit(1);
    }
}

fn detect_cycle(
    node: &str,
    graph: &BTreeMap<String, BTreeSet<String>>,
    visited: &mut BTreeSet<String>,
    active: &mut BTreeSet<String>,
    path: &mut Vec<String>,
    errors: &mut Vec<String>,
) {
    if visited.contains(node) {
        return;
    }
    if !active.insert(node.to_owned()) {
        if let Some(start) = path.iter().position(|entry| entry == node) {
            let mut cycle = path[start..].to_vec();
            cycle.push(node.to_owned());
            errors.push(format!(
                "workspace dependency cycle: {}",
                cycle.join(" -> ")
            ));
        }
        return;
    }

    path.push(node.to_owned());
    if let Some(edges) = graph.get(node) {
        for next in edges {
            detect_cycle(next, graph, visited, active, path, errors);
        }
    }
    path.pop();
    active.remove(node);
    visited.insert(node.to_owned());
}
