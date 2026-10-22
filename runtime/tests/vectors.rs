//! Runs the frozen v1-v5 vector suites through the runtime's public surface.

use std::path::PathBuf;

use ccp_runtime::vectors::{run_directory, total_failed};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repository root")
        .to_path_buf()
}

#[test]
fn runs_every_frozen_vector_suite() {
    let directories = [
        "test-vectors",
        "test-vectors/v2",
        "test-vectors/v3",
        "test-vectors/v4",
        "test-vectors/v5",
    ];
    for directory in directories {
        let summary = run_directory(&root().join(directory))
            .unwrap_or_else(|error| panic!("{directory}: {error}"));
        assert_eq!(
            total_failed(&summary),
            0,
            "{directory} failed: {}",
            ccp_kernel::serialize(&summary).unwrap_or_default()
        );
    }
}

#[test]
fn deterministic_grant_id_matches_the_frozen_vector() {
    use ccp_runtime::identity::verify_admission_policy;
    use ccp_runtime::identity::VerifyPolicyOptions;
    use ccp_runtime::model::AdmissionRequest;

    let path = root().join("test-vectors/v4/identity.json");
    let data = ccp_kernel::parse_strict(&std::fs::read_to_string(path).unwrap()).unwrap();
    let admissions = data
        .get("admissions")
        .and_then(ccp_kernel::Value::as_array)
        .expect("admissions");
    for vector in admissions {
        let document = vector
            .get("policy")
            .and_then(ccp_kernel::Value::as_str)
            .unwrap();
        let policy = verify_admission_policy(
            document,
            &VerifyPolicyOptions {
                now: vector
                    .get("verify_now")
                    .and_then(ccp_kernel::Value::as_str)
                    .map(str::to_string),
                expected_host: None,
            },
        )
        .expect("policy");
        let request_value = vector.get("request").expect("request");
        let request = AdmissionRequest {
            requester_key: request_value
                .get("requester_key")
                .and_then(ccp_kernel::Value::as_str)
                .unwrap()
                .to_string(),
            contact_id: request_value
                .get("contact_id")
                .and_then(ccp_kernel::Value::as_str)
                .unwrap()
                .to_string(),
            intent: request_value
                .get("intent")
                .and_then(ccp_kernel::Value::as_str)
                .unwrap()
                .to_string(),
            risk: request_value
                .get("risk")
                .and_then(ccp_kernel::Value::as_str)
                .unwrap()
                .to_string(),
            now: request_value
                .get("now")
                .and_then(ccp_kernel::Value::as_str)
                .unwrap()
                .to_string(),
            destination: request_value
                .get("destination")
                .and_then(ccp_kernel::Value::as_str)
                .map(str::to_string),
        };
        let result = ccp_runtime::admit(&policy, &request, None);
        if result.decision == "allow" {
            let id =
                ccp_runtime::admitted_grant_id(&policy, result.rule_id.as_ref().unwrap(), &request);
            assert!(id.starts_with("pg-"));
            assert_eq!(id.len(), 35);
        }
    }
}
