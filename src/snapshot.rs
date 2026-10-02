//! Cluster network snapshot: everything the analyzers need, captured once.
//!
//! Analysis never talks to the API server directly. It runs over a
//! [`ClusterSnapshot`], which is either collected live or loaded from a JSON
//! file (`diagnose --from-snapshot`). That keeps every check deterministic,
//! unit-testable against fixtures, and usable on air-gapped support bundles.

use k8s_openapi::api::apps::v1::{DaemonSet, Deployment};
use k8s_openapi::api::core::v1::{ConfigMap, Namespace, Node, Pod, Service};
use k8s_openapi::api::discovery::v1::EndpointSlice;
use k8s_openapi::api::networking::v1::NetworkPolicy;
use k8s_openapi::{Metadata, NamespaceResourceScope};
use kube::api::{ListParams, ObjectMeta};
use kube::{Api, Client, Resource};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::path::Path;
use std::time::Duration;

use crate::errors::{NetInspectError, NetInspectResult};

/// Bumped when the on-disk shape changes incompatibly.
pub const SCHEMA_VERSION: u32 = 1;

/// Per-list API timeout during collection.
const LIST_TIMEOUT: Duration = Duration::from_secs(15);

/// Namespace holding the cluster networking add-ons.
const SYSTEM_NAMESPACE: &str = "kube-system";

/// ConfigMaps in `kube-system` that carry network configuration. Only these
/// are collected — never arbitrary ConfigMaps.
const NETWORK_CONFIG_MAPS: &[&str] = &[
    "coredns",
    "kube-proxy",
    "node-local-dns",
    "kube-dns",
    "cilium-config",
];

const LAST_APPLIED: &str = "kubectl.kubernetes.io/last-applied-configuration";
const REDACTED: &str = "<redacted>";

/// A point-in-time capture of the cluster's network-relevant objects.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ClusterSnapshot {
    pub schema_version: u32,
    /// RFC 3339 timestamp of collection.
    pub collected_at: Option<String>,
    /// Namespace the workload objects were scoped to (`None` = cluster-wide).
    pub namespace: Option<String>,
    /// API server `gitVersion`, e.g. `v1.30.4`.
    pub cluster_version: Option<String>,
    pub nodes: Vec<Node>,
    pub namespaces: Vec<Namespace>,
    pub pods: Vec<Pod>,
    pub services: Vec<Service>,
    pub endpoint_slices: Vec<EndpointSlice>,
    pub network_policies: Vec<NetworkPolicy>,
    /// Always cluster-wide (falls back to `kube-system`): CNI agents live here.
    pub daemon_sets: Vec<DaemonSet>,
    /// `kube-system` only: CoreDNS and friends.
    pub deployments: Vec<Deployment>,
    /// `kube-system` network config only (see `NETWORK_CONFIG_MAPS`).
    pub config_maps: Vec<ConfigMap>,
    /// Lists that could not be collected (RBAC, timeout). Analyzers treat the
    /// corresponding data as unknown rather than empty.
    pub collection_errors: Vec<CollectionError>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectionError {
    /// Plural resource name, e.g. `networkpolicies`.
    pub resource: String,
    pub message: String,
}

impl ClusterSnapshot {
    /// Collect a snapshot from a live cluster. Individual list failures are
    /// recorded in `collection_errors` instead of aborting, so a restricted
    /// ServiceAccount still gets a partial diagnosis. Only failing to list
    /// *both* nodes and pods is fatal — nothing useful can be said then.
    pub async fn collect(client: &Client, namespace: Option<&str>) -> NetInspectResult<Self> {
        let mut snap = ClusterSnapshot {
            schema_version: SCHEMA_VERSION,
            collected_at: Some(k8s_openapi::chrono::Utc::now().to_rfc3339()),
            namespace: namespace.map(str::to_string),
            ..Default::default()
        };
        let mut errors = Vec::new();

        // Best-effort: /version is readable by any authenticated user.
        if let Ok(Ok(info)) = tokio::time::timeout(LIST_TIMEOUT, client.apiserver_version()).await {
            snap.cluster_version = Some(info.git_version);
        }

        let (nodes, namespaces, pods, services, slices, policies, daemon_sets, deployments) = tokio::join!(
            list(Api::<Node>::all(client.clone()), "nodes"),
            list(Api::<Namespace>::all(client.clone()), "namespaces"),
            list(scoped::<Pod>(client, namespace), "pods"),
            list(scoped::<Service>(client, namespace), "services"),
            list(scoped::<EndpointSlice>(client, namespace), "endpointslices"),
            list(
                scoped::<NetworkPolicy>(client, namespace),
                "networkpolicies"
            ),
            list(Api::<DaemonSet>::all(client.clone()), "daemonsets"),
            list(
                Api::<Deployment>::namespaced(client.clone(), SYSTEM_NAMESPACE),
                "deployments"
            ),
        );

        let nodes_failed = nodes.is_err();
        let pods_failed = pods.is_err();
        if nodes_failed && pods_failed {
            // Surface the underlying API error (403, connection refused, ...).
            return Err(nodes.err().map(|(_, e)| e).unwrap_or_else(|| {
                NetInspectError::Runtime("failed to list nodes and pods".to_string())
            }));
        }

        snap.nodes = take(nodes, &mut errors);
        snap.namespaces = take(namespaces, &mut errors);
        snap.pods = take(pods, &mut errors);
        snap.services = take(services, &mut errors);
        snap.endpoint_slices = take(slices, &mut errors);
        snap.network_policies = take(policies, &mut errors);
        snap.deployments = take(deployments, &mut errors);

        // Cluster-wide DaemonSet list may be forbidden; kube-system is enough
        // for the mainstream CNIs.
        snap.daemon_sets = match daemon_sets {
            Ok(items) => items,
            Err(_) => take(
                list(
                    Api::<DaemonSet>::namespaced(client.clone(), SYSTEM_NAMESPACE),
                    "daemonsets",
                )
                .await,
                &mut errors,
            ),
        };

        let cm_api = Api::<ConfigMap>::namespaced(client.clone(), SYSTEM_NAMESPACE);
        for name in NETWORK_CONFIG_MAPS {
            match tokio::time::timeout(LIST_TIMEOUT, cm_api.get_opt(name)).await {
                Ok(Ok(Some(cm))) => snap.config_maps.push(cm),
                Ok(Ok(None)) => {}
                Ok(Err(e)) => errors.push(CollectionError {
                    resource: format!("configmaps/{name}"),
                    message: NetInspectError::from(e).plain_message(),
                }),
                Err(_) => errors.push(CollectionError {
                    resource: format!("configmaps/{name}"),
                    message: "timed out".to_string(),
                }),
            }
        }

        snap.collection_errors = errors;
        snap.redact();
        Ok(snap)
    }

    /// Load a snapshot from a JSON file.
    pub fn load(path: &Path) -> NetInspectResult<Self> {
        let raw = std::fs::read_to_string(path).map_err(|e| {
            NetInspectError::Configuration(format!(
                "Cannot read snapshot '{}': {}",
                path.display(),
                e
            ))
        })?;
        Self::from_json(&raw).map_err(|e| match e {
            NetInspectError::InvalidInput(msg) => {
                NetInspectError::InvalidInput(format!("Snapshot '{}': {}", path.display(), msg))
            }
            other => other,
        })
    }

    pub fn from_json(raw: &str) -> NetInspectResult<Self> {
        let snap: ClusterSnapshot = serde_json::from_str(raw)
            .map_err(|e| NetInspectError::InvalidInput(format!("not a valid snapshot: {e}")))?;
        if snap.schema_version > SCHEMA_VERSION {
            return Err(NetInspectError::InvalidInput(format!(
                "schema_version {} is newer than this build supports ({}); upgrade k8s-netinspect",
                snap.schema_version, SCHEMA_VERSION
            )));
        }
        Ok(snap)
    }

    pub fn to_json(&self) -> NetInspectResult<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| NetInspectError::Runtime(format!("Failed to serialize snapshot: {e}")))
    }

    /// True when `resource` (plural name) failed to collect, i.e. its list is
    /// unknown rather than genuinely empty.
    pub fn is_unknown(&self, resource: &str) -> bool {
        self.collection_errors
            .iter()
            .any(|e| e.resource == resource)
    }

    /// Strip data that has no diagnostic value but may carry secrets or bulk:
    /// literal env values, `last-applied-configuration`, and managedFields.
    /// Snapshots are meant to be attached to tickets, so this is always on.
    pub fn redact(&mut self) {
        for pod in &mut self.pods {
            scrub_meta(&mut pod.metadata);
            if let Some(spec) = pod.spec.as_mut() {
                redact_pod_spec(spec);
            }
        }
        for ds in &mut self.daemon_sets {
            scrub_meta(&mut ds.metadata);
            if let Some(spec) = ds.spec.as_mut().and_then(|s| s.template.spec.as_mut()) {
                redact_pod_spec(spec);
            }
        }
        for dep in &mut self.deployments {
            scrub_meta(&mut dep.metadata);
            if let Some(spec) = dep.spec.as_mut().and_then(|s| s.template.spec.as_mut()) {
                redact_pod_spec(spec);
            }
        }
        for n in &mut self.nodes {
            scrub_meta(&mut n.metadata);
        }
        for n in &mut self.namespaces {
            scrub_meta(&mut n.metadata);
        }
        for s in &mut self.services {
            scrub_meta(&mut s.metadata);
        }
        for s in &mut self.endpoint_slices {
            scrub_meta(&mut s.metadata);
        }
        for p in &mut self.network_policies {
            scrub_meta(&mut p.metadata);
        }
        for c in &mut self.config_maps {
            scrub_meta(&mut c.metadata);
        }
    }
}

fn scrub_meta(meta: &mut ObjectMeta) {
    meta.managed_fields = None;
    if let Some(annotations) = meta.annotations.as_mut() {
        annotations.remove(LAST_APPLIED);
    }
}

fn redact_pod_spec(spec: &mut k8s_openapi::api::core::v1::PodSpec) {
    let containers = spec
        .containers
        .iter_mut()
        .chain(spec.init_containers.iter_mut().flatten());
    for c in containers {
        for env in c.env.iter_mut().flatten() {
            if env.value.is_some() {
                env.value = Some(REDACTED.to_string());
            }
        }
    }
    for c in spec.ephemeral_containers.iter_mut().flatten() {
        for env in c.env.iter_mut().flatten() {
            if env.value.is_some() {
                env.value = Some(REDACTED.to_string());
            }
        }
    }
}

fn scoped<K>(client: &Client, namespace: Option<&str>) -> Api<K>
where
    K: Resource<Scope = NamespaceResourceScope> + Metadata<Ty = ObjectMeta>,
    <K as Resource>::DynamicType: Default,
{
    match namespace {
        Some(ns) => Api::namespaced(client.clone(), ns),
        None => Api::all(client.clone()),
    }
}

async fn list<K>(
    api: Api<K>,
    resource: &'static str,
) -> Result<Vec<K>, (&'static str, NetInspectError)>
where
    K: Resource + Clone + DeserializeOwned + Debug,
{
    match tokio::time::timeout(LIST_TIMEOUT, api.list(&ListParams::default())).await {
        Ok(Ok(l)) => Ok(l.items),
        Ok(Err(e)) => Err((resource, NetInspectError::from(e))),
        Err(_) => Err((
            resource,
            NetInspectError::Timeout(format!(
                "Listing {} timed out after {} seconds",
                resource,
                LIST_TIMEOUT.as_secs()
            )),
        )),
    }
}

fn take<K>(
    result: Result<Vec<K>, (&'static str, NetInspectError)>,
    errors: &mut Vec<CollectionError>,
) -> Vec<K> {
    match result {
        Ok(items) => items,
        Err((resource, e)) => {
            errors.push(CollectionError {
                resource: resource.to_string(),
                message: e.plain_message(),
            });
            Vec::new()
        }
    }
}
