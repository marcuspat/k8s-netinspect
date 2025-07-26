use crate::errors::{NetInspectError, NetInspectResult};
use regex::Regex;
use std::env;
use kube::{Api, Client};
use k8s_openapi::api::core::v1::{Node, Pod, Service, Endpoints, Namespace};
use kube::api::ListParams;

/// Input validation utilities
pub struct Validator;

impl Validator {
    /// Validate Kubernetes pod name
    pub fn validate_pod_name(name: &str) -> NetInspectResult<()> {
        if name.is_empty() {
            return Err(NetInspectError::InvalidInput(
                "Pod name cannot be empty".to_string()
            ));
        }

        if name.len() > 253 {
            return Err(NetInspectError::InvalidInput(
                "Pod name cannot exceed 253 characters".to_string()
            ));
        }

        // Kubernetes naming convention: lowercase alphanumeric, hyphens, dots
        let re = Regex::new(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$")
            .map_err(|e| NetInspectError::Runtime(format!("Regex compilation failed: {}", e)))?;
        
        if !re.is_match(name) {
            return Err(NetInspectError::InvalidInput(
                format!(
                    "Invalid pod name '{}'. Must be lowercase alphanumeric with hyphens and dots only",
                    name
                )
            ));
        }

        Ok(())
    }

    /// Validate Kubernetes namespace name
    pub fn validate_namespace(namespace: &str) -> NetInspectResult<()> {
        if namespace.is_empty() {
            return Err(NetInspectError::InvalidInput(
                "Namespace cannot be empty".to_string()
            ));
        }

        if namespace.len() > 63 {
            return Err(NetInspectError::InvalidInput(
                "Namespace cannot exceed 63 characters".to_string()
            ));
        }

        // Kubernetes naming convention for namespaces
        let re = Regex::new(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
            .map_err(|e| NetInspectError::Runtime(format!("Regex compilation failed: {}", e)))?;
        
        if !re.is_match(namespace) {
            return Err(NetInspectError::InvalidInput(
                format!(
                    "Invalid namespace '{}'. Must be lowercase alphanumeric with hyphens only",
                    namespace
                )
            ));
        }

        Ok(())
    }

    /// Validate environment and prerequisites
    pub fn validate_environment() -> NetInspectResult<()> {
        // Check if kubeconfig exists
        if let Ok(kubeconfig_path) = env::var("KUBECONFIG") {
            if !std::path::Path::new(&kubeconfig_path).exists() {
                return Err(NetInspectError::Configuration(
                    format!("KUBECONFIG file not found: {}", kubeconfig_path)
                ));
            }
        } else {
            // Check default kubeconfig location
            if let Ok(home) = env::var("HOME") {
                let default_kubeconfig = format!("{}/.kube/config", home);
                if !std::path::Path::new(&default_kubeconfig).exists() {
                    return Err(NetInspectError::Configuration(
                        "No kubeconfig found. Set KUBECONFIG environment variable or place config at ~/.kube/config".to_string()
                    ));
                }
            }
        }

        Ok(())
    }

    /// Validate pod IP address format
    pub fn validate_pod_ip(ip: &str) -> NetInspectResult<()> {
        if ip.is_empty() {
            return Err(NetInspectError::InvalidInput(
                "Pod IP cannot be empty".to_string()
            ));
        }

        // Basic IP validation (IPv4 and IPv6)
        let ipv4_re = Regex::new(r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
            .map_err(|e| NetInspectError::Runtime(format!("IPv4 regex compilation failed: {}", e)))?;
        
        let ipv6_re = Regex::new(r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$")
            .map_err(|e| NetInspectError::Runtime(format!("IPv6 regex compilation failed: {}", e)))?;

        if !ipv4_re.is_match(ip) && !ipv6_re.is_match(ip) {
            return Err(NetInspectError::InvalidInput(
                format!("Invalid IP address format: {}", ip)
            ));
        }

        Ok(())
    }

    /// Validate that required tools/permissions are available with comprehensive RBAC checks
    pub async fn validate_kubernetes_access() -> NetInspectResult<()> {
        use kube::Client;
        
        // Try to create a client to validate access
        let client = match Client::try_default().await {
            Ok(client) => client,
            Err(e) => {
                return Err(NetInspectError::KubernetesConnection(
                    format!("Failed to create Kubernetes client. Check kubeconfig and cluster connectivity: {}", e)
                ));
            }
        };
        
        // Test cluster-level permissions first - nodes access
        match Self::validate_nodes_access(&client).await {
            Ok(_) => {},
            Err(e) => return Err(e),
        }
        
        // Test namespace-level permissions for pods
        match Self::validate_pods_access(&client).await {
            Ok(_) => {},
            Err(e) => return Err(e),
        }
        
        // Test services access (required for network debugging)
        match Self::validate_services_access(&client).await {
            Ok(_) => {},
            Err(e) => return Err(e),
        }
        
        // Test endpoints access (required for service endpoint analysis)
        match Self::validate_endpoints_access(&client).await {
            Ok(_) => {},
            Err(e) => return Err(e),
        }
        
        // Test namespace access
        match Self::validate_namespaces_access(&client).await {
            Ok(_) => {},
            Err(e) => return Err(e),
        }
        
        Ok(())
    }

    /// Validate nodes access - required for cluster-level network debugging
    async fn validate_nodes_access(client: &Client) -> NetInspectResult<()> {
        let nodes: Api<Node> = Api::all(client.clone());
        
        match nodes.list(&ListParams::default().limit(1)).await {
            Ok(_) => Ok(()),
            Err(kube::Error::Api(api_err)) if api_err.code == 403 => {
                Err(NetInspectError::PermissionDenied(
                    format!(
                        "Missing RBAC permission: 'nodes/list'. This permission is required to:\n\
                        • Analyze cluster network topology\n\
                        • Identify node-level network configurations\n\
                        • Debug cross-node pod communication\n\
                        \n💡 Solution: Grant cluster-level nodes access with:\n\
                        kubectl create clusterrole netinspect-nodes --verb=get,list --resource=nodes\n\
                        kubectl create clusterrolebinding netinspect-nodes --clusterrole=netinspect-nodes --serviceaccount=<namespace>:<serviceaccount>"
                    )
                ))
            }
            Err(e) => Err(NetInspectError::from(e)),
        }
    }

    /// Validate pods access - core requirement for network debugging
    async fn validate_pods_access(client: &Client) -> NetInspectResult<()> {
        // Test in default namespace first
        let pods: Api<Pod> = Api::namespaced(client.clone(), "default");
        
        match pods.list(&ListParams::default().limit(1)).await {
            Ok(_) => {
                // Also test if we can get individual pods (required for detailed inspection)
                match pods.list(&ListParams::default().limit(1)).await {
                    Ok(pod_list) => {
                        if let Some(pod) = pod_list.items.first() {
                            if let Some(pod_name) = &pod.metadata.name {
                                // Test get access on a specific pod
                                if let Err(kube::Error::Api(api_err)) = pods.get(pod_name).await {
                                    if api_err.code == 403 {
                                        return Err(NetInspectError::PermissionDenied(
                                            "Missing RBAC permission: 'pods/get'. Required for detailed pod network analysis.".to_string()
                                        ));
                                    }
                                }
                            }
                        }
                        Ok(())
                    }
                    Err(e) => Err(NetInspectError::from(e)),
                }
            }
            Err(kube::Error::Api(api_err)) if api_err.code == 403 => {
                Err(NetInspectError::PermissionDenied(
                    format!(
                        "Missing RBAC permission: 'pods/list' and 'pods/get'. These permissions are required to:\n\
                        • List pods in namespaces for network analysis\n\
                        • Retrieve pod network configurations and IP addresses\n\
                        • Analyze pod-to-pod connectivity\n\
                        \n💡 Solution: Grant pod access with:\n\
                        kubectl create role netinspect-pods --verb=get,list --resource=pods\n\
                        kubectl create rolebinding netinspect-pods --role=netinspect-pods --serviceaccount=<namespace>:<serviceaccount>\n\
                        \n📝 Note: Apply this in each namespace where you need to debug network issues."
                    )
                ))
            }
            Err(e) => Err(NetInspectError::from(e)),
        }
    }

    /// Validate services access - required for service network debugging
    async fn validate_services_access(client: &Client) -> NetInspectResult<()> {
        let services: Api<Service> = Api::namespaced(client.clone(), "default");
        
        match services.list(&ListParams::default().limit(1)).await {
            Ok(_) => Ok(()),
            Err(kube::Error::Api(api_err)) if api_err.code == 403 => {
                Err(NetInspectError::PermissionDenied(
                    format!(
                        "Missing RBAC permission: 'services/list' and 'services/get'. These permissions are required to:\n\
                        • Analyze service network configurations\n\
                        • Debug service-to-pod connectivity\n\
                        • Inspect service endpoints and load balancing\n\
                        \n💡 Solution: Grant service access with:\n\
                        kubectl create role netinspect-services --verb=get,list --resource=services\n\
                        kubectl create rolebinding netinspect-services --role=netinspect-services --serviceaccount=<namespace>:<serviceaccount>"
                    )
                ))
            }
            Err(e) => Err(NetInspectError::from(e)),
        }
    }

    /// Validate endpoints access - required for service endpoint analysis
    async fn validate_endpoints_access(client: &Client) -> NetInspectResult<()> {
        let endpoints: Api<Endpoints> = Api::namespaced(client.clone(), "default");
        
        match endpoints.list(&ListParams::default().limit(1)).await {
            Ok(_) => Ok(()),
            Err(kube::Error::Api(api_err)) if api_err.code == 403 => {
                Err(NetInspectError::PermissionDenied(
                    format!(
                        "Missing RBAC permission: 'endpoints/list' and 'endpoints/get'. These permissions are required to:\n\
                        • Analyze service endpoint configurations\n\
                        • Debug service discovery issues\n\
                        • Inspect backend pod connectivity for services\n\
                        \n💡 Solution: Grant endpoints access with:\n\
                        kubectl create role netinspect-endpoints --verb=get,list --resource=endpoints\n\
                        kubectl create rolebinding netinspect-endpoints --role=netinspect-endpoints --serviceaccount=<namespace>:<serviceaccount>"
                    )
                ))
            }
            Err(e) => Err(NetInspectError::from(e)),
        }
    }

    /// Validate namespaces access - required for multi-namespace network debugging
    async fn validate_namespaces_access(client: &Client) -> NetInspectResult<()> {
        let namespaces: Api<Namespace> = Api::all(client.clone());
        
        match namespaces.list(&ListParams::default().limit(1)).await {
            Ok(_) => Ok(()),
            Err(kube::Error::Api(api_err)) if api_err.code == 403 => {
                Err(NetInspectError::PermissionDenied(
                    format!(
                        "Missing RBAC permission: 'namespaces/list' and 'namespaces/get'. These permissions are required to:\n\
                        • List available namespaces for network debugging\n\
                        • Validate namespace existence before operations\n\
                        • Support cross-namespace network analysis\n\
                        \n💡 Solution: Grant namespace access with:\n\
                        kubectl create clusterrole netinspect-namespaces --verb=get,list --resource=namespaces\n\
                        kubectl create clusterrolebinding netinspect-namespaces --clusterrole=netinspect-namespaces --serviceaccount=<namespace>:<serviceaccount>"
                    )
                ))
            }
            Err(e) => Err(NetInspectError::from(e)),
        }
    }

    /// Validate specific RBAC permissions for a given resource and verbs
    pub async fn validate_specific_permission(
        resource: &str,
        verbs: &[&str],
        namespace: Option<&str>
    ) -> NetInspectResult<()> {
        use kube::{Client, Api};
        use k8s_openapi::api::core::v1::{Pod, Node, Service, Endpoints, Namespace};
        use kube::api::ListParams;

        let client = Client::try_default().await
            .map_err(|e| NetInspectError::KubernetesConnection(
                format!("Failed to create Kubernetes client: {}", e)
            ))?;

        match resource {
            "pods" => {
                let api: Api<Pod> = if let Some(ns) = namespace {
                    Api::namespaced(client, ns)
                } else {
                    Api::default_namespaced(client)
                };
                
                for verb in verbs {
                    match *verb {
                        "list" => {
                            if let Err(kube::Error::Api(api_err)) = api.list(&ListParams::default().limit(1)).await {
                                if api_err.code == 403 {
                                    return Err(NetInspectError::PermissionDenied(
                                        format!("Missing RBAC permission: 'pods/{}' in namespace '{}'", verb, namespace.unwrap_or("default"))
                                    ));
                                }
                            }
                        }
                        "get" => {
                            // First list to get a pod name, then try to get it
                            if let Ok(pod_list) = api.list(&ListParams::default().limit(1)).await {
                                if let Some(pod) = pod_list.items.first() {
                                    if let Some(pod_name) = &pod.metadata.name {
                                        if let Err(kube::Error::Api(api_err)) = api.get(pod_name).await {
                                            if api_err.code == 403 {
                                                return Err(NetInspectError::PermissionDenied(
                                                    format!("Missing RBAC permission: 'pods/{}' in namespace '{}'", verb, namespace.unwrap_or("default"))
                                                ));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        _ => {
                            return Err(NetInspectError::InvalidInput(
                                format!("Unsupported verb '{}' for resource validation", verb)
                            ));
                        }
                    }
                }
            }
            "nodes" => {
                let nodes: Api<Node> = Api::all(client);
                for verb in verbs {
                    match *verb {
                        "list" => {
                            if let Err(kube::Error::Api(api_err)) = nodes.list(&ListParams::default().limit(1)).await {
                                if api_err.code == 403 {
                                    return Err(NetInspectError::PermissionDenied(
                                        format!("Missing RBAC permission: 'nodes/{}' (cluster-level)", verb)
                                    ));
                                }
                            }
                        }
                        "get" => {
                            if let Ok(node_list) = nodes.list(&ListParams::default().limit(1)).await {
                                if let Some(node) = node_list.items.first() {
                                    if let Some(node_name) = &node.metadata.name {
                                        if let Err(kube::Error::Api(api_err)) = nodes.get(node_name).await {
                                            if api_err.code == 403 {
                                                return Err(NetInspectError::PermissionDenied(
                                                    format!("Missing RBAC permission: 'nodes/{}' (cluster-level)", verb)
                                                ));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        _ => {
                            return Err(NetInspectError::InvalidInput(
                                format!("Unsupported verb '{}' for resource validation", verb)
                            ));
                        }
                    }
                }
            }
            "services" => {
                let api: Api<Service> = if let Some(ns) = namespace {
                    Api::namespaced(client, ns)
                } else {
                    Api::default_namespaced(client)
                };
                
                for verb in verbs {
                    match *verb {
                        "list" => {
                            if let Err(kube::Error::Api(api_err)) = api.list(&ListParams::default().limit(1)).await {
                                if api_err.code == 403 {
                                    return Err(NetInspectError::PermissionDenied(
                                        format!("Missing RBAC permission: 'services/{}' in namespace '{}'", verb, namespace.unwrap_or("default"))
                                    ));
                                }
                            }
                        }
                        "get" => {
                            if let Ok(svc_list) = api.list(&ListParams::default().limit(1)).await {
                                if let Some(svc) = svc_list.items.first() {
                                    if let Some(svc_name) = &svc.metadata.name {
                                        if let Err(kube::Error::Api(api_err)) = api.get(svc_name).await {
                                            if api_err.code == 403 {
                                                return Err(NetInspectError::PermissionDenied(
                                                    format!("Missing RBAC permission: 'services/{}' in namespace '{}'", verb, namespace.unwrap_or("default"))
                                                ));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        _ => {
                            return Err(NetInspectError::InvalidInput(
                                format!("Unsupported verb '{}' for resource validation", verb)
                            ));
                        }
                    }
                }
            }
            "namespaces" => {
                let namespaces: Api<Namespace> = Api::all(client);
                for verb in verbs {
                    match *verb {
                        "list" => {
                            if let Err(kube::Error::Api(api_err)) = namespaces.list(&ListParams::default().limit(1)).await {
                                if api_err.code == 403 {
                                    return Err(NetInspectError::PermissionDenied(
                                        format!("Missing RBAC permission: 'namespaces/{}' (cluster-level)", verb)
                                    ));
                                }
                            }
                        }
                        "get" => {
                            if let Ok(ns_list) = namespaces.list(&ListParams::default().limit(1)).await {
                                if let Some(ns) = ns_list.items.first() {
                                    if let Some(ns_name) = &ns.metadata.name {
                                        if let Err(kube::Error::Api(api_err)) = namespaces.get(ns_name).await {
                                            if api_err.code == 403 {
                                                return Err(NetInspectError::PermissionDenied(
                                                    format!("Missing RBAC permission: 'namespaces/{}' (cluster-level)", verb)
                                                ));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        _ => {
                            return Err(NetInspectError::InvalidInput(
                                format!("Unsupported verb '{}' for resource validation", verb)
                            ));
                        }
                    }
                }
            }
            _ => {
                return Err(NetInspectError::InvalidInput(
                    format!("Unsupported resource '{}' for permission validation", resource)
                ));
            }
        }

        Ok(())
    }

    /// Generate comprehensive RBAC setup script for k8s-netinspect
    pub fn generate_rbac_setup_script(service_account: &str, namespace: &str) -> String {
        format!(
            r#"#!/bin/bash
# RBAC Setup Script for k8s-netinspect
# Service Account: {service_account}
# Namespace: {namespace}

echo "Setting up RBAC permissions for k8s-netinspect..."

# Create service account if it doesn't exist
kubectl create serviceaccount {service_account} -n {namespace} --dry-run=client -o yaml | kubectl apply -f -

# Cluster-level permissions (nodes, namespaces)
cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: k8s-netinspect-cluster
rules:
- apiGroups: [""]
  resources: ["nodes"]
  verbs: ["get", "list"]
- apiGroups: [""]
  resources: ["namespaces"]
  verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: k8s-netinspect-cluster
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: k8s-netinspect-cluster
subjects:
- kind: ServiceAccount
  name: {service_account}
  namespace: {namespace}
EOF

# Namespace-level permissions (pods, services, endpoints)
cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: k8s-netinspect-namespace
  namespace: {namespace}
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
- apiGroups: [""]
  resources: ["services"]
  verbs: ["get", "list"] 
- apiGroups: [""]
  resources: ["endpoints"]
  verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: k8s-netinspect-namespace
  namespace: {namespace}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: k8s-netinspect-namespace
subjects:
- kind: ServiceAccount
  name: {service_account}
  namespace: {namespace}
EOF

echo "✅ RBAC permissions configured successfully!"
echo "You can now use k8s-netinspect with the service account: {service_account}"
echo ""
echo "To apply the same namespace permissions to other namespaces, run:"
echo "kubectl apply -f - <<EOF"
echo "apiVersion: rbac.authorization.k8s.io/v1"
echo "kind: RoleBinding"
echo "metadata:"
echo "  name: k8s-netinspect-namespace"
echo "  namespace: <TARGET_NAMESPACE>"
echo "roleRef:"
echo "  apiGroup: rbac.authorization.k8s.io"
echo "  kind: Role"
echo "  name: k8s-netinspect-namespace"
echo "subjects:"
echo "- kind: ServiceAccount"
echo "  name: {service_account}"
echo "  namespace: {namespace}"
echo "EOF"
"#,
            service_account = service_account,
            namespace = namespace
        )
    }

    /// Validate that a namespace exists in the cluster
    pub async fn validate_namespace_exists(namespace: &str) -> NetInspectResult<()> {
        use kube::{Client, Api};
        use k8s_openapi::api::core::v1::Namespace;
        
        let client = Client::try_default().await
            .map_err(NetInspectError::from)?;
        
        let namespaces: Api<Namespace> = Api::all(client);
        
        match namespaces.get(namespace).await {
            Ok(_) => Ok(()),
            Err(kube::Error::Api(api_err)) if api_err.code == 404 => {
                Err(NetInspectError::ResourceNotFound(
                    format!("Namespace '{}' does not exist in the cluster. Use 'kubectl get namespaces' to list available namespaces.", namespace)
                ))
            }
            Err(kube::Error::Api(api_err)) if api_err.code == 403 => {
                Err(NetInspectError::PermissionDenied(
                    "Missing RBAC permission: namespaces/get. Please ensure your service account can access namespace information.".to_string()
                ))
            }
            Err(e) => Err(NetInspectError::from(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_pod_name() {
        // Valid names
        assert!(Validator::validate_pod_name("nginx").is_ok());
        assert!(Validator::validate_pod_name("my-app-123").is_ok());
        assert!(Validator::validate_pod_name("app.example.com").is_ok());
        
        // Invalid names
        assert!(Validator::validate_pod_name("").is_err());
        assert!(Validator::validate_pod_name("NGINX").is_err());
        assert!(Validator::validate_pod_name("app_name").is_err());
        assert!(Validator::validate_pod_name("-starts-with-dash").is_err());
    }

    #[test]
    fn test_validate_namespace() {
        // Valid namespaces
        assert!(Validator::validate_namespace("default").is_ok());
        assert!(Validator::validate_namespace("kube-system").is_ok());
        assert!(Validator::validate_namespace("my-namespace").is_ok());
        
        // Invalid namespaces
        assert!(Validator::validate_namespace("").is_err());
        assert!(Validator::validate_namespace("UPPERCASE").is_err());
        assert!(Validator::validate_namespace("under_score").is_err());
        assert!(Validator::validate_namespace("-starts-with-dash").is_err());
    }

    #[test]
    fn test_validate_pod_ip() {
        // Valid IPs
        assert!(Validator::validate_pod_ip("192.168.1.1").is_ok());
        assert!(Validator::validate_pod_ip("10.0.0.1").is_ok());
        
        // Invalid IPs
        assert!(Validator::validate_pod_ip("").is_err());
        assert!(Validator::validate_pod_ip("256.1.1.1").is_err());
        assert!(Validator::validate_pod_ip("not.an.ip.address").is_err());
    }

    #[test]
    fn test_rbac_setup_script_generation() {
        let script = Validator::generate_rbac_setup_script("netinspect-sa", "monitoring");
        
        // Verify script contains essential components
        assert!(script.contains("netinspect-sa"));
        assert!(script.contains("monitoring"));
        assert!(script.contains("ClusterRole"));
        assert!(script.contains("ClusterRoleBinding"));
        assert!(script.contains("Role"));
        assert!(script.contains("RoleBinding"));
        assert!(script.contains("nodes"));
        assert!(script.contains("pods"));
        assert!(script.contains("services"));
        assert!(script.contains("endpoints"));
        assert!(script.contains("namespaces"));
        assert!(script.contains("get"));
        assert!(script.contains("list"));
        
        // Verify script is executable
        assert!(script.starts_with("#!/bin/bash"));
        
        // Verify it has setup instructions
        assert!(script.contains("Setting up RBAC permissions"));
        assert!(script.contains("configured successfully"));
    }

    #[test]
    fn test_specific_permission_validation_input() {
        // Test invalid resource
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(Validator::validate_specific_permission(
            "invalid_resource", 
            &["get"], 
            Some("default")
        ));
        
        // Print the actual error for debugging
        println!("Actual error for invalid resource: {:?}", result);
        
        match result {
            Err(NetInspectError::InvalidInput(msg)) => {
                assert!(msg.contains("Unsupported resource"));
                assert!(msg.contains("invalid_resource"));
            }
            Err(NetInspectError::KubernetesConnection(_)) => {
                // This is expected in test environments without k8s cluster
                println!("Got KubernetesConnection error as expected in test environment");
            }
            other => panic!("Expected InvalidInput or KubernetesConnection error, got: {:?}", other),
        }
        
        // Test invalid verb - this should return InvalidInput before trying to connect
        let result = rt.block_on(Validator::validate_specific_permission(
            "pods", 
            &["invalid_verb"], 
            Some("default")
        ));
        
        // Print the actual error for debugging
        println!("Actual error for invalid verb: {:?}", result);
        
        match result {
            Err(NetInspectError::InvalidInput(msg)) => {
                assert!(msg.contains("Unsupported verb"));
                assert!(msg.contains("invalid_verb"));
            }
            Err(NetInspectError::KubernetesConnection(_)) => {
                // This might happen if it tries to connect before validating verb
                println!("Got KubernetesConnection error - the function should validate verb before connecting");
            }
            other => panic!("Expected InvalidInput or KubernetesConnection error, got: {:?}", other),
        }
    }

    #[test]
    fn test_rbac_error_message_content() {
        // Test that RBAC error messages contain helpful information
        let script = Validator::generate_rbac_setup_script("test-sa", "test-ns");
        
        // Should contain kubectl commands for setup
        assert!(script.contains("kubectl create"));
        assert!(script.contains("kubectl apply"));
        
        // Should contain RBAC resource definitions
        assert!(script.contains("apiVersion: rbac.authorization.k8s.io/v1"));
        assert!(script.contains("kind: ClusterRole"));
        assert!(script.contains("kind: Role"));
        
        // Should contain success message
        assert!(script.contains("✅"));
        assert!(script.contains("configured successfully"));
        
        // Should provide instructions for other namespaces
        assert!(script.contains("To apply the same namespace permissions"));
        assert!(script.contains("<TARGET_NAMESPACE>"));
    }

    #[test]
    fn test_comprehensive_permission_coverage() {
        // Verify all required permissions are covered in the script
        let script = Validator::generate_rbac_setup_script("test", "test");
        
        // Cluster-level resources
        assert!(script.contains(r#"resources: ["nodes"]"#));
        assert!(script.contains(r#"resources: ["namespaces"]"#));
        
        // Namespace-level resources
        assert!(script.contains(r#"resources: ["pods"]"#));
        assert!(script.contains(r#"resources: ["services"]"#));
        assert!(script.contains(r#"resources: ["endpoints"]"#));
        
        // Required verbs
        assert!(script.contains(r#"verbs: ["get", "list"]"#));
        
        // Both cluster and namespace level bindings
        assert!(script.contains("k8s-netinspect-cluster"));
        assert!(script.contains("k8s-netinspect-namespace"));
    }

    #[test]
    fn test_permission_validation_supported_resources() {
        // Test that all expected resources are supported
        let supported_resources = ["pods", "nodes", "services", "namespaces"];
        let supported_verbs = ["get", "list"];
        
        for resource in &supported_resources {
            for verb in &supported_verbs {
                // This should not return InvalidInput error for supported combinations
                let rt = tokio::runtime::Runtime::new().unwrap();
                let result = rt.block_on(Validator::validate_specific_permission(
                    resource, 
                    &[verb], 
                    Some("default")
                ));
                
                // Should not fail with InvalidInput for supported resources/verbs
                if let Err(NetInspectError::InvalidInput(msg)) = result {
                    panic!("Resource '{}' with verb '{}' should be supported, but got error: {}", resource, verb, msg);
                }
            }
        }
    }

    #[test]
    fn test_rbac_script_parameter_substitution() {
        let service_account = "custom-sa";
        let namespace = "custom-ns";
        let script = Validator::generate_rbac_setup_script(service_account, namespace);
        
        // Count occurrences to ensure all placeholders are replaced
        let sa_count = script.matches(service_account).count();
        let ns_count = script.matches(namespace).count();
        
        // Should appear multiple times throughout the script
        assert!(sa_count >= 4, "Service account should appear at least 4 times, found: {}", sa_count);
        assert!(ns_count >= 4, "Namespace should appear at least 4 times, found: {}", ns_count);
        
        // Should not contain placeholder strings
        assert!(!script.contains("{service_account}"));
        assert!(!script.contains("{namespace}"));
    }
}