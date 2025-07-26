#[cfg(test)]
mod validation_tests {
    use k8s_netinspect::validation::Validator;
    use k8s_netinspect::errors::NetInspectError;

    #[test]
    fn test_pod_name_validation() {
        // Valid pod names
        assert!(Validator::validate_pod_name("nginx").is_ok());
        assert!(Validator::validate_pod_name("my-app-123").is_ok());
        assert!(Validator::validate_pod_name("app.example.com").is_ok());
        assert!(Validator::validate_pod_name("web-server-1").is_ok());
        
        // Invalid pod names
        assert!(matches!(
            Validator::validate_pod_name(""),
            Err(NetInspectError::InvalidInput(_))
        ));
        assert!(matches!(
            Validator::validate_pod_name("NGINX"),
            Err(NetInspectError::InvalidInput(_))
        ));
        assert!(matches!(
            Validator::validate_pod_name("app_name"),
            Err(NetInspectError::InvalidInput(_))
        ));
        assert!(matches!(
            Validator::validate_pod_name("-starts-with-dash"),
            Err(NetInspectError::InvalidInput(_))
        ));
        assert!(matches!(
            Validator::validate_pod_name("ends-with-dash-"),
            Err(NetInspectError::InvalidInput(_))
        ));
        
        // Test length limits
        let long_name = "a".repeat(254);
        assert!(matches!(
            Validator::validate_pod_name(&long_name),
            Err(NetInspectError::InvalidInput(_))
        ));
    }

    #[test]
    fn test_namespace_validation() {
        // Valid namespaces
        assert!(Validator::validate_namespace("default").is_ok());
        assert!(Validator::validate_namespace("kube-system").is_ok());
        assert!(Validator::validate_namespace("my-namespace").is_ok());
        assert!(Validator::validate_namespace("app-prod").is_ok());
        
        // Invalid namespaces
        assert!(matches!(
            Validator::validate_namespace(""),
            Err(NetInspectError::InvalidInput(_))
        ));
        assert!(matches!(
            Validator::validate_namespace("UPPERCASE"),
            Err(NetInspectError::InvalidInput(_))
        ));
        assert!(matches!(
            Validator::validate_namespace("under_score"),
            Err(NetInspectError::InvalidInput(_))
        ));
        assert!(matches!(
            Validator::validate_namespace("-starts-with-dash"),
            Err(NetInspectError::InvalidInput(_))
        ));
        assert!(matches!(
            Validator::validate_namespace("ends-with-dash-"),
            Err(NetInspectError::InvalidInput(_))
        ));
        
        // Test length limits
        let long_namespace = "a".repeat(64);
        assert!(matches!(
            Validator::validate_namespace(&long_namespace),
            Err(NetInspectError::InvalidInput(_))
        ));
    }

    #[test]
    fn test_pod_ip_validation() {
        // Valid IPv4 addresses
        assert!(Validator::validate_pod_ip("192.168.1.1").is_ok());
        assert!(Validator::validate_pod_ip("10.0.0.1").is_ok());
        assert!(Validator::validate_pod_ip("172.16.0.1").is_ok());
        assert!(Validator::validate_pod_ip("1.1.1.1").is_ok());
        
        // Invalid IP addresses
        assert!(matches!(
            Validator::validate_pod_ip(""),
            Err(NetInspectError::InvalidInput(_))
        ));
        assert!(matches!(
            Validator::validate_pod_ip("256.1.1.1"),
            Err(NetInspectError::InvalidInput(_))
        ));
        assert!(matches!(
            Validator::validate_pod_ip("192.168.1"),
            Err(NetInspectError::InvalidInput(_))
        ));
        assert!(matches!(
            Validator::validate_pod_ip("not.an.ip.address"),
            Err(NetInspectError::InvalidInput(_))
        ));
        assert!(matches!(
            Validator::validate_pod_ip("192.168.1.1.1"),
            Err(NetInspectError::InvalidInput(_))
        ));
    }

    #[test]
    fn test_edge_cases() {
        // Single character names
        assert!(Validator::validate_pod_name("a").is_ok());
        assert!(Validator::validate_namespace("a").is_ok());
        
        // Names with multiple dots
        assert!(Validator::validate_pod_name("my.app.example.com").is_ok());
        
        // Names with numbers
        assert!(Validator::validate_pod_name("app123").is_ok());
        assert!(Validator::validate_namespace("ns123").is_ok());
        
        // Maximum valid length
        let max_pod_name = format!("{}a", "a".repeat(252)); // 253 chars total
        assert!(Validator::validate_pod_name(&max_pod_name).is_ok());
        
        let max_namespace = format!("{}a", "a".repeat(62)); // 63 chars total
        assert!(Validator::validate_namespace(&max_namespace).is_ok());
    }

    #[test]
    fn test_error_message_quality() {
        // Check that error messages are informative
        match Validator::validate_pod_name("INVALID_POD") {
            Err(NetInspectError::InvalidInput(msg)) => {
                assert!(msg.contains("lowercase"));
                assert!(msg.contains("alphanumeric"));
            },
            _ => panic!("Expected InvalidInput error"),
        }
        
        match Validator::validate_namespace("") {
            Err(NetInspectError::InvalidInput(msg)) => {
                assert!(msg.contains("empty"));
            },
            _ => panic!("Expected InvalidInput error"),
        }
        
        match Validator::validate_pod_ip("256.1.1.1") {
            Err(NetInspectError::InvalidInput(msg)) => {
                assert!(msg.contains("Invalid IP"));
            },
            _ => panic!("Expected InvalidInput error"),
        }
    }
}