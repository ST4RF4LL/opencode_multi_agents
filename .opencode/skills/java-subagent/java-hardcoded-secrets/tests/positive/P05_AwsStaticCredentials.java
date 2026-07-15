// Uses official AWS documentation example keys only (not real credentials).
public class P05_AwsStaticCredentials {
    public Object vulnerable() {
        String accessKey = "AKIAIOSFODNN7EXAMPLE";
        String secretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        // Pattern: static cloud credentials in source (SDK types optional for pattern match)
        return accessKey + ":" + secretKey;
    }

    public void alsoVulnerableBasicAwsPattern() {
        // Simulated BasicAWSCredentials construction pattern for static analysis
        createCredentials("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
    }

    private Object createCredentials(String accessKeyId, String secretAccessKey) {
        return new String[] { accessKeyId, secretAccessKey };
    }
}
