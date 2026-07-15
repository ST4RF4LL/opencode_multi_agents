public class N03_PublicCertificate {
    // Public certificate material is not a secret
    private static final String CERT = ""
        + "-----BEGIN CERTIFICATE-----\n"
        + "MIIBkTCB+wIJAKHBjVbFEXAMPLE\n"
        + "-----END CERTIFICATE-----\n";

    public String certPem() {
        return CERT;
    }
}
