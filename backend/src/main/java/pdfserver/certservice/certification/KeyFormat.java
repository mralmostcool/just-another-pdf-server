package pdfserver.certservice.certification;

public enum KeyFormat {
    PKCS12, // Base64 .p12 or .pdx file (requires passphrase)
    PEM_PKCS8 // Standard PEM-encoded private key string (optional passphrase)
}
