package pdfserver.certservice.certification;

import java.util.Base64;
import java.util.UUID;

import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class CertificateService {

    private final CertificateRepository repository;

    public CertificateRecord issuePlaceholdeRecord(String subjectName, String dummyKeyPayload) {
        String serial = UUID.randomUUID().toString().replace("-", "").substring(0, 16).toUpperCase();
        String encodedPayload = Base64.getEncoder().encodeToString(
                ("PLACEHOLDER-CERT-FOR:" + subjectName + "|KEY-REF" + dummyKeyPayload.hashCode()).getBytes());

        String placeholderPem = """
                ----BEGIN CERTIFICATE----
                %s
                -----END CERTIFICATE-----
                """.formatted(encodedPayload);

        CertificateRecord record = new CertificateRecord(subjectName, serial, placeholderPem);

        return repository.save(record);
    }

    public CertificateRecord getCertificate(UUID id) {
        return repository
                .findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Certificate not found: " + id));
    }

}
