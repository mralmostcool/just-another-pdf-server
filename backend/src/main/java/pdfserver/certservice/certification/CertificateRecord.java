package pdfserver.certservice.certification;

import java.time.Instant;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import jakarta.persistence.Table;
import lombok.Getter;

@Entity
@Getter
@Table(name = "certificates")
public class CertificateRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false)
    private String subjectName;

    @Column(nullable = false, unique = false)
    private String serialNumber;

    @Lob
    @Column(columnDefinition = "TEXT", nullable = false)
    private String pemContent;

    @Column(nullable = false, updatable = false)
    private Instant issuedAt;

    protected CertificateRecord() {
    }

    public CertificateRecord(String subjectName, String serialNumber, String pemContent) {
        this.subjectName = subjectName;
        this.serialNumber = serialNumber;
        this.pemContent = pemContent;
        this.issuedAt = Instant.now();
    }

}
