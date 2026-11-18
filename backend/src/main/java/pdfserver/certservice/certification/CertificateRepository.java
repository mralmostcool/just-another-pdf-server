package pdfserver.certservice.certification;

import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CertificateRepository extends JpaRepository<CertificateRecord, UUID> {

}
