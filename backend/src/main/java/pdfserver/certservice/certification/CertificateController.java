package pdfserver.certservice.certification;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

import java.util.UUID;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@RestController
@RequestMapping("/api/v1/certificates")
@RequiredArgsConstructor
public class CertificateController {

    private final CertificateService service;

    @PostMapping
    public ResponseEntity<CertificateRecord> issue(@Valid @RequestBody CertificateIssueRequest request) {
        CertificateRecord saved = service.issuePlaceholdeRecord(
                request.subjectName(),
                request.keyPayload());
        return ResponseEntity.ok(saved);
    }

    @GetMapping("/{id}")
    public ResponseEntity<CertificateRecord> view(@PathVariable UUID id) {
        return ResponseEntity.ok(service.getCertificate(id));
    }

}