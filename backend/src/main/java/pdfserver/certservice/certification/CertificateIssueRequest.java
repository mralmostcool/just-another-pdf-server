package pdfserver.certservice.certification;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

public record CertificateIssueRequest(
        @NotBlank(message = "Subject DN is required (e.g., CN=Alice, O=Acme, C=IN)") @Pattern(regexp = "^(CN|O|OU|L|ST|C)=[^,]+(,\\s*(CN|O|OU|L|ST|C)=[^,]+)*$", message = "Subject must be a valid X.500 Distinguished Name (e.g., CN=User, O=Org, C=IN)") String subjectName,
        @NotNull(message = "keyFormat is required (PKCS12 or PEM_PKCS8)") KeyFormat keyFormat,
        @NotBlank(message = "keyPayload is required") String keyPayload,
        String passphrase,
        @Min(value = 1, message = "validityDays must be at least 1") @Max(value = 3650, message = "validityDays cannot exceed 3650 (10 years)") Integer validityDays) {
    public int resolvedValidityDays() {
        return validityDays != null ? validityDays : 365;
    }

    @Override
    public String toString() {
        return "CertificateIssueRequest[subjectName=" + subjectName +
                ", keyFormat=" + keyFormat +
                ", keyPayload=[REDACTED]" +
                ", passphrase=" + (passphrase != null ? "[REDACTED]" : "null") +
                ", validityDays=" + resolvedValidityDays() + "]";
    }
}