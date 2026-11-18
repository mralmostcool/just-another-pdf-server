CREATE TABLE certificates (
    id UUID PRIMARY KEY,
    subject_name VARCHAR(255) NOT NULL,
    serial_number VARCHAR(64) NOT NULL UNIQUE,
    pem_content TEXT NOT NULL,
    issued_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX idx_cretificates_serial_number ON certificates(serial_number);