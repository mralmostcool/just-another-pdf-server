package pdfserver.certservice.certification;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

@Service
public class CertificateService {

    private final CertificateRepository repository;

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public CertificateService(CertificateRepository repository) {
        this.repository = repository;
    }

    public CertificateRecord issueCertificate(CertificateIssueRequest request) {
        try {
            PrivateKey privateKey = extractPrivateKey(request);
            PublicKey publicKey = derivePublicKey(privateKey);

            BigInteger serialNumber = new BigInteger(128, new SecureRandom()).abs();
            X500Name subject = new X500Name(request.subjectName());

            Instant now = Instant.now();
            Date notBefore = Date.from(now);
            Date notAfter = Date.from(now.plus(request.resolvedValidityDays(), ChronoUnit.DAYS));

            JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                    subject, // Issuer (self-signed with the provided key)
                    serialNumber,
                    notBefore,
                    notAfter,
                    subject, // Subject
                    publicKey);

            String signatureAlgorithm = resolveSignatureAlgorithm(privateKey);
            ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm)
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(privateKey);

            X509CertificateHolder certHolder = certBuilder.build(signer);
            X509Certificate certificate = new JcaX509CertificateConverter()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .getCertificate(certHolder);

            certificate.verify(publicKey);

            String pemContent = toPemString(certificate);
            String hexSerial = serialNumber.toString(16).toUpperCase();

            CertificateRecord record = new CertificateRecord(
                    request.subjectName(),
                    hexSerial,
                    pemContent);
            return repository.save(record);

        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to sign certificate with provided key material", e);
        }
    }

    public CertificateRecord getCertificate(UUID id) {
        return repository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Certificate not found: " + id));
    }

    private PrivateKey extractPrivateKey(CertificateIssueRequest request) throws Exception {
        char[] passwordChars = request.passphrase() != null
                ? request.passphrase().toCharArray()
                : new char[0];

        if (request.keyFormat() == KeyFormat.PKCS12) {
            byte[] p12Bytes = Base64.getDecoder().decode(request.keyPayload().trim());
            KeyStore keyStore = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
            keyStore.load(new ByteArrayInputStream(p12Bytes), passwordChars);

            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (keyStore.isKeyEntry(alias)) {
                    Key key = keyStore.getKey(alias, passwordChars);
                    if (key instanceof PrivateKey pk) {
                        return pk;
                    }
                }
            }
            throw new IllegalArgumentException("No private key entry found inside PKCS#12 bundle");
        }

        // PEM_PKCS8 (supports unencrypted PKCS#8, encrypted PKCS#8, and traditional
        // OpenSSL PEM)
        try (PEMParser pemParser = new PEMParser(new StringReader(request.keyPayload().trim()))) {
            Object parsed = pemParser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME);

            if (parsed instanceof PrivateKeyInfo keyInfo) {
                return converter.getPrivateKey(keyInfo);
            }
            if (parsed instanceof PKCS8EncryptedPrivateKeyInfo encryptedInfo) {
                InputDecryptorProvider decryptor = new JceOpenSSLPKCS8DecryptorProviderBuilder()
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .build(passwordChars);
                return converter.getPrivateKey(encryptedInfo.decryptPrivateKeyInfo(decryptor));
            }
            if (parsed instanceof PEMKeyPair keyPair) {
                return converter.getKeyPair(keyPair).getPrivate();
            }
            if (parsed instanceof PEMEncryptedKeyPair encryptedPair) {
                var decryptor = new JcePEMDecryptorProviderBuilder()
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .build(passwordChars);
                return converter.getKeyPair(encryptedPair.decryptKeyPair(decryptor)).getPrivate();
            }
            throw new IllegalArgumentException("Unsupported or unreadable PEM key format");
        }
    }

    private PublicKey derivePublicKey(PrivateKey privateKey) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance(
                privateKey.getAlgorithm(),
                BouncyCastleProvider.PROVIDER_NAME);

        if (privateKey instanceof RSAPrivateCrtKey rsaKey) {
            return keyFactory.generatePublic(
                    new RSAPublicKeySpec(rsaKey.getModulus(), rsaKey.getPublicExponent()));
        }
        if (privateKey instanceof ECPrivateKey ecKey) {
            ECParameterSpec params = ecKey.getParams();
            org.bouncycastle.jce.spec.ECParameterSpec bcSpec = org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util
                    .convertSpec(params);
            org.bouncycastle.math.ec.ECPoint q = bcSpec.getG().multiply(ecKey.getS());
            org.bouncycastle.math.ec.ECPoint normQ = q.normalize();
            java.security.spec.ECPoint w = new java.security.spec.ECPoint(
                    normQ.getAffineXCoord().toBigInteger(),
                    normQ.getAffineYCoord().toBigInteger());
            return keyFactory.generatePublic(new ECPublicKeySpec(w, params));
        }
        if (privateKey instanceof EdECPrivateKey edKey) {
            // Bouncy Castle's EdDSA private key exposes getPublicKey() directly
            if (edKey instanceof org.bouncycastle.jcajce.interfaces.EdDSAPrivateKey bcEdKey) {
                return bcEdKey.getPublicKey();
            }
        }
        throw new IllegalArgumentException("Unsupported key algorithm: " + privateKey.getAlgorithm());
    }

    private String resolveSignatureAlgorithm(PrivateKey privateKey) {
        return switch (privateKey.getAlgorithm().toUpperCase()) {
            case "RSA" -> "SHA256withRSA";
            case "EC", "ECDSA" -> "SHA256withECDSA";
            case "ED25519" -> "Ed25519";
            default ->
                throw new IllegalArgumentException("Unsupported signing algorithm: " + privateKey.getAlgorithm());
        };
    }

    private String toPemString(X509Certificate certificate) throws Exception {
        StringWriter stringWriter = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
            pemWriter.writeObject(certificate);
        }
        return stringWriter.toString();
    }
}