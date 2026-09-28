// RSAHostKeyVerificationDeterministicTests.swift
// Deterministic regression vectors for PrivateTailnetSSHCore_R3_MacCandidate.swift.
// Run in the same Swift module / Playground as the MacCandidate core.
// No network, password, or live SSH server is involved.

import Foundation

enum RSAHostKeyVerificationDeterministicTests {
    private static func b64(_ text: String) -> Data {
        Data(base64Encoded: text)!
    }

    private static let exponent = b64("AQAB")
    private static let modulus = b64("ttcX0/qze4HJCv6Usto4bnOb3HXAwRcKeK2dvHvnI2YbUASahe+aMR+4qM653ydk618ddGJALDGoZAn6nhzafHrAr8fZpsmU9QUOh8BSCQPaFOM6meh8S9TKpfl6ieePil5T3BII6NJhySXoXXGRBxTMwOkQxQQsmiRGUPfD49V4KSFe8RoDv2RbuqrwoBtINBlygISPtZQZof8TChfrgiy7mO/i9RyIWep6hkrArUNcXytpaLfD71uzpd0EK7AyMTOFU4wzx26vTn2wIuN6c/MiuPRgU1eguTcbTjSkShIom053llf9nN+D43Qc6lghB5xsTh9Eye3kkWWcTJC78w==")
    private static let exchangeHash = b64("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=")
    private static let signature256 = b64("m096f50ICk9CoYwzpXKzb36Q5rtKRr0KU0ZfGm6bQH9SLb19ini1chSPLVcH9APO22ylUTGLeLT+phVCbznWZbkMLuw0j0L+1kwFzR0jOPcmv8ztgPwICTeUD8qNHz0bQe+4ACy8FE5gSxW0I2psDjlq/NjRMhN5giY46tUM0nTQQ4rm6lBesGr8DbEd5wt1IyyS5cKbtKnmNyeGms2tLAN2Qg5YbvuG9zAdgfXMsngTCbyNMhmZe9+Qy6UjTxAGVnobRFzycDTuaWnuaFEiYGuMatTDlZwFSmxRjsp8p2JGoTs0cOt42Ssnuumv2ODnKxWePbNTrcgmpMH1iL0IVQ==")
    private static let signature512 = b64("ZegLV876KtJGJZU5xFcC1/OKG96yIjVrJPYC89WYsJVlFW8jb7gUdQqr+clC9dMqaNpetGf/skO6LJs+p6tCxlvXRfPVGvmQAbxr7oB5nkiURAd5Vo/d1El7o0EXCWaVZIIO9gjYH+V9dXOTM/Iy/iB4BdXnHhQSbtHqcQGHqK4PwyJdtM4j9f0N/PN0RSuiVMPSVE+Y5NEWqjv18NAUapEeliOBoAAyztZ+JAf/06N15+QIGWiMQx+BhbsKlgavrdfm4YvhrDRUdOY/vJLe5jHqb3hPJlPY5gT7Woo9avEWUl7Fw8JZqDb0gKJXCQQyngy0R9xetMG/MYHYI/mVTQ==")

    private static func positiveMPInt(_ magnitude: Data) -> Data {
        var bytes = Array(magnitude)
        while bytes.first == 0 { bytes.removeFirst() }
        guard !bytes.isEmpty else { return Data() }
        if bytes[0] & 0x80 != 0 { bytes.insert(0, at: 0) }
        return Data(bytes)
    }

    private static func hostKeyBlob() -> Data {
        var d = Data()
        d = IntegratedSSHWire.putString("ssh-rsa", into: d)
        d = IntegratedSSHWire.putString(positiveMPInt(exponent), into: d)
        d = IntegratedSSHWire.putString(positiveMPInt(modulus), into: d)
        return d
    }

    /// Deliberately non-canonical: modulus starts with high bit 1 but lacks the
    /// required mpint sign-protection 0x00. Strict parsing must reject it.
    private static func malformedNegativeModulusHostKeyBlob() -> Data {
        var d = Data()
        d = IntegratedSSHWire.putString("ssh-rsa", into: d)
        d = IntegratedSSHWire.putString(positiveMPInt(exponent), into: d)
        d = IntegratedSSHWire.putString(modulus, into: d)
        return d
    }

    private static func signatureBlob(_ algorithm: String, _ raw: Data) -> Data {
        var d = Data()
        d = IntegratedSSHWire.putString(algorithm, into: d)
        d = IntegratedSSHWire.putString(raw, into: d)
        return d
    }

    static func run() -> String {
        let key = hostKeyBlob()
        let valid256 = IntegratedSSHCrypto.verifyHostKey(
            blob: key,
            signature: signatureBlob("rsa-sha2-256", signature256),
            over: exchangeHash
        )
        let valid512 = IntegratedSSHCrypto.verifyHostKey(
            blob: key,
            signature: signatureBlob("rsa-sha2-512", signature512),
            over: exchangeHash
        )

        var alteredHash = exchangeHash
        alteredHash[alteredHash.startIndex] ^= 0x01
        let rejectsAlteredHash = !IntegratedSSHCrypto.verifyHostKey(
            blob: key,
            signature: signatureBlob("rsa-sha2-256", signature256),
            over: alteredHash
        )

        var alteredSignature = signature512
        alteredSignature[alteredSignature.startIndex] ^= 0x01
        let rejectsAlteredSignature = !IntegratedSSHCrypto.verifyHostKey(
            blob: key,
            signature: signatureBlob("rsa-sha2-512", alteredSignature),
            over: exchangeHash
        )

        let rejectsWrongAlgorithm = !IntegratedSSHCrypto.verifyHostKey(
            blob: key,
            signature: signatureBlob("ssh-rsa", signature256),
            over: exchangeHash
        )

        let rejectsNegativeMPIntEncoding = !IntegratedSSHCrypto.verifyHostKey(
            blob: malformedNegativeModulusHostKeyBlob(),
            signature: signatureBlob("rsa-sha2-256", signature256),
            over: exchangeHash
        )

        var trailingSignature = signatureBlob("rsa-sha2-256", signature256)
        trailingSignature.append(0x00)
        let rejectsTrailingSignatureBytes = !IntegratedSSHCrypto.verifyHostKey(
            blob: key,
            signature: trailingSignature,
            over: exchangeHash
        )

        let checks = [
            ("rsa-sha2-256 valid", valid256),
            ("rsa-sha2-512 valid", valid512),
            ("altered exchange hash rejected", rejectsAlteredHash),
            ("altered RSA signature rejected", rejectsAlteredSignature),
            ("ssh-rsa/SHA-1 algorithm label rejected", rejectsWrongAlgorithm),
            ("non-canonical negative RSA mpint rejected", rejectsNegativeMPIntEncoding),
            ("trailing signature bytes rejected", rejectsTrailingSignatureBytes),
        ]
        return checks.map { "\($0.1 ? "PASS" : "FAIL")  \($0.0)" }.joined(separator: "\n")
    }
}
