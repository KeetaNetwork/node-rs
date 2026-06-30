package network.keeta.wasi.harness;

import network.keeta.wasi.Account;
import network.keeta.wasi.Algorithm;
import network.keeta.wasi.Certificate;
import network.keeta.wasi.Keeta;

/**
 * Base-certificate metadata check for the bound Java SDK.
 */
public final class CertificateMetadata {
	/** The seed {@code doc_utils} derives its subject from; the fixture is issued
	 *  to the secp256k1 account at index 0 of this seed. */
	private static final String SUBJECT_SEED = "D6986115BE7334E50DA8D73B1A4670A510E8BF47E8C5C9960B8F5248EC7D6E3D";

	/** Unix seconds inside the fixture's validity window (2026-06-28..2027-06-28). */
	private static final long VALID_AT = 1_797_292_800L;

	private static final String FIXTURE_PEM = """
		-----BEGIN CERTIFICATE-----
		MIIDzTCCA3SgAwIBAgICMDkwCgYIKoZIzj0EAwIwFjEUMBIGA1UEAxYLVGVzdCBJ
		c3N1ZXIwIhgPMjAyNjA2MjgyMzIwNDVaGA8yMDI3MDYyODIzMjA0NVowFzEVMBMG
		A1UEAxYMVGVzdCBTdWJqZWN0MDYwEAYHKoZIzj0CAQYFK4EEAAoDIgACpkFiKH+5
		y+/csZUSPRIZwON061asGjraczszX1LL2HujggLOMIICyjAOBgNVHQ8BAf8EBAMC
		AMAwggK2BgorBgEEAYPpUwAABIICpjCCAqIwggFKBgorBgEEAYPpUwEDgYIBOjCC
		ATYCAQAwga0GCWCGSAFlAwQBLgQMfrJEYqEtjXoXFJrDBIGRBFEOgNX6ho8+Fil3
		91HDLYxx5u/l5UuOQFnJizMqoBkD/64XdrGWeURzt5ERG33SBxNJLaIbGLfU+w+a
		mu8HII50cSOjYYGalY7HbfAxqp0QStJZC9FTnr5+jHXQLSrfLnViXjPSz9sk7+xq
		eptUlXaromEIBaKAzavrUB8xlayBDh6hXNEToOjxmSai5f4khTBfBDD4fEMxz1aM
		wJbcmH5fi75NVNQH//2775k63qU3kWwuGu4yMrwa0TVvAd274S0xbC8GCWCGSAFl
		AwQCCAQgEj0cBCSSIdCPXWPhbdFGvSuSbegC0XhbAG82dmNRkbIEIA87wpxepdKD
		7qOY7UUEd9YUxIeSSBFwM2KPhO30zl+DMIIBQgYKKwYBBAGD6VMBAIGCATIwggEu
		AgEAMIGtBglghkgBZQMEAS4EDKznmG0IQycoVdJ9VQSBkQT/6Qumd90HGs1cof3u
		5derYnULnG3pbLxExHPqdzIwnOcXyFvGR8DDgBXYmUCspHjH3AQN6wYDfQ0IQ89F
		uakNlpGpGMWy152544+VG3fbrJmPkRhxKHPpYmQfiUGMqF0kGE7tLwzbC7cLx0ni
		jkkXUwlX5/UV3kJT3wBQciD1gKgl4euhYNxAfuyLtkZaZhkwXwQwJXrikAzhMr8q
		kKtaDkAohxfngm3mLEzsE+MmuI7hobUEIm59Uze8K3JG35L7OfVABglghkgBZQME
		AggEIGJ8nq65ul0UKAY3UL84Mg0Iddj9VYVNBa3oTnANZXYfBBgqlBgcLrd4of/W
		Hu4NJE0IKwCL+Gnbok4wDAYDVQURgAUxMjM0NTAKBggqhkjOPQQDAgNHADBEAiBY
		mcOwl1yNkItpFWeWby4gqa0rHOw7U0bHxpk9kYWHbgIgVbO0xyOAB7ByOqMO40Qh
		or6z8/Cbh+JIKGADPmGawrE=
		-----END CERTIFICATE-----
		""";

	private CertificateMetadata() {
	}

	public static void main(String[] args) {
		try (Keeta keeta = Keeta.load();
			Certificate certificate = keeta.certificate(FIXTURE_PEM);
			Account account = keeta.account(SUBJECT_SEED, 0, Algorithm.ECDSA_SECP256K1)) {
			check(certificate.subject().contains("Test Subject"), "the subject DN must name the fixture subject");
			check(certificate.issuer().contains("Test Issuer"), "the issuer DN must name the fixture issuer");
			check(certificate.serial().equals("12345"), "the serial must decode to its base-10 form");

			long notBefore = certificate.notBefore();
			long notAfter = certificate.notAfter();
			check(notBefore < notAfter, "the validity window must be ordered");
			check(notBefore <= VALID_AT && VALID_AT <= notAfter,
				"the in-window moment must fall inside the reported validity window");

			check(certificate.subjectPublicKey().equalsIgnoreCase(account.publicKey()),
				"the subject public key must equal the subject account's public key");
		}

		System.out.println("CERTIFICATE_METADATA_OK");
	}

	private static void check(boolean condition, String message) {
		if (!condition) {
			throw new IllegalStateException("certificate metadata assertion failed: " + message);
		}
	}
}
