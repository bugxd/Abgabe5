package ab5.test;

import org.junit.Assert;
import org.junit.Test;

import ab5.CertTools;
import ab5.impl.Nachnamen.CertToolsImpl;
//import intern.impl.CertToolsImpl;

public class CertToolsTest {

	private CertTools tools = new CertToolsImpl();

	@Test
	public void testCampusAAUZerts() {
		tools.loadServerCerts("campus.aau.at", 443);

		//Hole Zertifikat für campus.aau.at
		int testCert = tools.getCertificateChain().get(0);

		Assert.assertEquals(4, tools.getNumberCerts());
		
		//Die Reihenfolge kann je nach Implementierung variieren
		//Assert.assertEquals(Arrays.asList(0, 1, 2, 3), tools.getCertificateChain());

		Assert.assertEquals(
				"MIIFqjCCBJKgAwIBAgIQUsGVaBHsFxktvQStYRi0TzANBgkqhkiG9w0BAQsFADBkMQswCQYDVQQGEwJOTDEWMBQGA1UECBMNTm9vcmQtSG9sbGFuZDESMBAGA1UEBxMJQW1zdGVyZGFtMQ8wDQYDVQQKEwZURVJFTkExGDAWBgNVBAMTD1RFUkVOQSBTU0wgQ0EgMjAeFw0xNTA0MTgwMDAwMDBaFw0xODA0MTcyMzU5NTlaMDsxITAfBgNVBAsTGERvbWFpbiBDb250cm9sIFZhbGlkYXRlZDEWMBQGA1UEAxMNY2FtcHVzLmFhdS5hdDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAN9cE+HvXGR2i2S0ff7S7vHKZ4YbgzcuHr8a9epWZK/AGieiqnPHcJcQOPO9OBhSRjutvOPuN13lQhIu82kMrKhPf2VwqlcBw3MIT/7zo8hkLwnbxCNfwxJGxFIaQIWW3Y8g3haMAVU419izBiZuInODNcPuyswuxYk+0p6v5tAsh+4Q4jyeXtIQhbiXhx7ZTKyVKlyC7btlyOsL+WiE84NQhyhIfFgtCXy1KypTf4QakuAnxBn5htRZLER8mPyQhbvq492jZKavW7+cuKJn5rKv2DdMIZVx545HYnp9SZ6zIp/7K8gmGIuBeZ9t4OhZYPgA4ljxQIg5TUV0sqOMc5yrXBNDd75i0lTH4F3+GzK4pOgOektz+3DwSjPsu7f69JqKrvI9zLJSXpe+OZ/w4EjZfdo1TVu8/HPOWQFPgwZNZ/v1gg1iw+sgV2qCitucsF66bxINltP1WkWGLOICg3GwX3Aq0Oc+UgKpGhUtpPBoI1tiy1NpuRgCxdxQEqiIBUnmz4DmsvclDqTg7POuMu9PcfBc+K2ZnZSj+KSnGfRWfaU2Oj8HpIIVoRPiYASSwo22CnZQW89lmxlrjBC4Mguprdp8lKSS8SvC8ouXPGHdYqTgGOWOdiDaWLT1IOyoQkoXwo/EtPXmoj2OBlTerYq3tp1vkv6D9xykmz3/hS8lAgMBAAGjggF/MIIBezAfBgNVHSMEGDAWgBRb0IocmjJb4LXdllQb4YYosP22vTAdBgNVHQ4EFgQU+JhJad+BQY0CqzOO9vU2csqFhNQwDgYDVR0PAQH/BAQDAgWgMAwGA1UdEwEB/wQCMAAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMCIGA1UdIAQbMBkwDQYLKwYBBAGyMQECAh0wCAYGZ4EMAQIBMDoGA1UdHwQzMDEwL6AtoCuGKWh0dHA6Ly9jcmwudXNlcnRydXN0LmNvbS9URVJFTkFTU0xDQTIuY3JsMGwGCCsGAQUFBwEBBGAwXjA1BggrBgEFBQcwAoYpaHR0cDovL2NydC51c2VydHJ1c3QuY29tL1RFUkVOQVNTTENBMi5jcnQwJQYIKwYBBQUHMAGGGWh0dHA6Ly9vY3NwLnVzZXJ0cnVzdC5jb20wLgYDVR0RBCcwJYINY2FtcHVzLmFhdS5hdIIUY2FtcHVzLnVuaS1rbHUuYWMuYXQwDQYJKoZIhvcNAQELBQADggEBAEC2KG/4eS51Vl6ulDuTIJXl11KC8E/kwQ7UbC5JFQnvwfUltXTN6xzMCvdjl1NJMKNzdRg701IC0fH8S4BAdBEzs84rRyxS2EaKNBTvBLQPs2uSduAtySt90uzr8+i0rjMzoxmgzjTK2+r190ZWsBZ1BzPeuPa0tTB8XowwpM2N7zschNjpBURzbfBGVnKpgp/o6+xLtdBr3g+xrpLfpiwcudg2mrDrBMxjwe6HfQ6WjXVKvBMK94BdOWCLaF1bs0F/NEeNzvQmw86U44vFfHb/ntmvqShey9LT8C8fFNVSnVxm/VXrRzdcKVZUphNiD/nxU54/xbXF2PckI/tMQ2k=",
				tools.getCertRepresentation(testCert));

		Assert.assertEquals(
				"MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA31wT4e9cZHaLZLR9/tLu8cpnhhuDNy4evxr16lZkr8AaJ6Kqc8dwlxA48704GFJGO6284+43XeVCEi7zaQysqE9/ZXCqVwHDcwhP/vOjyGQvCdvEI1/DEkbEUhpAhZbdjyDeFowBVTjX2LMGJm4ic4M1w+7KzC7FiT7Snq/m0CyH7hDiPJ5e0hCFuJeHHtlMrJUqXILtu2XI6wv5aITzg1CHKEh8WC0JfLUrKlN/hBqS4CfEGfmG1FksRHyY/JCFu+rj3aNkpq9bv5y4omfmsq/YN0whlXHnjkdien1JnrMin/sryCYYi4F5n23g6Flg+ADiWPFAiDlNRXSyo4xznKtcE0N3vmLSVMfgXf4bMrik6A56S3P7cPBKM+y7t/r0moqu8j3MslJel745n/DgSNl92jVNW7z8c85ZAU+DBk1n+/WCDWLD6yBXaoKK25ywXrpvEg2W0/VaRYYs4gKDcbBfcCrQ5z5SAqkaFS2k8GgjW2LLU2m5GALF3FASqIgFSebPgOay9yUOpODs864y709x8Fz4rZmdlKP4pKcZ9FZ9pTY6PwekghWhE+JgBJLCjbYKdlBbz2WbGWuMELgyC6mt2nyUpJLxK8Lyi5c8Yd1ipOAY5Y52INpYtPUg7KhCShfCj8S09eaiPY4GVN6tire2nW+S/oP3HKSbPf+FLyUCAwEAAQ==",
				tools.getPublicKey(testCert));

		Assert.assertEquals(
				"QLYob/h5LnVWXq6UO5MgleXXUoLwT+TBDtRsLkkVCe/B9SW1dM3rHMwK92OXU0kwo3N1GDvTUgLR8fxLgEB0ETOzzitHLFLYRoo0FO8EtA+za5J24C3JK33S7Ovz6LSuMzOjGaDONMrb6vX3RlawFnUHM9649rS1MHxejDCkzY3vOxyE2OkFRHNt8EZWcqmCn+jr7Eu10GveD7Gukt+mLBy52DaasOsEzGPB7od9DpaNdUq8Ewr3gF05YItoXVuzQX80R43O9CbDzpTji8V8dv+e2a+pKF7L0tPwLx8U1VKdXGb9VetHN1wpVlSmE2IP+fFTnj/FtcXY9yQj+0xDaQ==",
				tools.getSignature(testCert));
		
		Assert.assertEquals(false, tools.isForCRLSign(testCert));
		Assert.assertEquals(true, tools.isForDigitalSignature(testCert));
		Assert.assertEquals(false, tools.isForKeyCertSign(testCert));
		Assert.assertEquals(true, tools.isForKeyEncipherment(testCert));
		
		Assert.assertEquals("52c1956811ec17192dbd04ad6118b44f", tools.getSerialNumber(testCert));
		
		Assert.assertEquals("b0ffcf3a1d82449815629d64886a4165", tools.getIssuerSerialNumber(testCert));
		
		Assert.assertEquals("C786B6631BC3CBD45BD20925293837425BDD17E3", tools.getSHA1Fingerprint(testCert));
		
		Assert.assertEquals("952DF75D64F8A9E9EA2997E602884590215E9D9A30F95E81B08A10FC63D9E630", tools.getSHA256Fingerprint(testCert));
		
		Assert.assertEquals("SHA256withRSA", tools.getSignatureAlgorithmName(testCert));
		
		Assert.assertEquals("CN=campus.aau.at,OU=Domain Control Validated", tools.getSubjectDistinguishedName(testCert).replaceAll(", ", ","));
		
		Assert.assertEquals("CN=TERENA SSL CA 2,O=TERENA,L=Amsterdam,ST=Noord-Holland,C=NL", tools.getIssuerDistinguishedName(testCert));
		
		Assert.assertEquals(true, tools.verifyAllCerts());
		
		
		int rootCA = tools.getCertificateChain().get(3);
		//Die RootCA hat sich selbst zertifiziert
		Assert.assertEquals(tools.getSerialNumber(rootCA), tools.getIssuerSerialNumber(rootCA));
		Assert.assertEquals(tools.getSubjectDistinguishedName(rootCA), tools.getIssuerDistinguishedName(rootCA));
	}
}
