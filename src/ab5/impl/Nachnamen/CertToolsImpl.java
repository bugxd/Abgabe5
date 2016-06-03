package ab5.impl.Nachnamen;

import java.net.URL;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.*;

import ab5.CertTools;

import javax.net.SocketFactory;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.xml.bind.DatatypeConverter;

public class CertToolsImpl implements CertTools {
	private Set<X509Certificate> certificates = new HashSet<>();;

	@Override
	public boolean loadServerCerts(String host, Integer port){

		/*try{
			URL httpsURL = new URL("https://campus.aau.at/");
			HttpsURLConnection connection = (HttpsURLConnection) httpsURL.openConnection();
			connection.connect();
			Certificate[] certs = connection.getServerCertificates();
			for (Certificate cert : certs) {
				if(cert instanceof X509Certificate) {
					certificates.add((X509Certificate) cert);
				}
			}
		}
		catch (Exception ex){
			ex.printStackTrace();
			return false;
		}*/

		try{
			SocketFactory factory = SSLSocketFactory.getDefault();
			SSLSocket socket = (SSLSocket) factory.createSocket(host, port);

			socket.startHandshake();

			for (Certificate cert :socket.getSession().getPeerCertificates()) {
				if(cert instanceof X509Certificate) {
					certificates.add((X509Certificate) cert);
				}
			}
		}
		catch (Exception e){
			e.printStackTrace();
			return false;
		}

		return true;
	}

	@Override
	public void setCerts(Set<X509Certificate> certs) {
		certificates = certs;
	}

	@Override
	public int getNumberCerts() {
		return certificates.size();
	}

	@Override
	public String getCertRepresentation(int cert) {
		if (cert >= this.certificates.size())
			return null;

		X509Certificate certificate = (X509Certificate) certificates.toArray()[cert];

		try {
			byte[] derCert = certificate.getEncoded();

			String pemCert = new String(Base64.getEncoder().encode(derCert));
			return pemCert;
		} catch (CertificateEncodingException e) {
			e.printStackTrace();
		}
		return null;
	}

	@Override
	public String getPublicKey(int cert) {
		if (cert >= this.certificates.size())
			return null;

		X509Certificate certificate = (X509Certificate) certificates.toArray()[cert];

		String publicKey = new String(Base64.getEncoder().encode(certificate.getPublicKey().getEncoded()));
		return publicKey;
	}

	@Override
	public String getSignatureAlgorithmName(int cert) {
		if (cert >= this.certificates.size())
			return null;

		X509Certificate certificate = (X509Certificate) certificates.toArray()[cert];
		return certificate.getSigAlgName();
	}

	@Override
	public String getSubjectDistinguishedName(int cert) {
		if (cert >= this.certificates.size())
			return null;

		X509Certificate certificate = (X509Certificate) certificates.toArray()[cert];
		return certificate.getSubjectX500Principal().getName();
	}

	@Override
	public String getIssuerDistinguishedName(int cert) {
		if (cert >= this.certificates.size())
			return null;

		X509Certificate certificate = (X509Certificate) certificates.toArray()[cert];
		return certificate.getIssuerX500Principal().getName();
	}

	@Override
	public Date getValidFrom(int cert) {
		if (cert >= this.certificates.size())
			return null;

		X509Certificate certificate = (X509Certificate) certificates.toArray()[cert];
		return certificate.getNotBefore();
	}

	@Override
	public Date getValidUntil(int cert) {
		if (cert >= this.certificates.size())
			return null;

		X509Certificate certificate = (X509Certificate) certificates.toArray()[cert];
		return certificate.getNotAfter();
	}

	@Override
	public String getSerialNumber(int cert) {
		if (cert >= this.certificates.size())
			return null;

		X509Certificate certificate = (X509Certificate) certificates.toArray()[cert];
		String hexString = printHexHash(certificate.getSerialNumber().toByteArray());

		// pos of first none zero
		int pos_beginning = 0;
		for (int i = 0; i < hexString.length(); i++)
		{
			if (hexString.charAt(i) != '0') {
				pos_beginning = i;
				break;
			}
		}

		return hexString.substring(pos_beginning);
	}

	@Override
	public String getIssuerSerialNumber(int cert) {
		if (cert >= this.certificates.size())
			return null;

		int pos_issuerCert = this.getIsserCertNumber(cert);

		if (pos_issuerCert == -1)
		{
			X509Certificate certificate = (X509Certificate) certificates.toArray()[cert];
			String hexString = printHexHash(certificate.getSerialNumber().toByteArray());

			// pos of first none zero
			int pos_beginning = 0;
			for (int i = 0; i < hexString.length(); i++)
			{
				if (hexString.charAt(i) != '0') {
					pos_beginning = i;
					break;
				}
			}

			return hexString.substring(pos_beginning);
		}

		X509Certificate issuerCertificate = (X509Certificate) certificates.toArray()[pos_issuerCert];
		String hexString = printHexHash(issuerCertificate.getSerialNumber().toByteArray());

		// pos of first none zero
		int pos_beginning = 0;
		for (int i = 0; i < hexString.length(); i++)
		{
			if (hexString.charAt(i) != '0') {
				pos_beginning = i;
				break;
			}
		}

		return hexString.substring(pos_beginning);
	}

	@Override
	public String getSignature(int cert) {
		if (cert >= this.certificates.size())
			return null;

		X509Certificate certificate = (X509Certificate) certificates.toArray()[cert];
		String signature = new String(Base64.getEncoder().encode(certificate.getSignature()));

		return signature;
	}

	public static String printHexHash(byte[] byteData){
		StringBuffer hexString = new StringBuffer();
		for (int i=0;i<byteData.length;i++) {
			String hex=Integer.toHexString(0xff & byteData[i]);
			if(hex.length()==1) hexString.append('0');
			hexString.append(hex);
		}
		return hexString.toString();
	}

	public static String getFingerprint(String instance, X509Certificate certificate){
		try{
			MessageDigest md = MessageDigest.getInstance(instance);
			md.update(certificate.getEncoded());
			return printHexHash(md.digest());
		}catch (Exception e){
			return null;
		}
	}

	@Override
	public String getSHA1Fingerprint(int cert) {
		if (cert >= this.certificates.size())
			return null;

		X509Certificate certificate = (X509Certificate) certificates.toArray()[cert];
		return getFingerprint("SHA-1",certificate).toUpperCase();
	}

	@Override
	public String getSHA256Fingerprint(int cert) {
		if (cert >= this.certificates.size())
			return null;

		X509Certificate certificate = (X509Certificate) certificates.toArray()[cert];
		return getFingerprint("SHA-256",certificate).toUpperCase();
	}

	//KeyUsage ::= BIT STRING {
	//			digitalSignature        (0),
	//			nonRepudiation          (1),
	//			keyEncipherment         (2),
	//			dataEncipherment        (3),
	//			keyAgreement            (4),
	//			keyCertSign             (5),
	//			cRLSign                 (6),
	//			encipherOnly            (7),
	//			decipherOnly            (8) }
	//

	@Override
	public boolean isForDigitalSignature(int cert) {
		if (cert >= this.certificates.size())
			return false;

		X509Certificate certificate = (X509Certificate) certificates.toArray()[cert];

		if (certificate.getKeyUsage()[0])
			return true;

		return false;
	}

	@Override
	public boolean isForKeyEncipherment(int cert) {
		if (cert >= this.certificates.size())
			return false;

		X509Certificate certificate = (X509Certificate) certificates.toArray()[cert];

		if (certificate.getKeyUsage()[2])
			return true;

		return false;
	}

	@Override
	public boolean isForKeyCertSign(int cert) {
		if (cert >= this.certificates.size())
			return false;

		X509Certificate certificate = (X509Certificate) certificates.toArray()[cert];

		if (certificate.getKeyUsage()[5])
			return true;

		return false;
	}

	@Override
	public boolean isForCRLSign(int cert) {
		if (cert >= this.certificates.size())
			return false;

		X509Certificate certificate = (X509Certificate) certificates.toArray()[cert];

		if (certificate.getKeyUsage()[6])
			return true;

		return false;
	}

	@Override
	public boolean verifyAllCerts() {

		List<Integer> certChain = this.getCertificateChain();
		Object certArray[] = this.certificates.toArray();

		try
		{
			for (int i = 0; i < certChain.size() - 1; i++)
			{
				X509Certificate currCert = (X509Certificate) certArray[certChain.get(i)];
				X509Certificate currCertParent = (X509Certificate) certArray[certChain.get(i+1)];

				currCert.verify(currCertParent.getPublicKey());
			}

			X509Certificate rootCa = (X509Certificate) certArray[certChain.get(certChain.size() - 1)];
			rootCa.verify(rootCa.getPublicKey());

		} catch (CertificateExpiredException e) {
			e.printStackTrace();
			return false;
		} catch (CertificateNotYetValidException e) {
			e.printStackTrace();
			return false;
		} catch (CertificateException e) {
			e.printStackTrace();
			return false;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			return false;
		} catch (SignatureException e) {
			e.printStackTrace();
			return false;
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
			return false;
		}

		// TODO Auto-generated method stub
		return true;
	}

	@Override
	public int getIsserCertNumber(int cert) {
		if (cert >= this.certificates.size())
			return -1;

		List<Integer> chain = this.getCertificateChain();

		int pos_cert = chain.lastIndexOf(cert);
		if (pos_cert >= chain.size() - 1)
			return -1;
		else
			return chain.get(pos_cert + 1);
	}

	@Override
	public List<Integer> getCertificateChain() {

		List<Integer> certificateChain = new ArrayList<>();
		Object certArray[] = this.certificates.toArray();

		// search root ca
		Integer rootCaIndex = null;

		for(int i = 0; i < this.certificates.size(); i++)
		{
			X509Certificate currCert = (X509Certificate) certArray[i];
			if (currCert.getIssuerX500Principal().equals(currCert.getSubjectX500Principal()))
			{
				rootCaIndex = i;
				certificateChain.add(rootCaIndex);
				break;
			}
		}

		if (rootCaIndex == null)
			return null;

		// get child after child
		while (certificateChain.size() < certArray.length)
		{
			X509Certificate parent = (X509Certificate) certArray[certificateChain.get(certificateChain.size() - 1)];
			Integer childIndex = this.getChildCertificate(parent, certArray);

			if (childIndex == null)
				return null;

			certificateChain.add(childIndex);
		}

		// reverse list
		Collections.reverse(certificateChain);

		// TODO Auto-generated method stub
		return certificateChain;
	}

	public Integer getChildCertificate(X509Certificate parent, Object[] possible_children)
	{
		for (int i = 0; i < possible_children.length; i++)
		{
			X509Certificate currChild = (X509Certificate) possible_children[i];
			if (currChild.getIssuerX500Principal().equals(parent.getSubjectX500Principal()) && !currChild.equals(parent))
				return i;
		}
		return null;
	}

}
