package ab5.impl.Nachnamen;

import java.net.URL;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.X509Certificate;
import java.util.*;

import ab5.CertTools;

import javax.net.SocketFactory;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.xml.bind.DatatypeConverter;

public class CertToolsImpl implements CertTools {
	private Set<X509Certificate> certificates;

	@Override
	public boolean loadServerCerts(String host, Integer port){
		certificates = new HashSet<>();

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

	public void PrintCert(int cert){
		X509Certificate certificate = (X509Certificate) certificates.toArray()[cert];
		System.out.print(certificate.toString());
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
		X509Certificate certificate = (X509Certificate) certificates.toArray()[cert];


		try {
			return DatatypeConverter.printBase64Binary(certificate.getEncoded()); // .replaceAll("(.{64})", "$1\n") für Base64 spezifikation
		} catch (CertificateEncodingException e) {
			e.printStackTrace();
			return null;
		}
	}

	@Override
	public String getPublicKey(int cert) {
		X509Certificate certificate = (X509Certificate) certificates.toArray()[cert];

		return certificate.getPublicKey().toString();
	}

	@Override
	public String getSignatureAlgorithmName(int cert) {
		X509Certificate certificate = (X509Certificate) certificates.toArray()[cert];
		return certificate.getSigAlgName();
	}

	@Override
	public String getSubjectDistinguishedName(int cert) {
		X509Certificate certificate = (X509Certificate) certificates.toArray()[cert];
		return certificate.getSubjectDN().toString();
	}

	@Override
	public String getIssuerDistinguishedName(int cert) {
		X509Certificate certificate = (X509Certificate) certificates.toArray()[cert];
		return certificate.getIssuerDN().toString();
	}

	@Override
	public Date getValidFrom(int cert) {
		X509Certificate certificate = (X509Certificate) certificates.toArray()[cert];
		return certificate.getNotBefore();
	}

	@Override
	public Date getValidUntil(int cert) {
		X509Certificate certificate = (X509Certificate) certificates.toArray()[cert];
		return certificate.getNotAfter();
	}

	@Override
	public String getSerialNumber(int cert) {
		X509Certificate certificate = (X509Certificate) certificates.toArray()[cert];
		return certificate.getSerialNumber().toString();
	}

	@Override
	public String getIssuerSerialNumber(int cert) {
		X509Certificate certificate = (X509Certificate) certificates.toArray()[cert];

		return certificate.getIssuerUniqueID().toString();
	}

	@Override
	public String getSignature(int cert) {
		X509Certificate certificate = (X509Certificate) certificates.toArray()[cert];
		return certificate.getSignature().toString();
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
		X509Certificate certificate = (X509Certificate) certificates.toArray()[cert];
		return getFingerprint("SHA-1",certificate);
	}

	@Override
	public String getSHA256Fingerprint(int cert) {
		X509Certificate certificate = (X509Certificate) certificates.toArray()[cert];
		return getFingerprint("SHA-256",certificate);
	}

	@Override
	public boolean isForDigitalSignature(int cert) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isForKeyEncipherment(int cert) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isForKeyCertSign(int cert) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isForCRLSign(int cert) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean verifyAllCerts() {
		try {
			for (X509Certificate cert : certificates) {
				cert.verify(cert.getPublicKey());
			}
		}catch (Exception e){
			e.printStackTrace();
			return false;
		}

		return true;
	}

	@Override
	public int getIsserCertNumber(int cert) {
		X509Certificate certificate = (X509Certificate) certificates.toArray()[cert];
		return 0;
	}

	@Override
	public List<Integer> getCertificateChain() {
		return null;
	}

}
