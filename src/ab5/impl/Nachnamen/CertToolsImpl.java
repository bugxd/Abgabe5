package ab5.impl.Nachnamen;

import java.net.URL;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Set;

import ab5.CertTools;

import javax.net.SocketFactory;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class CertToolsImpl implements CertTools {
	private Set<X509Certificate> certificates;

	@Override
	public boolean loadServerCerts(String host, Integer port){

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
		}

		return true;
	}

	@Override
	public void setCerts(Set<X509Certificate> certs) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public int getNumberCerts() {
		return certificates.size();
	}

	@Override
	public String getCertRepresentation(int cert) {
		X509Certificate certificate = (X509Certificate) certificates.toArray()[cert];
		return null;
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
		return null;
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
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public int getIsserCertNumber(int cert) {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public List<Integer> getCertificateChain() {
		// TODO Auto-generated method stub
		return null;
	}

}
