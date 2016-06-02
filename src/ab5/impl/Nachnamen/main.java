package ab5.impl.Nachnamen;

import javax.net.ssl.HttpsURLConnection;
import java.net.URL;
import java.security.cert.Certificate;

/**
 * Created by Luki on 26.05.2016.
 */
public class main {

    public static void main(String[] args) throws Exception{
        CertToolsImpl cti = new CertToolsImpl();
        cti.loadServerCerts("campus.aau.at",443);
        System.out.print(cti.getSerialNumber(0) + "\n");
        System.out.print(cti.getSerialNumber(1) + "\n");
        System.out.print(cti.getSerialNumber(2) + "\n");
        System.out.print(cti.getSerialNumber(3) + "\n");




        /*URL httpsURL = new URL("https://campus.aau.at/");
        HttpsURLConnection connection = (HttpsURLConnection) httpsURL.openConnection();
        connection.connect();
        Certificate[] certs = connection.getServerCertificates();
        for (Certificate cer : certs) {
            System.out.println(cer.getPublicKey());
        }*/

    }

}
