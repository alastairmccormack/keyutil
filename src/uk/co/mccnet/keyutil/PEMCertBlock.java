package uk.co.mccnet.keyutil;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.regex.Matcher;

import org.apache.commons.codec.binary.Base64;

public class PEMCertBlock extends PEMBlock {

	public PEMCertBlock(String pem) throws PEMBlockException {
		super(pem);
	}

	/**
	 * Converts a PEM block (with or without headers and footer) to a
	 * {@link X509Certificate}
	 * 
	 * @param pem
	 * @return an {@link X509Certificate} of the give PEM
	 * @throws PEMFileException 
	 */
	public static X509Certificate getCert(String pem) throws PEMBlockException {
				
		if (! Base64.isBase64(pem) ) {
			throw new PEMBlockException("PEM block does not contain valid Base64 data");
		}
		
		byte[] der = Base64.decodeBase64(pem);
		
		ByteArrayInputStream bais = new ByteArrayInputStream(der);
		CertificateFactory cf;
		try {
			cf = CertificateFactory.getInstance("X.509");
			X509Certificate cert = (X509Certificate) cf.generateCertificate(bais);
			return cert;
		} catch (CertificateException e) {
			throw new PEMBlockException("Can not create certificate from PEM block", e);
		}
	}
	
	public X509Certificate getCert() throws PEMBlockException {
		return getCert(pemString);
	}
	
	public static PEMCertBlock fromCert(X509Certificate x509Certificate, boolean trusted) throws PEMBlockException {
		byte[] der;
		try {
			der = x509Certificate.getEncoded();
		} catch (CertificateEncodingException e) {
			throw new PEMBlockException(e);
		}
		
		String rawPem = new String(Base64.encodeBase64Chunked(der), StandardCharsets.US_ASCII);
		StringBuilder pemStringB = new StringBuilder(rawPem);
		
		if (trusted) {
			pemStringB.insert(0, trustedCertBegin);
			pemStringB.append(trustedCertEnd);
		} else {
			pemStringB.insert(0, certBegin);
			pemStringB.append(certEnd);
		}
		
		String pem = pemStringB.toString();
		return new PEMCertBlock(pem);
	}
	
}
