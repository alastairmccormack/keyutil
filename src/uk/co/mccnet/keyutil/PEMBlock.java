package uk.co.mccnet.keyutil;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.codec.binary.Base64;

public class PEMBlock {
	
	public enum Type {
	    CERT, TRUSTED_CERT, PKCS8_KEY, PKCS8_ENCRYPTED_KEY, SSLEAY_KEY
	}
	
	Type type = null;
	
	static final Pattern pemBeginPattern = Pattern.compile("-+BEGIN.*?(CERTIFICATE|KEY)-+");
	static final Pattern pemEndPattern =   Pattern.compile("-+END.*?(CERTIFICATE|KEY)-+");

	static final String trustedCertBegin = "-----BEGIN TRUSTED CERTIFICATE-----";
	static final String trustedCertEnd =   "-----END TRUSTED CERTIFICATE-----";
	
	static final String certBegin = "-----BEGIN CERTIFICATE-----";
	static final String certEnd =   "-----END CERTIFICATE-----";
	
	static final String pkcs8KeyBegin = "-----BEGIN PRIVATE KEY-----";
	static final String pkcs8KeyEnd =   "-----END PRIVATE KEY-----";
	
	static final String pkcs8EncryptedKeyBegin = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
	static final String pkcs8EncryptedKeyEnd =   "-----END ENCRYPTED PRIVATE KEY-----";
	
	static final String ssleayKeyBegin = "-----BEGIN RSA PRIVATE KEY-----";
	static final String ssleayKeyEnd =   "-----END RSA PRIVATE KEY-----";
	
	protected String pemString;
	protected String rawPem;
	protected byte[] der;
		
	public PEMBlock(String pem) throws PEMBlockException {
		pemString = pem;

		if (pem.contains(certBegin)) type = Type.CERT;
		else if (pem.contains(trustedCertBegin)) type = Type.TRUSTED_CERT;
		else if (pem.contains(pkcs8KeyBegin)) type = Type.PKCS8_KEY;
		else if (pem.contains(pkcs8EncryptedKeyBegin)) type = Type.PKCS8_ENCRYPTED_KEY;
		else if (pem.contains(ssleayKeyBegin)) type = Type.SSLEAY_KEY;
		else throw new PEMBlockException("Unknow PEM type");
		
		// count pem headers
		Matcher pemHeaderMatcher = pemBeginPattern.matcher(pemString);
		int pemHeaderCount = 0;
		while (pemHeaderMatcher.find())
			pemHeaderCount++;
		
		if (pemHeaderCount > 1) {
			throw new PEMBlockException("More than one PEM block found");
		}
		
		// Remove pemHeader
		rawPem = pemHeaderMatcher.replaceAll("");
		// Remove pemFooter
		rawPem = pemEndPattern.matcher(pemString).replaceAll("");
	}
	
	/**
	 * Returns a {@link PEMBlock} from a raw pem block without headers and footers.
	 * 
	 * @param rawPem
	 * @param type
	 * @throws PEMBlockException 
	 */
	public PEMBlock(String rawPem, Type type) throws PEMBlockException {
		this.rawPem = rawPem;
		this.type = type;
		pemString = assembleFromRawPem(rawPem, type);
	}
	
	public PEMBlock(byte[] der, Type type) throws PEMBlockException {
		
		Base64 base64 = new Base64(64);
		
		byte[] base64Bytes = base64.encode(der);
		rawPem = new String(base64Bytes, StandardCharsets.US_ASCII);
		
		rawPem = rawPem.trim(); 
		pemString = assembleFromRawPem(rawPem, type);
		this.type = type;
	}

	private String assembleFromRawPem(String rawPem, Type type) throws PEMBlockException {
		String start = null;
		String end = null;
		
		switch (type) {
			case CERT:
				start = certBegin;
				end = certEnd;
				break;
			case PKCS8_ENCRYPTED_KEY:
				start = pkcs8EncryptedKeyBegin;
				end = pkcs8EncryptedKeyEnd;
				break;
			case PKCS8_KEY:
				start = pkcs8KeyBegin;
				end = pkcs8KeyEnd;
				break;
			case SSLEAY_KEY:
				start = ssleayKeyBegin;
				end = ssleayKeyEnd;
				break;
			case TRUSTED_CERT:
				start = trustedCertBegin;
				end = trustedCertEnd;
				break;
			default:
				throw new PEMBlockException(String.format("Unable to prepare %s type PEM", type));		
		}
		
		StringBuilder pemBuilder = new StringBuilder();
		pemBuilder.append(start);
		pemBuilder.append("\n");
		pemBuilder.append(rawPem);
		pemBuilder.append("\n");
		pemBuilder.append(end);
		pemBuilder.append("\n");
		
		return pemBuilder.toString();
	}

	
	public boolean isKey() {
		if (type ==  Type.PKCS8_ENCRYPTED_KEY || type == Type.PKCS8_KEY 
				|| type == Type.SSLEAY_KEY) {
					return true;
				}
		else {
			return false;
		}
	}
	
	public boolean isCert() {
		return ! isKey();
	}
	
	
	@Override
	public String toString() {
		return pemString;
	}
	
	public Type getType(){
		return type;
	}
}
