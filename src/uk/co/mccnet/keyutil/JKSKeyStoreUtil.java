package uk.co.mccnet.keyutil;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.logging.Logger;
import javax.security.auth.x500.X500Principal;
import org.apache.commons.codec.binary.Base64;


/**
 * Simple utility class to import PEM strings, PEM Strings and JKS files into a single JKS Keystore/Truststore
 * 
 * @see PEMFile
 *
 */

public class JKSKeyStoreUtil {
	File file;
	KeyStore keyStore;
	
	private static Logger logger = Logger.getLogger(Main.class.getName());
	
	/**
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws IOException
	 * @throws JKSKeyStoreUtilException
	 */	
	public JKSKeyStoreUtil() throws NoSuchAlgorithmException, CertificateException, IOException, JKSKeyStoreUtilException {
		
		try {
			keyStore = KeyStore.getInstance("JKS");
		} catch (KeyStoreException e) {
			throw new JKSKeyStoreUtilException(e);
		}
		
		keyStore.load(null);
	}
	
	
	/**
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws IOException
	 * @throws JKSKeyStoreUtilException
	 */	
	public JKSKeyStoreUtil(File file, String password) throws NoSuchAlgorithmException, CertificateException, IOException, JKSKeyStoreUtilException {
		
		try {
			keyStore = KeyStore.getInstance("JKS");
		} catch (KeyStoreException e) {
			throw new JKSKeyStoreUtilException(e);
		}
		
		FileInputStream fis = new FileInputStream(file);
		keyStore.load(fis, password.toCharArray());
		fis.close();
	}
	
	/**
	 * Saves changes
	 * 
	 * @throws JKSKeyStoreUtilException
	 * @throws IOException
	 */
	public void save(File file, String password) throws JKSKeyStoreUtilException, IOException {
		file.createNewFile();
		
		FileOutputStream fos = new FileOutputStream(file);
		try {
			logger.info("Saving to: " + file.getName());
			keyStore.store(fos, password.toCharArray() );
		} catch (Exception e) {
			throw new JKSKeyStoreUtilException(e);
		} finally {
			fos.close();
		}
		
	}
	
	/**
	 * Adds a PEM formatted string
	 * 
	 * @param pem							pem formated certificate
	 * @throws JKSKeyStoreUtilException
	 * @throws IOException
	 */
	public void importPEM(String pem) throws JKSKeyStoreUtilException, IOException {
		if (! Base64.isBase64(pem) ) {
			throw new JKSKeyStoreUtilException("PEM File does not contain valid Base64 data");
		}
		
		byte[] der = Base64.decodeBase64(pem);
		try {
			ByteArrayInputStream bais = new ByteArrayInputStream(der);
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509Certificate cert = (X509Certificate) cf.generateCertificate(bais); 
			
			String alias = getCertAlias(cert);
			
			if (alias == null) {
				logger.warning(String.format("Can not suitable alias for cert %s", getDN(cert)));
			} else if (containsAlias(alias)) {
				logger.warning(String.format( "%s alias already exists (%s)", alias, getDN(cert) )); 
			} else {
				logger.fine("Adding Cert with alias: " + alias);
				keyStore.setCertificateEntry(alias, cert);
			}
		} catch (Exception e) {
			throw new JKSKeyStoreUtilException(e);
		}
	}
	
	
	/**
	 * @param alias						string to check for
	 * @return							true if alias exists in Keystore
	 * @throws KeyStoreException
	 */
	public boolean containsAlias(String alias) throws KeyStoreException {
		return keyStore.containsAlias(alias);
	}
	
	/**
	 * Gets DN of a certificate
	 * 
	 * @param certificate
	 * @return								full DN of a certificate
	 */
	private String getDN(X509Certificate certificate) {
		X500Principal x509principal = certificate.getSubjectX500Principal();
		String dn = x509principal.getName("RFC2253");
		return dn;
	}
	
	private String getCertAlias(X509Certificate certificate) {
/*		String alias = "";
		
		String cn = null;
		String o = null;
		try {
			cn = getCertAttribute(certificate, "cn");
			o = getCertAttribute(certificate, "o");
		} catch (NamingException e) {
			
		}
		
		if (cn != null ) alias += cn + ", ";
		if (o != null ) alias += o;
		
		return alias;*/
		
		return getDN(certificate);
	}
	
/*	private String getCertAttribute(X509Certificate certificate, String attributeName) throws NamingException {
		String dn = getDN(certificate);
		LdapName ln = new LdapName(dn);
		
		logger.finer(String.format("Getting %s from %s", attributeName, dn));
		for (Rdn rdn : ln.getRdns()) {
			String type = rdn.getType();
			if (attributeName.toUpperCase().equals(type)) {
				return (String) rdn.getValue();
			}
		}
		return null;
				
	}*/
	
	/**
	 * @param pemFile						imports a whole {@linkplain PEMFile} object
	 * @throws JKSKeyStoreUtilException
	 * @throws IOException
	 */
	public void importPEMFile(PEMFile pemFile) throws JKSKeyStoreUtilException, IOException {
		ArrayList<String> pems = pemFile.getPEMBlocks();
		
		for (String pemString : pems) {
			importPEM(pemString);
		}
	}
	
	/**
	 * Imports certs and keys from a JKSKeyStoreUtil entries into this instance
	 * 
	 * @param importJKS						import JKS file				
	 * @throws KeyStoreException 
	 */
	public void importJKSKeyStore(JKSKeyStoreUtil importJKSU) throws KeyStoreException {		
		KeyStore importKS = importJKSU.getKeyStore();
		Enumeration<String> aliases = importKS.aliases();
		
		while (aliases.hasMoreElements()) {
			String oldalias = (String) aliases.nextElement();
			X509Certificate cert = (X509Certificate) importKS.getCertificate(oldalias);
			
			String alias = getCertAlias(cert);
			if (alias == null) {
				logger.warning(String.format("No alias found for %s", cert.toString() ) );
				continue;
			}
			
			if (containsAlias(alias)) {
				logger.warning(String.format("Alias %s already exists", alias));
				continue;
			}
			
			keyStore.setCertificateEntry(alias, cert);
		}
	}
	
	/**
	 * @return								keyStore object 
	 */
	public KeyStore getKeyStore() {
		return keyStore;
	}
	
	/**
	 * @return								Alias / Cert DN Hashmap contained in Keystore
	 * @throws KeyStoreException
	 */
	public HashMap<String, String> list() throws KeyStoreException {
		HashMap<String, String> result = new HashMap<String, String>();
		Enumeration<String> aliasesE = keyStore.aliases();
		

		
		while (aliasesE.hasMoreElements()) {
			String alias = (String) aliasesE.nextElement();
			X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
			String dn = getDN(cert);
			result.put(alias, dn);
		}
		return result;
	}
}
