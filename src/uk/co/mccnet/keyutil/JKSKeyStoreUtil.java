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
import java.util.logging.Logger;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.codec.binary.Base64;


/**
 * Simple utility to import add PEM strings and PEMFile objects to Java JKS keystores and truststores
 * 
 * @see PEMFile
 *
 */
public class JKSKeyStoreUtil {
	File file;
	KeyStore keyStore;
	private static Logger logger = Logger.getLogger(JKSKeyStoreUtil.class.getCanonicalName());

	char[] password;
	boolean deferedSave = false;
	
	
	/**
	 * @param file 							new or existing JKS file
	 * @param password						password to open JKS file
	 * @param create						create JKS file if it does not exist 
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws IOException
	 * @throws JKSKeyStoreUtilException
	 */
	protected JKSKeyStoreUtil(File file, String password, Boolean create) throws NoSuchAlgorithmException, CertificateException, IOException, JKSKeyStoreUtilException {
		this.file = file;
		
		try {
			keyStore = KeyStore.getInstance("JKS");
		} catch (KeyStoreException e) {
			throw new JKSKeyStoreUtilException(e);
		}
		
		if (password != null) this.password = password.toCharArray();
		
		if (create) {
			keyStore.load(null);
		} else {
			FileInputStream fis = new FileInputStream(file);
			keyStore.load(fis, this.password);
			fis.close();
		}
	}
	
	/**
	 * @param file							new JKS formatted key store
	 * @param password						keystore password
	 * @return								new <code>JKSKeyStoreUtil</code> object
	 * @throws JKSKeyStoreUtilException
	 */
	static public JKSKeyStoreUtil newKeyStore(File file, String password) throws JKSKeyStoreUtilException {
		try {
			return new JKSKeyStoreUtil(file, password, true);
		} catch (Exception e) {
			throw new JKSKeyStoreUtilException(e);
		}
	}
	
	/**
	 * Open existing JKS format file 
	 * 
	 * @param file							existing JKS formatted key store
	 * @param password						keystore password
	 * @return								<code>JKSKeyStoreUtil</code> object
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws IOException
	 * @throws JKSKeyStoreUtilException
	 */
	static public JKSKeyStoreUtil open(File file, String password) throws NoSuchAlgorithmException, CertificateException, IOException, JKSKeyStoreUtilException {
		return new JKSKeyStoreUtil(file, password, false);
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
			X500Principal x509principal = cert.getSubjectX500Principal();
			String alias = x509principal.getName();
			logger.info("Adding Cert with alias: " + alias);
			keyStore.setCertificateEntry(alias, cert);
		} catch (Exception e) {
			throw new JKSKeyStoreUtilException(e);
		}
		save();
	}
	
	private void save() throws JKSKeyStoreUtilException, IOException {
		if (!deferedSave) {
			file.createNewFile();
			
			FileOutputStream fos = new FileOutputStream(file);
			try {
				logger.info("Saving to: " + file.getName());
				keyStore.store(fos, password);
			} catch (Exception e) {
				throw new JKSKeyStoreUtilException(e);
			} finally {
				fos.close();
			}
		}
	}
	
	/**
	 * @param pemFile						imports a whole {@linkplain PEMFile} object
	 * @throws JKSKeyStoreUtilException
	 * @throws IOException
	 */
	public void importPEMFile(PEMFile pemFile) throws JKSKeyStoreUtilException, IOException {
		// disable saving until all imported
		deferedSave = true;
		ArrayList<String> pems = pemFile.getPEMBlocks();
		
		for (String pemString : pems) {
			importPEM(pemString);
		}
		deferedSave = false;
		save();
	}
}
