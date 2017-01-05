package uk.co.mccnet.keyutil;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.KeyStore.Entry;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.logging.Logger;
import javax.security.auth.x500.X500Principal;
import org.apache.commons.codec.binary.Base64;

import uk.co.mccnet.keyutil.PEMBlock.Type;
import uk.co.mccnet.keyutil.cli.Main;


/**
 * Simple utility class to import PEM strings, PEM Strings and JKS files into a single JKS Keystore/Truststore
 *
 * @see PEMFile
 *
 */

public class JKSKeyStoreUtil {
	private File file;
	private KeyStore keyStore;

	private static Logger logger = Logger.getLogger(Main.class.getName());

	/**
	 * Creates a new JKSKeyStoreUtil instance.
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
	 * Creates a new JKSKeyStoreUtil from an existing JKS file
	 *
	 * @param file								existing JKS file
	 * @param password							password to open JKS file
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
	public void importPEM(PEMBlock pemBlock) throws JKSKeyStoreUtilException, IOException {

		if (! pemBlock.isCert() ) {
			throw new JKSKeyStoreUtilException("PEM is not a certificate");
		}

		PEMCertBlock pemCertBlock = (PEMCertBlock) pemBlock;
		
		X509Certificate cert;
		try {
			cert = pemCertBlock.getCert();
			String alias = getCertAlias(cert);

			if (alias == null) {
				logger.warning(String.format("Can not suitable alias for cert %s", getDN(cert)));
			} else if (containsAlias(alias)) {
				logger.warning(String.format( "%s alias already exists (%s)", alias, getDN(cert) ));
			} else {
				logger.fine("Adding Cert with alias: " + alias);
				keyStore.setCertificateEntry(alias, cert);
			}

		} catch (PEMBlockException e) {
			throw new JKSKeyStoreUtilException(e);
		} catch (KeyStoreException e) {
			throw new JKSKeyStoreUtilException(e);
		}

	}

	protected void importKey(PEMKeyBlock pemKeyBlock, PEMCertBlock pemCertBlock,
			String alias, String password) throws JKSKeyStoreUtilException {

		try {
			PrivateKey privateKey = pemKeyBlock.getKey(password);
			X509Certificate[] cert = new X509Certificate[1];
			cert[0] = pemCertBlock.getCert();

			keyStore.setKeyEntry(alias, privateKey.getEncoded(), cert);

		} catch (PEMBlockException e) {
			throw new JKSKeyStoreUtilException(e);
		} catch (KeyStoreException e) {
			throw new JKSKeyStoreUtilException(e);
		}
	}


	/**
	 * @param pemFile imports a whole {@link PEMFileException} object
	 * @throws JKSKeyStoreUtilException
	 * @throws IOException
	 * @throws PEMFileException
	 */
	public void importPEMFile(PEMFile pemFile) throws JKSKeyStoreUtilException, PEMFileException, IOException {

		Iterator<PEMBlock> pemBlocks = pemFile.getPEMBlocks();

		while (pemBlocks.hasNext()) {
			// FIXME - Missing private key bit
			PEMBlock pemBlock = pemBlocks.next();
			if (pemBlock.isCert()) {
				importPEM(pemBlock);
			}
		}
	}

	public PrivateKey getKey(String alias, String password) throws JKSKeyStoreUtilException {
		KeyStore.PasswordProtection keyStorePasswordProtection =
				new KeyStore.PasswordProtection(password.toCharArray());

		try {
			PrivateKeyEntry keyEntry = (PrivateKeyEntry) keyStore.getEntry(alias,
					keyStorePasswordProtection);
			return keyEntry.getPrivateKey();
		} catch (NoSuchAlgorithmException e) {
			throw new JKSKeyStoreUtilException(e);
		} catch (UnrecoverableEntryException e) {
			throw new JKSKeyStoreUtilException(e);
		} catch (KeyStoreException e) {
			throw new JKSKeyStoreUtilException(e);
		}
	}

	public PEMFile getPemFile(String password) throws JKSKeyStoreUtilException {
		PEMFile pemFile = new PEMFile();
		Enumeration<String> aliases;
		try {
			aliases = keyStore.aliases();
		} catch (KeyStoreException e) {
			throw new JKSKeyStoreUtilException(e);
		}

		while (aliases.hasMoreElements()) {
			String alias = aliases.nextElement();

			try {

				if (keyStore.isCertificateEntry(alias)) {
					X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
					PEMCertBlock pemCertBlock = PEMCertBlock.fromCert(certificate, false);

					pemFile.addPem(pemCertBlock);

				} else if (keyStore.isKeyEntry(alias)) {

					PrivateKey pk = (PrivateKey) keyStore.getKey(alias, password.toCharArray());

					PEMKeyBlock pemKeyBlock = PEMKeyBlock.fromPrivateKey(pk);
					pemFile.addPem(pemKeyBlock);

					Certificate[] certs = keyStore.getCertificateChain(alias);

					for (Certificate certificate : certs) {
						byte[] der = certificate.getEncoded();
						PEMBlock pemBlock = new PEMBlock(der, Type.CERT);
						pemFile.addPem(pemBlock);
					}

				} else {
					logger.warning(String.format("Alias '%s' not key or certificate", alias));
				}



			} catch (NoSuchAlgorithmException e) {
				throw new JKSKeyStoreUtilException(e);
			} catch (UnrecoverableEntryException e) {
				throw new JKSKeyStoreUtilException(e);
			} catch (KeyStoreException e) {
				throw new JKSKeyStoreUtilException(e);
			} catch (PEMBlockException e) {
				throw new JKSKeyStoreUtilException(e);
			} catch (CertificateEncodingException e) {
				throw new JKSKeyStoreUtilException(e);
			}



		}

		return pemFile;
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
