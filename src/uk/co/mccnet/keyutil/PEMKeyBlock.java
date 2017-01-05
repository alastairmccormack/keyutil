package uk.co.mccnet.keyutil;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import org.apache.commons.ssl.PKCS8Key;

public class PEMKeyBlock extends PEMBlock {

	public PEMKeyBlock(String pem) throws PEMBlockException {
		super(pem);
	}

	public PEMKeyBlock(byte[] der, Type pkcs8Key) throws PEMBlockException {
		super(der, pkcs8Key);
	}

	public static PEMKeyBlock fromPrivateKey(PrivateKey privateKey) throws PEMBlockException {
		byte[] der = privateKey.getEncoded();

		PEMKeyBlock pemKeyBlock = new PEMKeyBlock(der, Type.PKCS8_KEY);

		return pemKeyBlock;
	}

	public PrivateKey getKey(String password) throws PEMBlockException {
		return getKey(pemString, password);
	}

	public static PrivateKey getKey(String pem, String password) throws PEMBlockException {
		PKCS8Key pkcs8Key;

		try {
			pkcs8Key = new PKCS8Key(pem.getBytes(StandardCharsets.US_ASCII), password.toCharArray());
		} catch (GeneralSecurityException e) {
			throw new PEMBlockException(e);
		}

		PrivateKey pk = pkcs8Key.getPrivateKey();
		return pk;
	}

}
