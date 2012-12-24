package uk.co.mccnet.keyutil;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


/**
 * Opens CA PEM certificate bundles files (such as ca-bundle.crt). 
 * 
 * A PEM bundle consists of individual PEM certificates concatenated together with optional text descriptions.
 * Each certificate starts with either: <p><code>-----BEGIN TRUSTED CERTIFICATE-----</code>
 * or
 * <code>-----BEGIN CERTIFICATE-----</code>
 * <p>
 * The end of a certificate is signified with:<p><code>-----END TRUSTED CERTIFICATE-----</code>
 * or
 * <code>-----END CERTIFICATE-----</code>
 * <p>
 * 
 * All other text is ignored
 * 
 */
public class PEMFile {
	Pattern pemBeginPattern = Pattern.compile("-+BEGIN.*?CERTIFICATE-+");
	Pattern pemEndPattern = Pattern.compile("-+END.*?CERTIFICATE-+");
	String fileName;
	File pemFile;
	
	/**
	 * @param pemFile				a file containing PEM formatted certificates
	 */
	public PEMFile(File pemFile) {
		this.pemFile = pemFile;
	}
	
	/**
	 * Splits a CA bundle into individual PEM certificate blocks
	 * 
	 * @return						an <code>ArrayList</code> of PEM Certificates
	 * @throws IOException
	 */
	public ArrayList<String> getPEMBlocks() throws IOException {
		FileReader fr = new FileReader(pemFile);
		BufferedReader pemFileBR = new BufferedReader(fr);
		ArrayList<String> result = new ArrayList<String>();
		
		try {
			Boolean inBlock = false;
			String pemBlock = null;
			while (pemFileBR.ready()) {
				String line = pemFileBR.readLine();
					
				if (!inBlock) {
					// look for start of block
					Matcher beginPatternMatcher = pemBeginPattern.matcher(line);
					if (beginPatternMatcher.find()) {
						inBlock = true;
						pemBlock = "";
					}				
				} else {
					Matcher endPatternMatcher = pemEndPattern.matcher(line);
					if (endPatternMatcher.find()) {
						result.add(pemBlock);
						inBlock = false;
					} else {
						// We must me in a pemblock
						pemBlock += line;
					}
				}
			}
			
		} finally {
			pemFileBR.close();
		}
		
		if (result.isEmpty()) {
			return null;
		} else {
			return result;
		}
	}

}
