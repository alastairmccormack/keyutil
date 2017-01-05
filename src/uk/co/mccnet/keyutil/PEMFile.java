package uk.co.mccnet.keyutil;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Iterator;
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
	static Pattern pemBeginPattern = Pattern.compile("-+BEGIN.*?CERTIFICATE-+");
	static Pattern pemEndPattern = Pattern.compile("-+END.*?CERTIFICATE-+");
	String fileName;
	File pemFile;

	// unwritten PemBlocks
	ArrayList<PEMBlock> localPemBlocks = new ArrayList<PEMBlock>();

	/**
	 * @param pemFile				a file containing PEM formatted certificates
	 */
	public PEMFile(File pemFile) {
		this.pemFile = pemFile;
	}

	public PEMFile() {

	}

	/**
	 * Splits a PEM bundle into individual PEM certificate blocks
	 *
	 * @return Iterator of PEMBlocks
	 * @throws PEMFileException
	 * @throws IOException
	 */
	public Iterator<PEMBlock> getPEMBlocks() throws PEMFileException {

		ArrayList<PEMBlock> result = new ArrayList<PEMBlock>(localPemBlocks);

		if (pemFile != null) {

			FileReader fr = null;
			try {
				fr = new FileReader(pemFile);
			} catch (FileNotFoundException e1) {
				throw new PEMFileException(e1);
			}

			BufferedReader pemFileBR = new BufferedReader(fr);


			try {
				Boolean inBlock = false;
				StringBuilder pemStringBlockB = null;
				while (pemFileBR.ready()) {
					String line = pemFileBR.readLine() + "\n";

					if (!inBlock) {
						// look for start of block
						Matcher beginPatternMatcher = pemBeginPattern.matcher(line);
						if (beginPatternMatcher.find()) {
							inBlock = true;
							pemStringBlockB = new StringBuilder(line);
						}
					} else {
						// We must me in a pemblock
						pemStringBlockB.append(line);
						Matcher endPatternMatcher = pemEndPattern.matcher(line);
						if (endPatternMatcher.find()) {
							PEMBlock pemBlock = new PEMBlock(pemStringBlockB.toString());
							result.add(pemBlock);
							inBlock = false;
						}
					}
				}


			} catch (IOException e) {
				throw new PEMFileException(e);
			} catch (PEMBlockException e) {
				throw new PEMFileException(e);
			} finally {
				try {
					pemFileBR.close();
				} catch (IOException e) {
					throw new PEMFileException(e);
				}
			}
		}

		return result.iterator();
	}

	public void addPem(PEMBlock pemBlock) {
		localPemBlocks.add(pemBlock);
	}

	/**
	 * Write changes to file
	 * @throws IOException
	 * @throws PEMFileException
	 */
	public void write() throws PEMFileException, IOException {
		write(pemFile);
	}

	public void write(String filename) throws PEMFileException, IOException {
		File file = new File(filename);
		write(file);
	}

	public void write(File file) throws PEMFileException, IOException {
		FileOutputStream fos = new FileOutputStream(file);
		write(fos);
	}


	public void write(FileOutputStream fileOutputStream) throws PEMFileException, IOException {

		OutputStreamWriter outputStreamWriter = new OutputStreamWriter(fileOutputStream, StandardCharsets.US_ASCII);
		BufferedWriter bufferedWriter = new BufferedWriter(outputStreamWriter);

		bufferedWriter.write(toString());
		bufferedWriter.close();
	}

	public String toString() {

		StringBuilder stringBuilder = new StringBuilder();

		Iterator<PEMBlock> pemBlocks;

		try {
			pemBlocks = getPEMBlocks();
			while (pemBlocks.hasNext()) {
				PEMBlock pemBlock = pemBlocks.next();
				String pemString = pemBlock.toString();

				stringBuilder.append(pemString);
				stringBuilder.append("\n");
			}
		} catch (PEMFileException e) {
			e.printStackTrace();
		}

		return stringBuilder.toString();
	}

}
