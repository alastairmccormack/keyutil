package uk.co.mccnet.keyutil.cli.modes;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map.Entry;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionBuilder;
import org.apache.commons.cli.OptionGroup;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.PosixParser;

import uk.co.mccnet.keyutil.JKSKeyStoreUtil;
import uk.co.mccnet.keyutil.JKSKeyStoreUtilException;
import uk.co.mccnet.keyutil.PEMFile;
import uk.co.mccnet.keyutil.PEMFileException;
import uk.co.mccnet.keyutil.cli.CliMode;

public class ImportCerts implements CliMode {
	Options options;

	@SuppressWarnings("static-access")
	public ImportCerts() {
		options = new Options();
		options.addOption("h", "help", false, "Show help");
		options.addOption("n", "new", false, "create new keystore");

		Option keyStore = 		OptionBuilder.hasArg()
												.withLongOpt("keystore")
												.withDescription("keystore filename")
												.withArgName("FILENAME")
												.withType(File.class)
												.isRequired()
												.create("k");

		Option keyStorePassword = OptionBuilder.hasArg()
											   	.withLongOpt("password")
											   	.hasArg()
											   	.withDescription("keystore password")
											   	.withArgName("PASSWORD")
											   	.isRequired()
											   	.create("p");

		Option pemFilename 		= OptionBuilder.hasArg()
												.withLongOpt("certs")
												.withDescription("pem filename")
												.withArgName("FILENAME [FILENAME]..")
												.isRequired()
												.hasArgs()
												.create("c");

		options.addOption(keyStore)
			   .addOption(keyStorePassword)
			   .addOption(pemFilename);

	}

	@Override
	public void parse(String[] args) throws InvalidUsageException, UnrecoverableModeException {

		CommandLineParser parser = new PosixParser();
		CommandLine line = null;

		try {
	        line = parser.parse( options, args);
	    } catch( ParseException exp ) {
	    	String message = exp.getMessage() + "\n\n" + getHelp();
	    	throw new InvalidUsageException(message, exp);
	    }

		if (line.hasOption("help")) {
			throw new InvalidUsageException(getHelp());
		}

		JKSKeyStoreUtil jksKeyStoreUtil;
		String password = line.getOptionValue("password");

		try {
			File keyStoreFile = (File) line.getParsedOptionValue("keystore");

			if (line.hasOption("new")) {
				jksKeyStoreUtil = new JKSKeyStoreUtil();
			} else {
				jksKeyStoreUtil = new JKSKeyStoreUtil(keyStoreFile, password );
			}


			for (String certFilename : line.getOptionValues("certs")) {
				File pemFileFile = new File(certFilename);

				if (! pemFileFile.exists()) {
					throw new FileNotFoundException(certFilename);
				}

				PEMFile pemFile = new PEMFile(pemFileFile);
				jksKeyStoreUtil.importPEMFile(pemFile);
			}

			jksKeyStoreUtil.save(keyStoreFile, password);

		} catch (NoSuchAlgorithmException | CertificateException | IOException |
				JKSKeyStoreUtilException | ParseException | PEMFileException e) {
			throw new UnrecoverableModeException(e);
		}

	}

	@Override
	public String getHelp() {

		HelpFormatter formatter = new HelpFormatter();

		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		PrintWriter pw = new PrintWriter(outputStream, true);
		formatter.printHelp(pw, 120, this.getClass().getSimpleName().toLowerCase(), null, options, 5, 5, null, true);
		return outputStream.toString();

	}

	@Override
	public String getDescription() {
		return "Import certificates from PEM files";
	}

}
