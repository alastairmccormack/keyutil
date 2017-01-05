package uk.co.mccnet.keyutil.cli.modes;

import java.io.ByteArrayOutputStream;
import java.io.File;
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

public class exportCerts implements CliMode {
	Options options;

	@SuppressWarnings("static-access")
	public exportCerts() {
		options = new Options();
		options.addOption("h", "help", false, "Show help");

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
												.withLongOpt("cert")
												.withDescription("pem output filename")
												.withArgName("FILENAME")
												.withType(File.class)
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

		try {
			File keyStoreFile = (File) line.getParsedOptionValue("keystore");
			jksKeyStoreUtil = new JKSKeyStoreUtil(keyStoreFile, line.getOptionValue("password") );

			File pemFileFile = (File) line.getParsedOptionValue("cert");
			/*PEMFile pemFile = new PEMFile(pemFileFile);
			jksKeyStoreUtil.importPEMFile(pemFile);*/

			PEMFile pemFile = jksKeyStoreUtil.getPemFile(line.getOptionValue("password"));
			pemFile.write(pemFileFile);

		} catch (NoSuchAlgorithmException | CertificateException | IOException | JKSKeyStoreUtilException | ParseException | PEMFileException e) {
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
		return "Export certs and keys from keystore";
	}

}
