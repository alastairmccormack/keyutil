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
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.PosixParser;

import uk.co.mccnet.keyutil.JKSKeyStoreUtil;
import uk.co.mccnet.keyutil.JKSKeyStoreUtilException;
import uk.co.mccnet.keyutil.cli.CliMode;

public class List implements CliMode {
	Options options;

	@SuppressWarnings("static-access")
	public List() {
		options = new Options();
		options.addOption("h", "help", false, "Show help");

		Option keyStore = OptionBuilder.hasArg()
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

		options.addOption(keyStore)
			   .addOption(keyStorePassword);
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

			HashMap<String, String> aliases = jksKeyStoreUtil.list();
			for (Entry<String, String> entry : aliases.entrySet())
			{
			    System.out.println(String.format("%s: %s", entry.getKey(), entry.getValue()));
			}

		} catch (NoSuchAlgorithmException | CertificateException | IOException | JKSKeyStoreUtilException | ParseException | KeyStoreException e) {
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
		return "List certs and keys from keystores";
	}

}
