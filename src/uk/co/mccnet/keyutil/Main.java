package uk.co.mccnet.keyutil;

import java.io.File;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionBuilder;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.PosixParser;

/**
 * Utility to add a PEM certificates from a CA bundle file into a new or existing Java Keystore file (JKS)
 *
 */
public class Main {

	private static Logger logger = Logger.getLogger(Main.class.getCanonicalName());
	
	/**
	 * @param args
	 * @throws Exception 
	 */
	
	@SuppressWarnings("static-access")
	public static void main(String[] args) throws Exception {

		logger.setLevel(Level.INFO);
		
		Options options = new Options();
		options.addOption("h", "help", false, "Show help");
		options.addOption("F", "force", false, "Force actions");
		
		options.addOption("n", "new", false, "Create new Java Keystore");
		options.addOption("q", "quiet", false, "Quiet");
	
		options.addOption(OptionBuilder.withLongOpt("password")
				.withDescription("Keystore password")
				.hasArg()
				.isRequired()
				.create("p"));
		
		Option ksFileOption = new Option("f", "keystore-file", true, "Keystore filename");
		ksFileOption.setRequired(true);
		options.addOption(ksFileOption);
		
		Option pemFileOption = new Option("i", "import-file", true, "PEM import filename");
		pemFileOption.setRequired(true);
		options.addOption(pemFileOption);
		
		CommandLineParser parser = new PosixParser();
		CommandLine line = null;
		
	    try {
	        // parse the command line arguments
	        line = parser.parse( options, args );
	    } catch( ParseException exp ) {
	        // oops, something went wrong
	       
	    	System.out.println(exp.getMessage() + "\n");
	       
	    	printHelp(options);
	    }
		
	    if (line.hasOption("help")) {
	    	printHelp(options);
	    }
	    
	    if (line.hasOption("q")) {
	    	logger.setLevel(Level.SEVERE);
	    }
	    	    
	    File keyStore = new File(line.getOptionValue("keystore-file"));
	    
	    if ( line.hasOption("new") && keyStore.exists() && ! line.hasOption("force")) {
	    	throw new Exception("New Keystore - File already exists. Use --force to overwrite");
	    } else if (! line.hasOption("new") && ! keyStore.exists()) {
			throw new Exception(String.format("%s does not exist. Create it with --new.", keyStore.getPath()));
		}
	    
		File pemFile = new File(line.getOptionValue("import-file"));
		PEMFile pf = new PEMFile(pemFile);
		JKSKeyStoreUtil jksKeyStoreUtil = JKSKeyStoreUtil.newKeyStore(new File(line.getOptionValue("keystore-file")), line.getOptionValue("password"));
		jksKeyStoreUtil.importPEMFile(pf);
	}
	
	private static void printHelp(Options options) {
		HelpFormatter helpFormatter = new HelpFormatter();
		
		helpFormatter.printHelp("keyutil", options, true);
    	System.exit(1);
	}

}
