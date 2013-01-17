package uk.co.mccnet.keyutil;

import java.io.File;
import java.security.KeyStoreException;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Map.Entry;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionGroup;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.PosixParser;

/**
 * Utility to add a PEM certificates from a CA bundle file into a new or existing Java Keystore file (JKS)
 *
 */
public class Main {
	private static Logger logger = Logger.getLogger(Main.class.getName());
	
	/**
	 * @param args
	 * @throws Exception 
	 */
	
	public static void main(String[] args) throws Exception {

		logger.setLevel(Level.INFO);
		
		Options options = new Options();
		options.addOption("h", "help", false, "Show help");
		options.addOption("F", "force", false, "Force actions"); 
		options.addOption("n", "new", false, "Create new Java Keystore");
		
		Option passwordOption = new Option("p", "password", true, "Keystore (secret) password");
		passwordOption.setRequired(true);
		options.addOption(passwordOption);
		
		Option fileOption = new Option("f", "keystore-file", true, "Output keystore filename");
		fileOption.setRequired(true);
		fileOption.setArgName("keystore");
		options.addOption(fileOption);
		
		OptionGroup ogLogging = new OptionGroup();
		ogLogging.addOption(new Option("q", "quiet", false, "Quiet"));
		ogLogging.addOption(new Option("d", "debug", false, "Debug"));		
		options.addOptionGroup(ogLogging);
		
		OptionGroup ogMode = new OptionGroup();
		ogMode.setRequired(true);
		ogMode.addOption(new Option("l", "list", false, "List cert mode"));
		ogMode.addOption(new Option("i", "import", false, "Import certs mode"));
		options.addOptionGroup(ogMode);
		
		Option pemFileOption = new Option("e", "import-pem-file", true, "PEM import filenames");
		pemFileOption.setArgs(Option.UNLIMITED_VALUES);
		pemFileOption.setArgName("PEM_file [<PEM_files>..]");
		options.addOption(pemFileOption);
		
		Option jksFileOption = new Option("j", "import-jks-file", true, "JKS import filename using given password");
		jksFileOption.setArgs(Option.UNLIMITED_VALUES);
		jksFileOption.setArgName("JKS_file:password [<JKS_file:password>..]");
		options.addOption(jksFileOption);
		
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
	    
	    // Ensure console logs > INFO
	    //Handler consoleHandler = new ConsoleHandler();
	    //consoleHandler.setLevel(Level.FINEST);
	    //logger.addHandler(consoleHandler);
	    
	    if (line.hasOption("quiet")) {
	    	logger.setLevel(Level.SEVERE);
	    } else if (line.hasOption("debug")) {
	    	logger.setLevel(Level.FINEST);
		}   
	    	    
	    File keyStore = new File(line.getOptionValue("keystore-file"));
	    String password = line.getOptionValue("password");
	    
	    if ( line.hasOption("new") && keyStore.exists() && ! line.hasOption("force")) {
	    	throw new Exception("New Keystore - File already exists. Use --force to overwrite");
	    } else if (! line.hasOption("new") && ! keyStore.exists()) {
			throw new Exception(String.format("%s does not exist. Create it with --new.", keyStore.getPath()));
		}
	    
		JKSKeyStoreUtil jksKeyStoreUtil;
		
		if (line.hasOption("new") ) {
			jksKeyStoreUtil = new JKSKeyStoreUtil();
		} else {
			// load existing
			jksKeyStoreUtil = new JKSKeyStoreUtil(keyStore, password);
		}
		
		if (line.hasOption("list")) {
			list(jksKeyStoreUtil);
		} else if (line.hasOption("import")) {
			if (line.hasOption("import-pem-file")) {
				for (String pemFileName : line.getOptionValues("import-pem-file")) {
					File pemFile = new File(pemFileName);
					PEMFile pf = new PEMFile(pemFile); 
					jksKeyStoreUtil.importPEMFile(pf);
				}
			}
			
			if (line.hasOption("import-jks-file")) {
				for (String jksFileArg : line.getOptionValues("import-jks-file")) {
					String filePassArray[] = jksFileArg.split(":");
					if (filePassArray.length != 2) {
						throw new Exception("Invalid format of JKS file import argument");
					}
					File jksFile = new File(filePassArray[0]);
					JKSKeyStoreUtil sourceKS = new JKSKeyStoreUtil(jksFile, filePassArray[1]); 
					jksKeyStoreUtil.importJKSKeyStore(sourceKS);
					logger.info(String.format("%s imported", jksFile.getName()));
				}
			}
			
			jksKeyStoreUtil.save(keyStore, password);
		}	
	}
	
	private static void list(JKSKeyStoreUtil jksKeyStoreUtil) throws KeyStoreException {
		HashMap<String, String> aliasesCertsHash = jksKeyStoreUtil.list();
		
		Set<Entry<String, String>> aliasSet = aliasesCertsHash.entrySet();
		for (Entry<String, String> entry : aliasSet) {
			System.out.println(String.format("%s -- DN: %s", entry.getKey(), entry.getValue()));
		}
	}
	
	private static void printHelp(Options options) {
		HelpFormatter helpFormatter = new HelpFormatter();
		helpFormatter.setWidth(120);
		
		helpFormatter.printHelp("keyutil", options, true);
    	System.exit(1);
	}

}
