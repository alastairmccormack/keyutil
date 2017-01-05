package uk.co.mccnet.keyutil.cli;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map.Entry;
import java.util.Set;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionBuilder;
import org.apache.commons.cli.OptionGroup;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.PosixParser;

import uk.co.mccnet.keyutil.cli.modes.ImportCerts;
import uk.co.mccnet.keyutil.cli.modes.InvalidUsageException;
import uk.co.mccnet.keyutil.cli.modes.List;
import uk.co.mccnet.keyutil.cli.modes.UnrecoverableModeException;
import uk.co.mccnet.keyutil.cli.modes.exportCerts;

public class Main2 {

	CliMode[] modes = { new ImportCerts(), new List(), new exportCerts() };
	HashMap<String, CliMode> modeMap = new HashMap<>();

	public Main2() {
		// TODO Auto-generated constructor stub
	}

	public static void main(String[] args) throws InstantiationException, IllegalAccessException {
		Main2 main2 = new Main2();
		main2.parse(args);
	}

	@SuppressWarnings("static-access")
	public void parse(String[] args) throws InstantiationException, IllegalAccessException {
		for (CliMode modeClass : modes) {
			modeMap.put(modeClass.getClass().getSimpleName().toLowerCase(), modeClass);
		}


		Options options = new Options();

		OptionGroup ogLogging = new OptionGroup();
		ogLogging.addOption(new Option("q", "quiet", false, "Quiet"));
		ogLogging.addOption(new Option("d", "debug", false, "Debug"));
		options.addOptionGroup(ogLogging);

		//options.addOption(new Option("h", "help", false, "This help"));

		OptionGroup ogMode = new OptionGroup();

		Set<Entry<String, CliMode>> modesSet = modeMap.entrySet();
		for (Entry<String, CliMode> entry : modesSet) {

			Option modeOpt = OptionBuilder.withDescription(entry.getValue().getDescription())
					   						 .withLongOpt(entry.getKey())
					   						 .hasArgs()
					   						 .create();
			ogMode.addOption(modeOpt);

		}

		options.addOptionGroup(ogMode);

		CommandLineParser parser = new PosixParser();
		CommandLine line = null;

		try {
	        // parse the command line arguments
	        line = parser.parse( options, args);
	    } catch( ParseException exp ) {
	        // oops, something went wrong
	    	System.out.println(exp.getMessage() + "\n");
	    	printHelp(options);
	    }

		CliMode cliMode = null;
		String [] modeArgs = null;

		for (Iterator iterator = ogMode.getNames().iterator(); iterator.hasNext();) {
			String modeName = (String) iterator.next();

			if (line.hasOption(modeName)) {
				modeArgs = line.getOptionValues(modeName);
				cliMode = modeMap.get(modeName);

				try {
					cliMode.parse(modeArgs);
				} catch (InvalidUsageException | UnrecoverableModeException e) {
					System.out.println(e.getMessage());
					System.exit(1);
				}
			}
		}

	}

	private void printHelp(Options options) {
		String usage = "Usage %s [options] (sub-command) [arguments]\n\n"
					 + "The Key Utility for normal people. Import and Export keys and certs using industry formats\n\n"
				     + "sub-commands:\n";
		System.out.println(String.format(usage, "keyutil"));

		Set<String> modesSet = modeMap.keySet();

		ArrayList<String> modeList = new ArrayList<>(modesSet);
		Collections.sort(modeList);

		for (String modeString : modeList) {
			System.out.println(String.format("    %s", modeString));
		}

    	System.exit(1);
	}

}
