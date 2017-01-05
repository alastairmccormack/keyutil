package uk.co.mccnet.keyutil.cli;

import uk.co.mccnet.keyutil.cli.modes.InvalidUsageException;
import uk.co.mccnet.keyutil.cli.modes.UnrecoverableModeException;

public interface CliMode {
	public String description = null;

	public void parse(String[] args) throws InvalidUsageException, UnrecoverableModeException;

	public String getHelp();

	public String getDescription();
}
