package uk.co.mccnet.keyutil;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class PEMFile {
	Pattern pemBeginPattern = Pattern.compile("-+BEGIN.*?CERTIFICATE-+");
	Pattern pemEndPattern = Pattern.compile("-+END.*?CERTIFICATE-+");
	String fileName;
	File pemFile;
	
	public PEMFile(File pemFile) {
		this.pemFile = pemFile;
	}
	
	public ArrayList<String> getPEMBlocks() throws IOException {
		FileReader fr = new FileReader(pemFile);
		BufferedReader pemFileBR = new BufferedReader(fr);
		
		ArrayList<String> result = new ArrayList<String>();
		
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
		
		pemFileBR.close();
		if (result.isEmpty()) {
			return null;
		} else {
			return result;
		}
	}

}
