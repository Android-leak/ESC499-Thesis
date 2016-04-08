package nist;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.parsers.ParserConfigurationException;

import nist.NVDEntry.FileType;
import nist.NVDEntry.SourceClass;
import nist.NVDEntry.StackRegion;

import org.xml.sax.SAXException;

import webParser.GoogleSource;

public class NistStackClassifier {
	public final String keywordDir = System.getProperty("user.dir") + File.separator + "keywords" + File.separator;

	public void analyseResult(HashMap<String, ArrayList<NVDEntry>> allYears) throws FileNotFoundException {
		String[] years = allYears.keySet().toArray(new String[allYears.keySet().size()]);
		Arrays.sort(years);
		
		for (String key : years) {
			System.out.println("*****" + key +": " + allYears.get(key).size() + 
					" Android related vulnerabilities*****");
			analyseByYear(allYears.get(key), key);
		}

		// Count scores based on Android layers
		ArrayList<NVDEntry> app = new ArrayList<NVDEntry>();
		ArrayList<NVDEntry> framework = new ArrayList<NVDEntry>();
		ArrayList<NVDEntry> natives = new ArrayList<NVDEntry>();
		ArrayList<NVDEntry> kernel = new ArrayList<NVDEntry>();
		for (String key : years) {
			ArrayList<NVDEntry> entries = allYears.get(key);
			for (NVDEntry entry : entries) {
				if (entry.affectedStack == StackRegion.APP) {
					app.add(entry);
				}
				else if (entry.affectedStack == StackRegion.FRAMEWORK) {
					framework.add(entry);
				}
				else if (entry.affectedStack == StackRegion.NATIVE) {
					natives.add(entry);
				}
				else if (entry.affectedStack == StackRegion.KERNEL) {
					kernel.add(entry);
				}
			}
		}
		//calculator.getScores(app, "Application");
		//calculator.getScores(framework, "framework");
		//calculator.getScores(natives, "natives");
		//calculator.getScores(kernel, "kernel");
		// Count scores based on file types
		ArrayList<NVDEntry> java = new ArrayList<NVDEntry>();
		ArrayList<NVDEntry> cpp = new ArrayList<NVDEntry>();
		for (String key : years) {
			ArrayList<NVDEntry> entries = allYears.get(key);
			for (NVDEntry entry : entries) {
				if (entry.fileTypes[0] != 0) {
					System.out.println(entry.CWE);
					java.add(entry);
				}
				if (entry.fileTypes[1] != 0) {
					cpp.add(entry);
				}
			}
		}
		CompositeScoreCalculator calculator = new CompositeScoreCalculator();
		calculator.getScores(java, "Java");
		calculator.getScores(cpp, "CPP");
	}

	private void analyseByYear(ArrayList<NVDEntry> entries, String key) throws FileNotFoundException {
		PrintWriter out = new PrintWriter(new FileOutputStream(
				new File(System.getProperty("user.dir") + File.separator + key + ".txt"), false));

		int[] stackCounts = new int[StackRegion.values().length];
		int[] fileTypeCounts = new int[FileType.values().length];
		for (NVDEntry entry : entries) {
			// figure out whether the entry contain certain sources
			for (VulnRef ref : entry.references) {
				entry.isAndroid |= ref.isAndroidSource;
				entry.isLinux |= ref.isLinuxSource;
				entry.isSecurityBulletin |= ref.isSecurityBulletin;
			}

			countFileTypes(entry, false);
			
			classifyByGoogleRef(entry);
			//classifyStackByLinuxRefs(entry);
			classifyStackBySummaryPattern(entry);
			classifyStackBySummaryKeywords(entry);
			classifyStackBySummaryRefs(entry);
			//classifyStackByCPE(entry);

			stackCounts[entry.affectedStack.index] += 1;
			for (int i = 0; i < fileTypeCounts.length; i++) {
				fileTypeCounts[i] += entry.fileTypes[i];
			}
		}
		out.close();
		System.out.println("\tApp\tFramework\tNative\tKernel\tUnknown");
		System.out.println("\t" + stackCounts[0] + "\t" + stackCounts[1] + 
				"\t\t" + stackCounts[2] + "\t" + stackCounts[3] + "\t" + stackCounts[4] + "\t");
		for (FileType type : FileType.values()) {
			System.out.print("\t" + type);
		}
		System.out.println();
		for (int i : fileTypeCounts) {
			System.out.print("\t" + i);
		}
		System.out.println();
	}

	/**
	 * Classify this entry's sources. google source is most reliable, 
	 * followed by linux, last being summary text source
	 */
	private void countFileTypes(NVDEntry entry, boolean checkSummary) {
		// check google source or linux source
		for (VulnRef ref : entry.references) {
			if (ref.isAndroidSource) {
				entry.sourceFileType[SourceClass.GOOGLE_SOURCE.idx] ++;
				for (GoogleSource gSrc : ref.googleSource) {
					for (FileType type : FileType.values()) {
						if (gSrc.subDirectory.contains(type.suffix)) {
							entry.fileTypes[type.idx] += 1;
							entry.summaryReferences.add(gSrc.subDirectory);
						}
					}
				}
			}
			if (ref.isLinuxSource) {
				entry.sourceFileType[SourceClass.LINUX_SOURCE.idx] ++;
			}
		}
		if (!checkSummary) {
			return;
		}
		// nothing useful. check summary
		if (entry.sourceFileType[SourceClass.GOOGLE_SOURCE.idx] == 0 && 
				entry.sourceFileType[SourceClass.LINUX_SOURCE.idx] == 0) {
			parseSummaryFileType(entry);
			if (entry.isSummaryUseful) {
				entry.sourceFileType[SourceClass.SUMMARY_TEXT.idx] ++;
			}
		}
	}

	/**
	 * Parse the summary texts, and look for certain file suffix. If found, log them.
	 */
	private void parseSummaryFileType(NVDEntry entry) {
		String[] phrases= entry.summary.split(" ");
		for (String phrase : phrases) {
			phrase = phrase.replace(")", "").replace("(", "");
			for (FileType type : FileType.values()) {
				if (phrase.contains(type.suffix)) {
					entry.fileTypes[type.idx] += 1;
					entry.summaryReferences.add(phrase);
					entry.isSummaryUseful = true;
				}
			}
		}
	}

	private void classifyByGoogleRef(NVDEntry entry) {
		if (!entry.isAndroid) {
			return;
		}
		// check stack region
		if (entry.sourceFileType[FileType.JAVA.idx] != 0 || 
				entry.sourceFileType[FileType.XML.idx] != 0) {
			entry.affectedStack = StackRegion.FRAMEWORK;
			entry.setClassified();
		}
	}

	// TODO: something's wrong. gives way too many kernel classifications
	private void classifyStackByLinuxRefs(NVDEntry entry) {
		if (!entry.isLinux) {
			return;
		}
		entry.affectedStack = StackRegion.KERNEL;
		entry.setClassified();
	}
	
	private HashSet<String> loadKeyword(String filename) {
		HashSet<String> keywords = new HashSet<String>();
		try (BufferedReader br = new BufferedReader(new FileReader(filename))) {
		    String line;
		    while ((line = br.readLine()) != null) {
		    	line = line.trim();
		    	if (!line.isEmpty()) {
		    		keywords.add(line);
		    	}
		    }
		    return keywords;
		}
		catch (Exception e) {
			e.printStackTrace();
			return keywords;
		}
	}
	private void classifyStackBySummaryKeywords(NVDEntry entry) {
		HashSet<String> thirdPartyKeywords = loadKeyword(keywordDir + "application_keywords.txt");
		HashSet<String> frameworkKeywords = loadKeyword(keywordDir + "framework_keywords.txt");
		HashSet<String> nativeKeywords = loadKeyword(keywordDir + "native_keywords.txt");
		HashSet<String> kernelKeywords = loadKeyword(keywordDir + "kernel_keywords.txt");
		for (String keyword : frameworkKeywords) {
			if (entry.summary.contains(keyword)) {
				entry.affectedStack = StackRegion.FRAMEWORK;
				entry.setClassified();
			}
		}
		for (String keyword : nativeKeywords) {
			if (entry.summary.contains(keyword)) {
				entry.affectedStack = StackRegion.NATIVE;
				entry.setClassified();
			}
		}
		for (String keyword : thirdPartyKeywords) {
			if (entry.summary.contains(keyword)) {
				entry.affectedStack = StackRegion.APP;
				entry.setClassified();
			}
		}
		for (String keyword : kernelKeywords) {
			if (entry.summary.contains(keyword)) {
				entry.affectedStack = StackRegion.KERNEL;
				entry.setClassified();
			}
		}
	}
	/**
	 * Heuristic function. 
	 * @param entry
	 */
	private void classifyStackBySummaryPattern(NVDEntry entry) {
		// 3rd party apps tend to have the pattern (aka cat.gencat.mobi.artacces)
		Pattern pattern = Pattern.compile("\\(aka (.*\\..*)\\)");
		Matcher m = pattern.matcher(entry.summary);
		if (m.find()) {
			entry.affectedStack = StackRegion.APP;
			entry.setClassified();
		}
		// 3rd party apps tend to have the pattern The xxx application
		pattern = Pattern.compile("The (.*) application");
		m = pattern.matcher(entry.summary);
		if (m.find()) {
			if (m.group(1).split(" ").length <= 6) { // make sure capture group is not overly long
				entry.affectedStack = StackRegion.APP;
				entry.setClassified();
			}
		}
	}
	private void classifyStackBySummaryRefs(NVDEntry entry) {
		for (String ref : entry.summaryReferences) {
			if ((ref.contains("com.") || ref.contains("org.")) && !ref.contains("com.android")) {
				entry.affectedStack = StackRegion.APP;
				entry.setClassified();
			}
		}
	}

	private void classifyStackByCPE(NVDEntry entry) {
		boolean hasAndroid = false;
		boolean hasLinux = false;
		for (VulnCpe cpe : entry.CPEs) {
			if (cpe.vendor.contains("google") && 
					cpe.product.contains("android")) {
				hasAndroid = true;
			}
			if (cpe.product.contains("linux")) {
				hasLinux = true;
			}
		}
		if (!hasAndroid && !hasLinux) {
			entry.affectedStack = StackRegion.APP;
			entry.setClassified();
		}
	}
	


	public static void main(String[] args) throws ParserConfigurationException, SAXException, IOException {
		NVDParser parser = new NVDParser();
		HashMap<String, ArrayList<NVDEntry>> result = parser.parseAll();
		NistStackClassifier classifier = new NistStackClassifier();
		classifier.analyseResult(result);
	}

}
