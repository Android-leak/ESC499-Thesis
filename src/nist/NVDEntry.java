package nist;

import java.util.ArrayList;
import java.util.Date;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class NVDEntry {

	public enum StackRegion {
		APP(0),
		FRAMEWORK(1),
		NATIVE(2),
		KERNEL(3),
		UNKNOWN(4);
		public final int index;
		StackRegion(final int index) {
			this.index = index;
		}
	}

	public enum FileType {
		JAVA(".java", 0), 
		CPP(".cpp", 1), 
		C(".c ", 2), 
		C_HEADER(".h ", 3),
		XML(".xml", 4),
		MK(".mk", 5),
		PKG_NAME("com.", 6),
		ORG_NAME("org.", 7);
        public final int idx;
        public final String suffix;
        FileType(final String suffix, final int index) {
        	this.suffix = suffix;
            this.idx = index;
        }
	}

	public enum SourceClass {
		GOOGLE_SOURCE(0),
		SECURITY_BULLETIN(1),
		LINUX_SOURCE(2),
		SUMMARY_TEXT(3);

		public final int idx;
		SourceClass(final int index) {
			this.idx = index;
		}
	}

	public String plainTextXML;
	public String CVE;
	public String CWE;
	public String date;
	public String summary;
	public VulnCvss CVSS;
	public ArrayList<VulnCpe> CPEs = new ArrayList<VulnCpe>();

	public ArrayList<VulnRef> references = new ArrayList<VulnRef>();
	public ArrayList<String> summaryReferences = new ArrayList<String>(); // sources scraped from summary

	// Classification metrics for each entry
	public boolean isAndroid = false; // specifically in android's framework or below
	public boolean isSecurityBulletin = false;
	public boolean isLinux = false;
	public boolean isSummaryUseful = false;

	public int[] fileTypes = new int[FileType.values().length];
	public int[] sourceFileType = new int[SourceClass.values().length];
	public StackRegion affectedStack = StackRegion.UNKNOWN;

	private boolean classified;
	private boolean set = false;
	public void setClassified() {
		if (!set) {
			classified = true;
			set = true;
		}
	}
	public boolean isClassified() {
		return classified;
	}

	public Date getDate() {
		// formate is like so: 2007-03-02T16:18:00.000-05:00
		Pattern p = Pattern.compile("(\\d\\d\\d\\d)-(\\d\\d)-(\\d\\d)");
		Matcher m = p.matcher(this.date);
		if (!m.find()) {
			return null;
		}
		return new Date(Integer.parseInt(m.group(1)), 
				Integer.parseInt(m.group(2)), 
				Integer.parseInt(m.group(3)));
	}
	/**
	 * TODO: potentially useless
	 * - only google: inconclusive
	 * - only linux: kernel
	 */
	public void stackRegionClassify() {
		boolean hasSource = false;
		if (sourceFileType[SourceClass.GOOGLE_SOURCE.idx] > 0) {
			hasSource = true;
		}
		if (sourceFileType[SourceClass.LINUX_SOURCE.idx] > 0) {
			hasSource = true;
		}
		if (sourceFileType[SourceClass.SUMMARY_TEXT.idx] > 0) {
			hasSource = true;
		}
		if (!hasSource) {
			// manually parse
		}

		classifyByCpes();
	}

	/**
	 * Read entry's CPEs. This helps classify the stack regions
	 * 
	 */
	private void classifyByCpes() {
//		for (VulnCpe cpe : this.CPEs) {
//			if (cpe.vendor.equalsIgnoreCase("google") || 
//					cpe.product.equalsIgnoreCase("android")) {
//				this.isAndroid = true;
//			}
//			if (cpe.vendor.contains("linux") || cpe.product.contains("kernel")) {
//				this.isLinux = true;
//			}
//		}
//		if (!this.isAndroid && !this.isLinux) {
//			this.isThirdParty = true;
//		}
	}

}
