package webParser;

import java.util.ArrayList;
import java.util.Date;

public class CVEData extends CVEInfo {
	public String vulId; // internal id for 
	public String cweId;

	public String cveUrl;

	public String type;
	public String summary;

	public double CVSS;
	
	public Date dateReported;
	public Date dateFixed;
	public Date dateFixReleased;

	public ArrayList<String> affectedVers = new ArrayList<String> ();
	public ArrayList<String> affectedDevices = new ArrayList<String> ();
	public ArrayList<String> categories = new ArrayList<String> ();
	

	
	public ArrayList<String> referenceUrls = new ArrayList<String>();
	public ArrayList<GoogleSource> sources = new ArrayList<GoogleSource>();
	
	public CVEData() {
		this.origin = CVEInfo.Origin.CVEDetail;
	}

	public CVEData(String vulId, String cveId, String cveUrl, String cweId,
			String summary, String summaryLong) {
		this.origin = CVEInfo.Origin.CVEDetail;
		this.vulId = vulId;
		this.cveID = cveId;
		this.cweId = cweId;
		this.type = summary;
		this.summary = summaryLong;
		if (!cveUrl.startsWith("http")) {
			cveUrl = URLs.cveDetailHome + cveUrl;
		}
		this.cveUrl = cveUrl;
	}
	
	public String toString() {
		return String.format(
				"Summary: %s\n"+
				"cveID: %s\n"+
				"cweID: %s\n"+
				"Link: %s\n"+
				"Detail: %s",
				type, cveID, cweId, cveUrl, summary);
	}
}
