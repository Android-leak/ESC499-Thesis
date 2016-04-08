package webParser;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jsoup.Connection;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

/**
 * Class to parse 
 * @author Jim
 *
 */
public class CVEParser {

	private int vulIdCount = 1;
	private int[] cvePageIndices = {1, 2, 3, 4, 5}; // number of pages
	private String androidDirList = System.getProperty("user.dir") + File.separator + "sources.csv";

	public ArrayList<CVEData> parse(boolean loadLocally, boolean writeLocally) throws IOException {
		ArrayList<CVEData> result = null;
		if (loadLocally) {
			result = FileIO.readVulnerabilities();
		}
		else {
			result = this.parseAllCveDetails();
		}
		System.out.println(String.format("*****Summary: Parsed %d vulnerabilities*****", result.size()));
		this.parseForAndroidSource(result);
		if (writeLocally) {
			FileIO.writeVulnerabilities(result);
		}
		return result;
	}
	
	/**
	 * Step 1
	 * Returns a list of all CVE Vulnerabilities about Android on cvedetails.com
	 * @return
	 * @throws IOException
	 */
	private ArrayList<CVEData> parseAllCveDetails() throws IOException {
		ArrayList<CVEData> allVul = new ArrayList<CVEData>();

		int numRetries = 0; // in case of network failure
		for (int i = 0; i < cvePageIndices.length; i++) {
			int pageIndex  = cvePageIndices[i];
			try {
				Document doc = postForCvePage(pageIndex);

				Elements srrowns = doc.getElementsByClass("srrowns");
				// populate vulnerability detail
				for (Element tr : srrowns) {
					Elements tds = tr.select("td");
					String cveID = tds.get(1).select("a").html();
					String cveUrl = tds.get(1).select("a").attr("href");
					String cweID = tds.get(2).select("a").html();
					String summary = tds.get(4).html();
					// find long summary
					String summaryLong = "";
					Element nextTd = tr.nextElementSibling().select("td").get(0);
					if (nextTd.className().equals("cvesummarylong")) {
						summaryLong = nextTd.html();
					}
					CVEData newVul = new CVEData(""+vulIdCount,
							cveID, cveUrl, cweID, summary, summaryLong);
					parseCveDetail(newVul);
					allVul.add(newVul);
					System.out.println("Retrieved " + vulIdCount +" vulnerabilities");
					vulIdCount++;
				}
			}
			catch (IOException e) { // network failure. retry again
				numRetries++;
				if (numRetries > 3) {
					throw e;
				}
				i--;
			}
		}
		System.out.println(String.format("*****Summary: Parsed %d vulnerabilities*****", allVul.size()));
		return allVul;
	}

	/**
	 * Parses for CVEDetails for vulnerabilities categorized as Android
	 * @param pageIndex
	 * @return
	 * @throws IOException
	 */
	private Document postForCvePage(int pageIndex) throws IOException {
		Connection connection = Jsoup.connect(URLs.cveDetailVulnerabilityList)
		.data("vendor_id","1224")
		.data("product_id","19997")
		.data("version_id","")
		.data("order","1")
		.data("trc","184")
		.data("sha","1bd76566e804bd0baf4aa6ef43598ed24565b5b6");
		connection.data("page",""+pageIndex);
		Document document = connection.post();
		return document;
	}

	
	/**
	 * Step 2
	 * Given a specific CVE vulnerability, parse further details
	 * @param url
	 * @throws IOException 
	 */
	private void parseCveDetail(CVEData vul) throws IOException {
		String url = "http://www.cvedetails.com/cve/" + vul.cveID + "/";
		Document doc = Jsoup.connect(url).get();

		// CVSS
		Element detailTable = doc.getElementById("details");

		// Products affected. A product table looks liek this:
		//#	| Product Type	| Vendor	| Product	| Version	| Update	| Edition	| Language	
		Element affectedProdTable = doc.getElementById("vulnprodstable");
		Elements prodRow = affectedProdTable.select("tr");
		for (int i = 1; i < prodRow.size(); i++) {
			Elements cols = prodRow.get(i).select("td");
			if (!cols.get(3).select("a").html().equals("Android")) {
				continue; // not an android product
			}
			String verNumber = cols.get(4).html();
			if (!cols.get(5).html().equals("")) {
				verNumber += " " + cols.get(5).html();
			}
			vul.affectedVers.add(verNumber);
		}

		// Number of affected versions
		Element affectedVerTable = doc.getElementById("vulnversconuttable");

		// Reference
		Element refTable = doc.getElementById("vulnrefstable");
		Elements refs = refTable.select("td");
		for (Element reftd: refs) {
			String refUrl = reftd.select("a").attr("href");
			vul.referenceUrls.add(refUrl);
		}
	}
	
	/**
	 * Step 3
	 * Parse each vulnerability and look for a googlesource.com link.
	 * It always points to a source in Android directory
	 * Calling this always overwrites sources.csv
	 * @param vulnerabilities
	 * @throws IOException 
	 */
	public void parseForAndroidSource(ArrayList<CVEData> vulnerabilities) throws IOException {
		int sourceCount = 0;
		File csv = new File(androidDirList);
		csv.delete();

		System.out.println("*****Parsing for urls containing android.googlesource.com*****");
		for (CVEData v : vulnerabilities) {
			for (String url : v.referenceUrls) {
				if (url.contains("android.googlesource.com")) {
					parseGoogleSourceUrl(v, url);
					sourceCount++;
				}
			}
		}
		System.out.println(String.format("***** %s vulnerabilities has links to googlesource.com*****", sourceCount));
	}

	/**
	 * Step 4
	 * Go to each Googlesource.com url, parse out the specific files
	 * @throws IOException 
	 */
	private void parseGoogleSourceUrl(CVEData v, String url) throws IOException {
		PrintWriter out = new PrintWriter(new FileOutputStream(new File(androidDirList), true));

		Pattern patt = Pattern.compile("https://android.googlesource.com(.*)\\+/(.*)");
		Matcher m = patt.matcher(url);
		if (m.find()) {
			String rootDir = m.group(1);
			String commitBranch = m.group(2);
			String subDir = "";
			if (commitBranch.equals("5a9753fca56f0eeb9f61e342b2fccffc364f9426")) {
				out.close();
				return; // this one is merge conflict
			}
			if (commitBranch.contains("/")) {
				// this url points to a specific file
				int ind = commitBranch.indexOf("/");
				subDir = commitBranch.substring(ind);
				subDir = subDir.replaceAll("%2F", "/");
				commitBranch = commitBranch.substring(0, ind);
				String str = String.format("%s,%s,%s,%s", v.cveID, rootDir, commitBranch, subDir);
				v.sources.add(new GoogleSource(rootDir, commitBranch, subDir));
				System.out.println(str);
				out.println(str);
			}
			else {
				// this url points to a commit. Go to the commit page and check changed files
				Document doc = null;
				while (true) {
					try {
						doc = Jsoup.connect(url).get();
						break;
					}
					catch (SocketTimeoutException e) {
						System.out.println("Timeout");
						continue;
					}
				}
				Elements es = doc.getElementsByClass("DiffTree");
				if (es.size() == 0) {
					out.close();
					return;
				}
				Element diffTree = es.get(0);
				Elements lis = diffTree.select("li");
				for (Element li : lis) {
					subDir = li.select("a").get(0).html();
					subDir = subDir.replaceAll("%2F", "/");
					String str = String.format("%s,%s,%s,%s", v.cveID, rootDir, commitBranch, subDir);
					v.sources.add(new GoogleSource(rootDir, commitBranch, subDir));
					System.out.println(str);
					out.println(str);
				}
			}
		}
		out.close();
		return;
	}

//	public static void main(String[] args) throws IOException {
//		CVEParser parser = new CVEParser();
//		parser.parse(false, true);
//	}
}	
