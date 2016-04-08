package nist;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Scanner;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

public class NVDParser {
	public String nistDir  = System.getProperty("user.dir") + File.separator + "nist_xml";
	private String manualParseDir = System.getProperty("user.dir") + File.separator + "hooman.csv";

	public HashMap<String, ArrayList<NVDEntry>> parseAll() throws FileNotFoundException {
		File folder = new File(nistDir);
		File[] listOfFiles = folder.listFiles();
		HashMap<String, ArrayList<NVDEntry>> result = new HashMap<String, ArrayList<NVDEntry>>();

		for (int i = 0; i < listOfFiles.length; i++) {
			if (!listOfFiles[i].isFile()) {
				continue;
			}
			result.put(listOfFiles[i].getName(), (parseNistXML(listOfFiles[i])));
		}
		return result;
		//manualParse(entries);
	}

	/**
	 * Set up a manual parse protocol through csv
	 * @param entries
	 * @throws FileNotFoundException
	 */
	public void manualParse(ArrayList<NVDEntry> entries) throws FileNotFoundException {
		PrintWriter out = new PrintWriter(new FileOutputStream(new File(manualParseDir), true));
		for (NVDEntry entry : entries) {
			String cve = entry.CVE;
			String cveDetailUrl = "http://www.cvedetails.com/cve/" + cve + "/";
			out.println(String.format("%s,%s,%s", cve, cveDetailUrl, entry.affectedStack));
		}
		out.close();
		Scanner keyboard = new Scanner(System.in);
		System.out.println("Manually categorize everything. Once finished, press Enter.");
		keyboard.nextLine();
	}

	/**
	 * Given a specific NIST's XML log, parse it all
	 * @param file
	 * @return
	 */
	public ArrayList<NVDEntry> parseNistXML(File file) {
		try {
			System.out.println("*****" + file.getName() + "*****");
			ArrayList<Node> xmlEntries = parseXmlForKeyword(file, "android");
			ArrayList<NVDEntry> nistEntries = new ArrayList<NVDEntry>();
			for (Node node : xmlEntries) {
				NVDEntry entry = parseCveEntry((Element)node);
				nistEntries.add(entry);
			}
			return nistEntries;
		}
		catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	/**
	 * Parse one xml document, return nodes whose body contain the keyword (ex: android)
	 * @param filename
	 * @throws ParserConfigurationException
	 * @throws SAXException
	 * @throws IOException
	 */
	private ArrayList<Node> parseXmlForKeyword(File fXmlFile, String keyword)
			throws ParserConfigurationException, SAXException, IOException {
		DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
		DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
		Document doc = dBuilder.parse(fXmlFile);
		doc.getDocumentElement().normalize();
		Element nvd = doc.getDocumentElement();
		NodeList nodeList = nvd.getElementsByTagName("entry");

		int androidCount = 0;
		int entryCount = nodeList.getLength();
		ArrayList<Node> entries = new ArrayList<Node>();
		for (int j = 0; j < entryCount; j++) {
		    Node entry = nodeList.item(j);
		    String entryStr = nodeToString(entry);
		    if (entryStr.contains(keyword)) {
		    	androidCount ++;
		    	entries.add(entry);
		    }
		}
		System.out.println("totalCount=" + entryCount);
		System.out.println("androidCount=" + androidCount);
		return entries;
	}
	
	/**
	 * 
	 */
	private NVDEntry parseCveEntry(Element entry) {
		NVDEntry nistEntry = new NVDEntry();
		nistEntry.plainTextXML = nodeToString(entry);

		// CVE-id
		Node cve = entry.getElementsByTagName("vuln:cve-id").item(0);
		nistEntry.CVE = cve.getTextContent();
		// CWE-id
		try {
			Node cwe = entry.getElementsByTagName("vuln:cwe").item(0);
			nistEntry.CWE = ((Element)cwe).getAttributes().item(0).getTextContent();
		}
		catch (NullPointerException e) {
			// surpressed
		}
		// Dates
		Node dates = entry.getElementsByTagName("vuln:published-datetime").item(0);
		nistEntry.date = dates.getTextContent();
		// Affected software
		Element vulnSoftware = (Element)entry.getElementsByTagName("vuln:vulnerable-software-list").item(0);
		if (vulnSoftware == null) {
			//System.out.println(nistEntry.CVE + " is not associated with any product");
		}
		else {
			// CPE
			NodeList affectedSoftware = vulnSoftware.getElementsByTagName("vuln:product");
			for (int i = 0; i < affectedSoftware.getLength(); i++) {
				Element software = (Element)affectedSoftware.item(i);
				String cpeStr = software.getTextContent();
				VulnCpe cpe = new VulnCpe(cpeStr);
				nistEntry.CPEs.add(cpe);
			}
		}

		// CVSS
		NodeList vulnCvss= entry.getElementsByTagName("vuln:cvss");
		VulnCvss cvss = new VulnCvss((Element)vulnCvss.item(0));
		nistEntry.CVSS = cvss;

		// References
		NodeList refs = entry.getElementsByTagName("vuln:references");
		for (int i = 0; i < refs.getLength(); i++) {
			Element ref = (Element) ((Element)refs.item(i)).getElementsByTagName("vuln:reference").item(0);
			String url = ref.getAttribute("href");
			VulnRef vulnRef = new VulnRef(url);
			nistEntry.references.add(vulnRef);
		}
		
		Element summary = (Element)entry.getElementsByTagName("vuln:summary").item(0);
		nistEntry.summary = summary.getTextContent();
		return nistEntry;
	}

	private String nodeToString(Node node) {
		try {
			TransformerFactory tf = TransformerFactory.newInstance();
			Transformer transformer = tf.newTransformer();
			transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
			StringWriter writer = new StringWriter();
			transformer.transform(new DOMSource(node), new StreamResult(writer));
			String output = writer.getBuffer().toString();
			return output;
		}
		catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
}

