package webParser;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashSet;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

public class AVOParser {
	private String avoUrl = "http://androidvulnerabilities.org/vulnerabilities/";
	private String avoJsonDir = System.getProperty("user.dir") + File.separator + "avo_jsons";

	/**
	 * Parses AVO, and retrieves all the json strings available. store all of them onto disk
	 * @return
	 * @throws IOException
	 */
	public void parseAVODirForJsonNames() throws IOException {
		Document doc = Jsoup.connect(avoUrl).get();
		Elements alla = doc.select("a");
		ArrayList<String> jsonNames = new ArrayList<String>();
		int count = 0;
		for (Element a : alla) {
			if (a.html().contains(".json")) {
				String jsonName = a.html(); // jsonSubUrl ex: APK_duplicate_file.json
				jsonNames.add(jsonName);
				count++;
			}
		}
		System.out.println("*****Parsed " + count + " json files from AVO.org*****");
		File vulFolder = new File(avoJsonDir);
		vulFolder.mkdirs(); // make directory if doesn't exist
		for (File f : vulFolder.listFiles()) { // delete existing
			f.delete();
		}
		ObjectMapper mapper = new ObjectMapper();
		mapper.enable(SerializationFeature.INDENT_OUTPUT);

		for (String name : jsonNames) {
			System.out.println("Parsing " + name);
			String url = avoUrl + name;
			String json = Jsoup.connect(url).ignoreContentType(true).execute().body();
			String vulPath = avoJsonDir + File.separator + name;
			PrintWriter out = new PrintWriter(vulPath);
			out.print(json);
			out.close();
		}
	}

	/**
	 * Parse all cve numbers from AVO vulnerabilities
	 * @throws IOException 
	 */
	public ArrayList<String> extractCVEs() throws IOException {
		ArrayList<String> cves = new ArrayList<String>();
		File folder = new File(avoJsonDir);
		File[] listOfFiles = folder.listFiles();
		for (int i = 0; i < listOfFiles.length; i++) {
			if (!listOfFiles[i].isFile()) {
				continue;
			}
			BufferedReader br = new BufferedReader(new FileReader(listOfFiles[i]));
			String json = "";
		    String line;
		    while ((line = br.readLine()) != null) {
		       json = json.concat(line);
		    }
		    br.close();
		    ObjectMapper mapper = new ObjectMapper();
		    //System.out.println(json);
		    mapper.enable(DeserializationFeature.ACCEPT_EMPTY_ARRAY_AS_NULL_OBJECT);
		    mapper.enable(DeserializationFeature.ACCEPT_SINGLE_VALUE_AS_ARRAY);
		    mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
		    AVOData avoJson = (AVOData) mapper.readValue(json, AVOData.class);
		    if (avoJson.CVE == null) {
		    	continue;
		    }
	    	for (ArrayList<String> cveInfo : avoJson.CVE) {
	    		for (String str : cveInfo) {
	    			if (str.matches("CVE-\\d+-\\d+")) {
	    				cves.add(str);
	    			}
	    		}
	    	}
		}
		System.out.println("*****Parsed " + cves.size() + " CVE from AVO*****");
		return cves;
	}

	public ArrayList<String> findUniqueCVEFromAVO(ArrayList<String> avoCves) {
		HashSet<String> existingCves = new HashSet<String>();
		ArrayList<String> uniqueCve = new ArrayList<String>();
		File folder = new File(FileIO.vulnerabilityDir);
		File[] listOfFiles = folder.listFiles();
		for (int i = 0; i < listOfFiles.length; i++) {
			if (!listOfFiles[i].isFile()) {
				continue;
			}
			String name = listOfFiles[i].getName().replace(".json", "");
			existingCves.add(name);
		}
		for (String avoCve : avoCves) {
			if (!existingCves.contains(avoCve)) {
				uniqueCve.add(avoCve);
			}
		}
		System.out.println("*****Found " + uniqueCve.size() + " unique CVEs in AVO****");
		return uniqueCve;
	}
}
