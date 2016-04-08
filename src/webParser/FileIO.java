package webParser;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

public class FileIO {
	public static String vulnerabilityDir = System.getProperty("user.dir") + File.separator + "vulnerabilities";

	/**
	 * Returns the list of vulnerabilities stored on the file system
	 * @throws IOException 
	 */
	public static ArrayList<CVEData> readVulnerabilities() throws IOException {
		ArrayList<CVEData> localVuls = new ArrayList<>(); 
		File vulFolder = new File(vulnerabilityDir);
		ObjectMapper mapper = new ObjectMapper();
		for (final File fileEntry : vulFolder.listFiles()) {
	        if (fileEntry.isDirectory()) {
	        	continue;
	        }
	        // for each json file, read in
			CVEData vul = mapper.readValue(
					new File(fileEntry.getAbsolutePath()), CVEData.class);
	        localVuls.add(vul);
	    }
		return localVuls;
	}
	
	/**
	 * Writes the list of vulnerabilities to the file system. 
	 * Note: Will delete and overwrite everything in the /vulnerabilities folder
	 * @param vulnerabilities
	 * @throws FileNotFoundException
	 * @throws JsonProcessingException
	 */
	public static void writeVulnerabilities(ArrayList<CVEData> vulnerabilities) 
			throws FileNotFoundException, JsonProcessingException {
		File vulFolder = new File(vulnerabilityDir);
		vulFolder.mkdirs(); // make directory if doesn't exist
		for (File f : vulFolder.listFiles()) { // delete existing
			f.delete();
		}
		
		ObjectMapper mapper = new ObjectMapper();
		mapper.enable(SerializationFeature.INDENT_OUTPUT);

		for (CVEData v : vulnerabilities) {
			String vulPath = vulnerabilityDir + File.separator + v.cveID + ".json";
			PrintWriter out = new PrintWriter(vulPath); 
			out.print(mapper.writeValueAsString(v));
			out.close();
		}
		System.out.println("*****" + vulnerabilities.size() + " vulnerabilities written to FS*****");
	}

}
