package webParser;

import java.util.ArrayList;
import java.util.HashMap;

public class AVOData {
	public String name;
	public ArrayList<ArrayList<String>> CVE;
	//public boolean Responsibly_disclosed;
	//public ArrayList<String> Categories;
	//public String Severity;
	//public ArrayList<ArrayList<String>> Details;
	//public ArrayList<ArrayList<String>> Discovered_by;
	//public ArrayList<HashMap<String, String>> Discovered_on;
	//public ArrayList<HashMap<String, String>> Submission;
	//public ArrayList<ArrayList<String>> Reported_on;
	//public ArrayList<ArrayList<String>> Fixed_on;
	//public ArrayList<ArrayList<String>> Fix_released_on;
	//public ArrayList<ArrayList<String>> Affected_versions;
	//public ArrayList<ArrayList<String>> Affected_devices;
	//public ArrayList<String> Affected_versions_regexp;
	//public ArrayList<ArrayList<String>> Affected_manufacturers;
	//public ArrayList<ArrayList<String>> Fixed_versions;
	public HashMap<String, AVOSource> references;

}