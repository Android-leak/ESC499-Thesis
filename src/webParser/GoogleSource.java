package webParser;

public class GoogleSource {
	public String rootDirectory = null;
	public String branch = null;
	public String subDirectory = null;
	
	public GoogleSource(String root, String branch, String sub) {
		this.rootDirectory = root;
		this.branch = branch;
		this.subDirectory = sub;
	}
}
