package nist;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class VulnCpe {
	// Ex: cpe:/a:adobe:flash_player:20.0.0.306::~~~edge~~
	public String productType = "";
	public String vendor = "";
	public String product = "";
	public String version = "";
	public String edition = "";
	public String cpeStr = "";

	public VulnCpe(String cpeStr) {
		this.cpeStr = cpeStr;
		Pattern p = Pattern.compile("cpe:\\/(.*)");
		Matcher m = p.matcher(cpeStr);
		if (!m.find()) {
			System.out.println("Improper CPE");
		}
		cpeStr = m.group(1);
		String[] tokens = cpeStr.replace("::", ":").split(":");
		this.productType = tokens[0];
		this.vendor = tokens[1];
		this.product = tokens[2];
		if (tokens.length >= 4) {
			this.version = tokens[3];
		}
		if (tokens.length >= 5) {
			this.edition = tokens[4];
		}
	}
	
	public String toString() {
		return String.format("%s:%s:%s", this.productType, this.vendor, this.product) + 
				(this.version.isEmpty() ? "" : ":" + this.version) + 
				(this.edition.isEmpty() ? "" : ":" + this.edition);
	}

	public static void main(String[] args) {
//		String[] test = {"cpe:/a:adobe:flash_player:20.0.0.306::~~~edge~~",
//				"cpe:/a:adobe:flash_player:11.2.202.569",
//				"cpe:/o:google:android",
//				"cpe:/o:linux:linux_kernel"};
//		for (String str : test) {
//			System.out.println(new CPE(str));
//		}
	}
}
