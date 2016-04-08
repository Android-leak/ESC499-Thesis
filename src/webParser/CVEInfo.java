package webParser;

public class CVEInfo {
	public enum Origin {
		OVA,
		CVEDetail,
		NIST
	}
	public String cveID;
	public Origin origin;
}
