package nist;

import org.w3c.dom.Element;

public class VulnCvss {
	public double score;
	public String accessVector;
	public String accessComplexity;
	public String authentication;
	public String confidentialityImpact;
	public String integrityImpact;
	public String availabilityImpact;
	public String date;
	
	public VulnCvss() {
		
	}
	
	public VulnCvss(Element vulnCvss) {
		if (vulnCvss == null) {
			return;
		}
		Element metrics = (Element)vulnCvss.getElementsByTagName("cvss:base_metrics").item(0);
		String scoreStr = metrics.getElementsByTagName("cvss:score").item(0).getTextContent();
		this.score = Double.parseDouble(scoreStr);
		this.accessVector = metrics.getElementsByTagName("cvss:access-vector").item(0).getTextContent();
		this.accessComplexity = metrics.getElementsByTagName("cvss:access-complexity").item(0).getTextContent();
		this.authentication = metrics.getElementsByTagName("cvss:authentication").item(0).getTextContent();
		this.confidentialityImpact = metrics.getElementsByTagName("cvss:confidentiality-impact").item(0).getTextContent();
		this.integrityImpact = metrics.getElementsByTagName("cvss:integrity-impact").item(0).getTextContent();
		this.availabilityImpact = metrics.getElementsByTagName("cvss:availability-impact").item(0).getTextContent();
		this.date = metrics.getElementsByTagName("cvss:generated-on-datetime").item(0).getTextContent();
		
	}
}
