package nist;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CompositeScoreCalculator {

	private HashMap<String, Double> androidCoverage = new HashMap<String, Double>();
	private String androidScoreDir = System.getProperty("user.dir") + File.separator + "android_versions.csv";

	public CompositeScoreCalculator() {
		try (BufferedReader br = new BufferedReader(new FileReader(androidScoreDir))) {
		    String line;
		    while ((line = br.readLine()) != null) {
		       String[] tokens = line.split(",");
		       androidCoverage.put(tokens[0], Double.parseDouble(tokens[1]));
		    }
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Deprecated
	public double impactScore(NVDEntry entry) {
		double coveragePercent = calculateVersionCoverage(entry);
		double decayValue = calculateStartDateDecay(entry);
		double cvss = entry.CVSS.score;
		return coveragePercent * decayValue * cvss;
	}
	
	@Deprecated
	public double patchabilityScore(NVDEntry entry) {
		double coveragePercent = calculateVersionCoverage(entry);
		double decayValue = calculateStartDateDecay(entry);
		double result = 1 - coveragePercent * decayValue;
		return result;
	}

	private double calculateStartDateDecay(NVDEntry entry) {
		long diffSec = (new Date(2016, 3, 23).getTime() - entry.getDate().getTime());
		int diffDay = (int) (diffSec / 86400000);
		return decay(diffDay);
	}

	
	public void getScores(ArrayList<NVDEntry> entries, String region) {
		double cvss = 0.0;
		double decay = 0.0;
		double impact = 0.0;

		for (NVDEntry entry : entries) {
			cvss += entry.CVSS.score;
			impact += calculateVersionCoverage(entry);
			decay += calculateStartDateDecay(entry);
		}
		System.out.println("\n*****REGION=" + region + "*****");
		System.out.println("Vulnerability#=" + entries.size());
		System.out.println("Cvss avg=" + cvss / entries.size());
		System.out.println("Lifetime Decay avg=" + decay/ entries.size());
		System.out.println("Impact avg=" + impact / entries.size());
	}


	/**
	 * decay function according to Thomas et al.'s paper.
	 * Input is number of days since release
	 * @param t
	 * @return
	 */
	private double decay(int t) {
		double t0 = 80.6;
		double decay = 0.00262;
		if (t < t0) {
			return 1.0;
		}
		double result = Math.exp(-decay * (t - t0));
		return result;
	}
	
	private double calculateVersionCoverage(NVDEntry entry) {
		double coverage = 0.0;
		HashSet<String> versions = new HashSet<String>(); 
		for (VulnCpe cpe : entry.CPEs) {
			if (!cpe.product.equals("android")) {
				continue;
			}
			Pattern p = Pattern.compile("(\\d\\.\\d)");
			Matcher m = p.matcher(cpe.version);
			if (m.find()) {
				versions.add(m.group(1));
			}
		}
		for (String ver : versions) {
			if (androidCoverage.containsKey(ver)) {
				coverage += androidCoverage.get(ver);
			}
		}
		return coverage;
	}
	
	
}
