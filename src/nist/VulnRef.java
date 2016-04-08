package nist;

import java.io.File;
import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import webParser.GoogleSource;

public class VulnRef {
	public String url;
	public boolean isAndroidSource;
	public boolean isSecurityBulletin;
	public boolean isLinuxSource;
	public ArrayList<GoogleSource> googleSource = new ArrayList<GoogleSource>();

	private void parseGoogleSourceUrl(String url) {
		try {
			String androidDirList = System.getProperty("user.dir") + File.separator + "sources.csv";
			PrintWriter out = new PrintWriter(new FileOutputStream(new File(androidDirList), true));

			Pattern patt = Pattern.compile("https://android.googlesource.com(.*)\\+/(.*)");
			Matcher m = patt.matcher(url);
			if (!m.find()) {
				out.close();
				return;
			}
			this.isAndroidSource = true;
			String rootDir = m.group(1);
			String commitBranch = m.group(2);
			if (commitBranch.equals("5a9753fca56f0eeb9f61e342b2fccffc364f9426")) {
				out.close();
				return; // this one is merge conflict
			}
			String subDir = "";
			if (commitBranch.contains("/")) {
				// this url points to a specific file
				int ind = commitBranch.indexOf("/");
				subDir = commitBranch.substring(ind);
				subDir = subDir.replaceAll("%2F", "/");
				commitBranch = commitBranch.substring(0, ind);
				this.googleSource.add(new GoogleSource(rootDir, commitBranch, subDir));
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
				if (doc.getElementsByClass("DiffTree").size() == 0) {
					this.isAndroidSource = false;
					out.close();
					return;
				}
				Element diffTree = doc.getElementsByClass("DiffTree").get(0);
				Elements lis = diffTree.select("li");
				for (Element li : lis) {
					subDir = li.select("a").get(0).html();
					subDir = subDir.replaceAll("%2F", "/");
					String str = String.format("%s,%s,%s", rootDir, commitBranch, subDir);
					out.println(str);
					this.googleSource.add(new GoogleSource(rootDir, commitBranch, subDir));
				}
				out.close();
			}
		}
		catch (Exception e) {
			this.isAndroidSource = false;
			e.printStackTrace();
		}
	}
	
	private void parseLinuxSource(String url) {
		if (url.contains("Kernel") || url.contains("kernel")) {
			this.isLinuxSource = true;
		}
	}
	
	public VulnRef(String url) {
		this.url = url;
		parseGoogleSourceUrl(url);
		this.isSecurityBulletin = url.contains("source.android.com");
		parseLinuxSource(url);
	}
}
