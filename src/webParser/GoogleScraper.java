package webParser;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;

/**
 * Not working. Lack of access to Google's search results
 * @author Jim
 *
 */
public class GoogleScraper {
	public static void scrap() throws IOException {
		URL url = new URL("https://www.google.ca/?gfe_rd=cr&ei=IhfrVrWjGMOC8Qf0oYj4BQ&gws_rd=ssl#q=android+site:cvedetails.com&start=0");
		try (BufferedReader reader = new BufferedReader(new InputStreamReader(url.openStream(), "UTF-8"))) {
		    for (String line; (line = reader.readLine()) != null;) {
		        System.out.println(line);
		    }
		}
	}
	public static void main(String[] args) throws IOException {
		GoogleScraper.scrap();
	}
}
