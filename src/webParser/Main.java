package webParser;

import java.io.IOException;
import java.util.ArrayList;

public class Main {
	public static void main(String[] args) throws IOException {

		AVOParser avoParser = new AVOParser();
		//avoParser.parseAVODirForJsonNames();
		ArrayList<String> avoCves = avoParser.extractCVEs();
		ArrayList<String> newCves = avoParser.findUniqueCVEFromAVO(avoCves);
		
		
	}
}
