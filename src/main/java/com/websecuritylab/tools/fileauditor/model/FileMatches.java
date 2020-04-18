package com.websecuritylab.tools.fileauditor.model;

import java.util.ArrayList;
import java.util.List;

public class FileMatches {
    public String filename;
    public String path;

    List<Match> matches = new ArrayList<>();

	public FileMatches(String filename, String path) {
		this.filename = filename;
		this.path = path;
	}
	
	public void addMatch(PowerShellSearchResult r) {
		matches.add( new Match(r.LineNumber, r.Line, r.Matches.get(0)));
	}

}
