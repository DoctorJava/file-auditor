package com.websecuritylab.tools.fileauditor.model;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Report {
	public String app;
	
	public Map<String, FileSummary> fileSummary = new HashMap<>();
	public Map<String, List<FileMatches>> fileDetails = new HashMap<>();
	
	public Report(String app) {
		this.app = app;
	}
	
	public void addFileMatch(PowerShellSearchResult r) {
//		if ( fileDetails.containsKey(r.Filename)) {
//			
//		}else {
//			FileMatches fm = new FileMatches();
//			fileDetails.put( r.Filename, new FileMatches())
//		}
//		fileDetails.put(fm.filename, fm.matches);
		
		String fKey = r.Path;
		String mKey = r.Matches.get(0);
		if ( fKey.equals(mKey)) {
			System.out.println("Ignoring filename match: " + mKey );
			return;
		}
	    if ( fileSummary.containsKey( fKey )) {
	    	// System.out.println("Already got: " + r.Filename);
	    	if ( fileSummary.get(fKey).matchCount.containsKey( mKey )) {
	    		Map<String, Integer> mc = fileSummary.get(fKey).matchCount;
	    		mc.put(mKey, mc.get(mKey) + 1);    		
	    	} else {
	    		fileSummary.get(fKey).matchCount.put(fKey, new Integer(1));
	    	}
	    	fileDetails.get(fKey).add(new FileMatches(r.Filename,r.Path));
	    }else {
	    	//System.out.println("Got new: " + r.Filename);
	    	
	    	FileSummary fs = new FileSummary(r.Filename,r.Path);
	    	fs.matchCount.put(mKey, new Integer(1));
	    	fileSummary.put(fKey, fs);
    	
	    	FileMatches fm = new FileMatches(r.Filename,r.Path);
	    	fm.addMatch(r);
	    	List<FileMatches> fmList = new ArrayList<>();
	    	fmList.add(fm);
	    	fileDetails.put(fKey, fmList);
	    }
	}
}
