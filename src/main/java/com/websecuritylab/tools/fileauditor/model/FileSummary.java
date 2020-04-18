package com.websecuritylab.tools.fileauditor.model;

import java.util.HashMap;
import java.util.Map;

public class FileSummary {
    public String filename;
    public String path;
    public Map<String, Integer> matchCount = new HashMap<>();
	
    public FileSummary(String filename, String path) {
		this.filename = filename;
		this.path = path;
	}
    
    
}
