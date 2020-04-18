package com.websecuritylab.tools.fileauditor.model;

import java.util.List;

public class Match {
    public Integer lineNumber;
    public String line;
    public String match;
    
	public Match(Integer lineNumber, String line, String match) {
		this.lineNumber = lineNumber;
		this.line = line;
		this.match = match;
	}
    
    

}
