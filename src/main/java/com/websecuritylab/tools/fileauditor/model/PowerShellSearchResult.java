package com.websecuritylab.tools.fileauditor.model;

import java.util.List;

public class PowerShellSearchResult {
	
    public Boolean IgnoreCase;
    public Integer LineNumber;
    public String Line;
    public String Filename;
    public String Path;
    public String Pattern;
    public String Context;
    public List<String> Matches;
    
    
    public PowerShellSearchResult() {};
    
//	[ {
//	  "IgnoreCase" : true,
//	  "LineNumber" : 67,
//	  "Line" : "            cipher = new BlowfishEngine();",
//	  "Filename" : "BlockCipherSpec.java",
//	  "Path" : "C:\\Users\\scott\\AppData\\Local\\Temp\\fileauditor\\decompiled\\org\\cryptacular\\spec\\BlockCipherSpec.java",
//	  "Pattern" : "rijndael|blowfish",
//	  "Context" : null,
//	  "Matches" : [ "Blowfish" ]
//	} ]
}
