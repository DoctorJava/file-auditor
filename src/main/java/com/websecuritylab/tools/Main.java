package com.websecuritylab.tools;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Collection;
import java.util.Properties;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import groovy.json.JsonOutput;


public class Main {
	
	private enum SOURCE_TYPE { L }
	
	public enum FIND_EXT { jar, java, war }
    private static final Logger logger = LoggerFactory.getLogger( Main.class );  
	private static final String PROPS_FILE = "file-auditor.props";
	private static final String SYNTAX = "java -jar file-auditor.jar ";
	private static final String RUN_DECOMPILE = "java -jar lib/%s  %s --outputdir %s";				// Synax for CFR: java -jar lib/<CFR>.jar <FILES> --outputdir <OUTPUT_DIR>
	private static final String TEMP_DIR = "fileauditor";
	
	private static Properties props = new Properties();		
	String cfrJar = props.getProperty(CliOptions.CFR_JAR);


	public static void main(String[] args) {
		String mainCmd = SYNTAX + String.join(" ", Arrays.asList(args));
		logger.info(mainCmd);
		
		CommandLine cl = CliOptions.generateCommandLine(args);
		if (cl.getOptionValue(CliOptions.REPORT_JSON) != null ) {
			try ( InputStream is = new FileInputStream( cl.getOptionValue(CliOptions.REPORT_JSON) ); )
			{	
				String appName = cl.getOptionValue(CliOptions.APP_NAME);
	            String jsonTxt = IOUtils.toString(is, "UTF-8");
	            //System.out.println("Got JSON: " + jsonTxt);
				outputJsonReport(jsonTxt, appName);   // This is a pretty print version.  The doclet output is not.
				outputHtmlReport(jsonTxt,appName);
			}catch (Exception e) {
				e.printStackTrace();
			}
			return;
		}
		System.out.println();
		String propFile = PROPS_FILE;
		if (cl.getOptionValue(CliOptions.PROP_FILE) != null ) propFile = cl.getOptionValue(CliOptions.PROP_FILE);

		try ( InputStream fis = new FileInputStream(propFile); ) {
			props.load(fis);
			logger.info("Got prop SOURCE_DIR: " + props.getProperty(CliOptions.SOURCE_DIR));
		} catch (IOException e) {
			props.setProperty(CliOptions.SOURCE_TYPE, "A");
			props.setProperty(CliOptions.SOURCE_DIR, ".");
			props.setProperty(CliOptions.CFR_JAR, "cfr-0.147.jar");
			
		}	
	
		boolean isVerbose = false;
		boolean isKeepTemp = false;
		boolean isLinux = false;
		try (BufferedReader buf = new BufferedReader(new InputStreamReader(System.in))) {
			if (cl.hasOption(CliOptions.HELP)) {
				CliOptions.printHelp(SYNTAX);
				FileUtil.finish();
			} 

			if (cl.hasOption(CliOptions.VERBOSE)) isVerbose = true;
			if (cl.hasOption(CliOptions.KEEP_TEMP)) isKeepTemp = true;
			if (cl.hasOption(CliOptions.IS_LINUX)) isLinux = true;
			if (cl.getOptionValue(CliOptions.CFR_JAR) != null )  props.setProperty(CliOptions.CFR_JAR, cl.getOptionValue(CliOptions.CFR_JAR));

			
			OutputStream output = new FileOutputStream(PROPS_FILE);
			props.store(output,  null);
			
			System.out.println("---------- NetDoc Scanning Properties ----------");
			System.out.println("File: " + propFile);
			System.out.println();
			System.out.println(props.toString().replace(", ", "\n").replace("{", "").replace("}", ""));  
			System.out.println("------------------------------------------------");
			
			
		} catch (Exception e) {
			e.printStackTrace();
			//return;
		} 

		
		
		
		
	}
	
	private static void run(SOURCE_TYPE sourceType, boolean isLinux, boolean keepTemp, boolean isVerbose) throws IOException {
		File tempDir = Util.createTempDir(TEMP_DIR);
		String tempPath = tempDir.getAbsolutePath().replace("\\","/");		// replace windows backslash because either works with the cmd

		String cfrJar = props.getProperty(CliOptions.CFR_JAR);

		String decompiledPath = tempPath + "/decompiled";

        try {
        	switch( sourceType )
			{
				case L:
				String dir = "D:/dev/tools/NetDoc/samples/lib";
				File filePath = new File(dir);
				Collection<File> files = FileUtil.listFilesByExt(filePath, FIND_EXT.jar);
				for (File file: files ) {
					String runDecompileA = String.format(RUN_DECOMPILE, cfrJar, file, decompiledPath);
					logger.debug("Running: " + runDecompileA);
					//Util.runCommand(isLinux, runDecompileA, isVerbose);
					break;
				}
			}
        }
        	finally {			// TODO: This doesn't get executed with javadoc command exits with error.
    			if ( !keepTemp ) {
    				Util.deleteDir(tempDir);							
    			}
    		}


	}
	
	
	private static void outputJsonReport(String json, String info) throws IOException {
		String OUT_JSON = "out/net-doc-jee-report_"+info+".json";
		
		try(BufferedWriter writer = new BufferedWriter(new FileWriter(OUT_JSON))){
		    writer.write(JsonOutput.prettyPrint(json)); 
		    System.out.println("Output JSON file: " + OUT_JSON);
		}
	}
	private static void outputHtmlReport(String json, String info) throws IOException {
		String OUT_HTML_SINGLE = "out/net-doc-jee-report_"+info+".html";
		String OUT_HTML_ONLY = "out/net-doc-jee-report_"+info+"_only.html";

			
//		try(BufferedWriter writer = new BufferedWriter(new FileWriter(OUT_HTML_SINGLE))){
//		    writer.write(Util.convertJsToHtml( Util.convertJsonToJs(json), false )); 
//		    System.out.println("Output HTML file: " + OUT_HTML_ONLY);
//		}
//		
		try(BufferedWriter writer = new BufferedWriter(new FileWriter(OUT_HTML_SINGLE))){
		    writer.write(FileUtil.convertJsToHtml( FileUtil.convertJsonToJs(json), true )); 
		    System.out.println("Output HTML file: " + OUT_HTML_SINGLE);
		}		
	}


}
