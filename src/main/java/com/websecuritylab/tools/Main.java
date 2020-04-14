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
	
	private enum SOURCE_TYPE { A, C, S }		// [A]rchive file (WAR/EAR/JAR), [C]LASS files, [S]OURCE files.
	
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
	            FileUtil.outputJsonReport(jsonTxt, appName);   // This is a pretty print version.  The doclet output is not.
	            FileUtil.outputHtmlReport(jsonTxt,appName);
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
			logger.info("Got prop AUDIT_DIR: " + props.getProperty(CliOptions.AUDIT_DIR_PATH));
		} catch (IOException e) {
			props.setProperty(CliOptions.AUDIT_DIRECTORY, "N");
			props.setProperty(CliOptions.SOURCE_TYPE, "A");
			props.setProperty(CliOptions.AUDIT_DIR_PATH, ".");
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

            if (cl.hasOption(CliOptions.INTERACTIVE)) {
            	handlePropInput(buf,CliOptions.AUDIT_DIRECTORY, false);
            	handlePropInput(buf,CliOptions.SOURCE_TYPE, false);
                 
                
//                if ( props.getProperty(CliOptions.SOURCE_TYPE).toUpperCase().startsWith("J") ) {
//   				    String appName = handleTextInput(buf,CliOptions.APP_NAME);
//                	String jsonTxt = handleTextInput(buf,CliOptions.REPORT_JSON);
//                	FileUtil.outputJsonReport(jsonTxt, appName);   // This is a pretty print version.  The doclet output is not.
//                	FileUtil.outputHtmlReport(jsonTxt,appName);
//    				return;
//                } else 
                
                Boolean isDirectory = props.getProperty(CliOptions.AUDIT_DIRECTORY).toUpperCase().startsWith("Y");
                	
                if ( isDirectory ) {
                    handlePropInput(buf,CliOptions.AUDIT_DIR_PATH, true);
               	    String appName = props.getProperty(CliOptions.AUDIT_DIR_PATH);
                	int lastSlash = appName.lastIndexOf("/");			// TODO: Handle Windows backslash too?
                   	if ( lastSlash == appName.length() - 1 ) appName = appName.substring(0,lastSlash);	// Trim last slash 
                   	lastSlash = appName.lastIndexOf("/");
                	if ( lastSlash > 0 ) appName = appName.substring(lastSlash+1);
                	props.setProperty(CliOptions.APP_NAME, appName );              	          	
                  } else {
                      handlePropInput(buf,CliOptions.AUDIT_DIR_PATH, true);
                  	handlePropInput(buf,CliOptions.AUDIT_FILE, false);
                  	String appName = props.getProperty(CliOptions.AUDIT_FILE);
                  	int lastDot = appName.lastIndexOf(".");
                  	if ( lastDot > 0 ) appName = appName.substring(0, lastDot);
                  	props.setProperty(CliOptions.APP_NAME, appName );
               }

                handlePropInput(buf,CliOptions.SEARCH_TEXT, false);
                handlePropInput(buf,CliOptions.APP_NAME, false);
                
               // handlePropInput(buf,CliOptions.IS_LINUX, false);
                String dirPath = props.getProperty(CliOptions.AUDIT_DIR_PATH);
                String filePath = dirPath + props.getProperty(CliOptions.AUDIT_FILE);
    			SOURCE_TYPE sourceType = Enum.valueOf(SOURCE_TYPE.class, props.getProperty(CliOptions.SOURCE_TYPE).toUpperCase());
                 
                Collection<File> files = null;
                if ( isDirectory ) {
                    System.out.println("Auditing files in folder ("+props.getProperty(CliOptions.AUDIT_DIRECTORY)+"): " + dirPath);
        			File f = new File(dirPath);
        			files = FileUtil.listFilesByExt(f, FIND_EXT.jar);               	
                }
                else {
                    System.out.println("Auditing single file("+props.getProperty(CliOptions.AUDIT_FILE)+"): " + filePath);
        			File f = new File(filePath);
                	files = Arrays.asList(f);
                }
                
                String searchPath = dirPath;
        		if ( sourceType == SOURCE_TYPE.A) {
        			File tempDir = Util.createTempDir(TEMP_DIR);
        			for (File file: files ) {
           				System.out.println("Decompiling file: " + file.getAbsolutePath());		
     					//Util.unzip(file.getAbsolutePath(), tempDir);
           				
           				searchPath = runDecompile(file, tempDir, isLinux, isKeepTemp, isVerbose);	
           			          				
           				
           				
        			}       		
        		}
        		String searchText = props.getProperty(CliOptions.SEARCH_TEXT);
   				System.out.println("Searching file(s) for text: " + searchText);		
   				String outStr = searchRecursiveForString(searchPath, searchText, isLinux, isVerbose);
        		System.out.println("Got OutStr: " + outStr);

//    			for (File file: files ) {
//    				System.out.println("Got file: " + file.getName());		
//
//    				//run(sourceType, isLinux, isKeepTemp, isVerbose);	
//    			}
    			
    			
                logger.info("Running: " + SYNTAX + " -s " +   props.getProperty(CliOptions.AUDIT_DIR_PATH));
            } else {
            	if (props.getProperty(CliOptions.AUDIT_DIR_PATH) != null) {
    				if (!FileUtil.fileFolderExists( props.getProperty(CliOptions.AUDIT_DIR_PATH)))
    					FileUtil.abort("Aborting program.  The source directory (" +  props.getProperty(CliOptions.AUDIT_DIR_PATH) + ") does not exist.");
    			} else {
    				FileUtil.abort("Aborting program.  The root source directory (-s) option is required.");
    			}
            }
			
			OutputStream output = new FileOutputStream(PROPS_FILE);
			props.store(output,  null);
			
			System.out.println("---------- FileAuditor Scanning Properties ----------");
			System.out.println("File: " + propFile);
			System.out.println();
			System.out.println(props.toString().replace(", ", "\n").replace("{", "").replace("}", ""));  
			System.out.println("------------------------------------------------");
			
			

			
		} catch (Exception e) {
			e.printStackTrace();
			//return;
		} 

		
		
		
		
	}
	
	private static String runDecompile(File file, File tempDir, boolean isLinux, boolean keepTemp, boolean isVerbose) throws IOException {
		String tempPath = tempDir.getAbsolutePath().replace("\\", "/"); // replace windows backslash because either works with the cmd

		String cfrJar = props.getProperty(CliOptions.CFR_JAR);

		String decompiledPath = tempPath + "/decompiled/";

		try {
			String runDecompileA = String.format(RUN_DECOMPILE, cfrJar, file, decompiledPath);
			logger.debug("Running: " + runDecompileA);
			Util.runCommand(isLinux, runDecompileA, isVerbose);

		} finally { // TODO: This doesn't get executed with javadoc command exits with error.
			if (!keepTemp) {
				Util.deleteDir(tempDir);
			}
		}
		
		return decompiledPath;

	}

	//Get-ChildItem C:/Users/scott/AppData/Local/Temp/fileauditor/decompiled/*.java -Recurse | Select-String -Pattern "parseTrie" | group path | select name
	
	
	private static String searchRecursiveForString( String rootPath, String searchText, boolean isLinux, boolean isVerbose) throws IOException {
		String HR_START = ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>";
		String HR_END 	= "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<";
		StringBuffer output = new StringBuffer();
		System.out.println("Searching rootPath: " + rootPath);
		// Get-ChildItem 'C:/Users/scott/AppData/Local/Temp/fileauditor/decompiled/*.java' -Recurse | Select-String -Pattern 'CloneNotSupportedException | parseTrie' | ForEach-Object { ' | ' + $_.lineNumber  + ' | ' + $_.fileName + ' | ' + $_.Line }
		// Get-ChildItem 'C:/Users/scott/AppData/Local/Temp/fileauditor/decompiled/*.java' -Recurse | Select-String -Pattern 'CloneNotSupportedException | parseTrie' | ForEach-Object { ' | ' + $_.lineNumber  + ' | ' + $_.fileName + ' | ' + $_.Line }
		String cmd;
		if (isLinux)
			cmd = "TODO: grep command";
		else
			cmd = "Get-ChildItem " + rootPath + " -Recurse | Select-String -Pattern '" + searchText + "' | ForEach-Object { ' | ' + $_.lineNumber  + ' | ' + $_.fileName + ' | ' + $_.Line }";
			//cmd = "Get-ChildItem " + rootPath + " -Recurse | Select-String -Pattern '" + searchText + "' | group path | select name";
			//cmd = "Get-ChildItem C:/Users/scott/AppData/Local/Temp/fileauditor/decompiled/*.java -Recurse | Select-String -Pattern '" + searchText + "' | group path | select name";
		
		
		logger.info("Running command: " + cmd);
        ProcessBuilder processBuilder = new ProcessBuilder();
        if ( isVerbose ) {
            System.out.println(HR_START);
            System.out.println("Running "+ ( isLinux ? "LINUX" : "WINDOWS" ) +" command: ");
            System.out.println();
            System.out.println(cmd);
            System.out.println();       	
        }
		final File tmp = File.createTempFile("netdocOut", null);
		try {
			tmp.deleteOnExit();

			if (isLinux)
				processBuilder.command("sh", "-c", cmd).redirectErrorStream(true).redirectOutput(tmp);
			else
				processBuilder.command("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "-Command", cmd).redirectErrorStream(true).redirectOutput(tmp); // Windows

			final Process process = processBuilder.start();
			final int exitCode = process.waitFor();

			BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(tmp)));
			String line = "";
			while ((line = reader.readLine()) != null) {
				if (isVerbose) System.out.println(line);
				output.append(line);
			}
			reader.close();
			tmp.delete();
			logger.debug("\nExited with error code : " + exitCode);
			if (isVerbose) System.out.println("\nExited with error code : " + exitCode);
		} catch (Exception e) {
			logger.error( "EEEEEEEEEEEEError in runCommand: " + processBuilder.toString() + " with error: " + e.getMessage());
		} finally {
			tmp.delete();
		}
		if (isVerbose) System.out.println(HR_END);

		return output.toString();
		
	}

    private static void handlePropInput(BufferedReader buf, String key, boolean hasTrailingSlash) throws IOException {
        System.out.print("Enter the " + key + " (" + props.getProperty(key) + "): ");
        String entry = buf.readLine();
        if (!entry.equals("")) {
            if (hasTrailingSlash && (!entry.endsWith("/") && !entry.endsWith("\\")) )  props.setProperty( key, entry + "/" );
            else props.setProperty( key, entry);
        }      
    }
    private static String handleTextInput(BufferedReader buf, String key) throws IOException {
        System.out.print("Enter the " + key + " : ");
        String entry = buf.readLine();

        return entry;     
    }
}
