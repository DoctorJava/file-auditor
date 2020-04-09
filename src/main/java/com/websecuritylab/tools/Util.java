package com.websecuritylab.tools;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Util {
    private static final Logger logger = LoggerFactory.getLogger( Util.class );  
	final static int BUFFER = 2048;
	
	public static final String[] ignoreExt = new String[] { "gif", "png", "jpg", "jpeg", "svg", "css", "scss"};
	public static final Set<String> IGNORE_EXT = new HashSet<>(Arrays.asList(ignoreExt));
	
	public static final String HR_START = ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>";
	public static final String HR_END 	= "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<";
	
	public static String withSlashStar(String path) {
		if ( path.endsWith("*") ) return path;
		else if ( path.endsWith("/") ) return path + "*";
		else if ( path.endsWith("\\") ) return path + "*";
		else  return path + "/*"; 
	}


	
    private static final int BUFFER_SIZE = 4096;

    
    public static void unjar(String jarFilePath, File tempDir) throws IOException {
    	String destDirectory = tempDir.getAbsolutePath();
        File destDir = new File(destDirectory);
        if (!destDir.exists()) {
            destDir.mkdir();
        }
        logger.info("Unjaring file: " + jarFilePath + " to temp directory: " + tempDir);

    }
 

    
	public static void zipDir(String zipFileName, String dir) throws Exception {
		File dirObj = new File(dir);
		ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(zipFileName));
		logger.info("Creating : " + zipFileName);
		addDir(dirObj, zos);
		zos.finish();
		//out.close();
	}

    private static void addDir(File dirObj, ZipOutputStream out) throws IOException {
        File[] files = dirObj.listFiles();
        byte[] tmpBuf = new byte[1024];

        for (int i = 0; i < files.length; i++) {
          if (files[i].isDirectory()) {
            addDir(files[i], out);
            continue;
          }
          
          FileInputStream in = new FileInputStream(files[i].getAbsolutePath());
         
          String filePath = files[i].getPath();
          if ( filePath.contains(":")) filePath = filePath.substring( filePath.indexOf(":") + 1);  // Strip drive from Windows Path (D:/) because it is illegal for zip file
          if ( filePath.startsWith("/") || filePath.startsWith("\\") ) filePath = filePath.substring(1);  // Strip drive from Windows Path (D:/) because it is illegal for zip file

          logger.info(" Adding: " + filePath);
          out.putNextEntry(new ZipEntry(filePath));
          
          int len;
          while ((len = in.read(tmpBuf)) > 0) {
            out.write(tmpBuf, 0, len);
          }
          out.closeEntry();
          in.close();
        }
      }
    
    //public void unzip(String zipFilePath, String destDirectory) throws IOException {
    public static void unzip(String zipFilePath, File tempDir) throws IOException {
    	String destDirectory = tempDir.getAbsolutePath();
        File destDir = new File(destDirectory);
        if (!destDir.exists()) {
            destDir.mkdir();
        }
        logger.info("Unzipping file: " + zipFilePath + " to temp directory: " + tempDir);
        ZipInputStream zipIn = new ZipInputStream(new FileInputStream(zipFilePath));
        ZipEntry entry = zipIn.getNextEntry();
        // iterates over entries in the zip file
        while (entry != null) {
            String filePath = destDirectory + File.separator + entry.getName();  	// Error extracting file: C:\Users\scott\AppData\Local\Temp\netdoc\META-INF/MANIFEST.MF
            //String filePath = destDirectory + "/" + entry.getName();
            if (!entry.isDirectory()) {
                // if the entry is a file, extracts it
                extractFile(zipIn, filePath);
            } else {
                // if the entry is a directory, make the directory
                File dir = new File(filePath);
                dir.mkdir();
            }
            zipIn.closeEntry();
            entry = zipIn.getNextEntry();
        }
        zipIn.close();
    }
    /**
     * Extracts a zip entry (file entry)
     * @param zipIn
     * @param filePath
     * @throws IOException
     */
    private static void extractFile(ZipInputStream zipIn, String filePath) throws IOException {
    	try (
    			BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(filePath));)
    	{
            byte[] bytesIn = new byte[BUFFER_SIZE];
            int read = 0;
            while ((read = zipIn.read(bytesIn)) != -1) {
                bos.write(bytesIn, 0, read);
            }   		
    	}catch ( Exception e) {
    		logger.error("EEEEEEEEEEEEError extracting file: " + filePath + " with error: " + e.getMessage());
    	}

    }
	
	public static File createTempDir(String dirStr) throws IOException {
		String tempDirStr = File.createTempFile("temp-file", "tmp").getParent()+"/" + dirStr;
		File tempDir  = new File(tempDirStr);
		if (tempDir.exists()) {
			//emptyDir(tempDir);
			deleteDir(tempDir);
		} else {
			boolean createdTempFolder = tempDir.mkdirs();
			if (!createdTempFolder) throw new IOException();
			logger.info("Created Temp Directory: "+tempDir.getAbsolutePath());			
		}
		return tempDir;
	}

	public static boolean  deleteDir(File directoryToBeDeleted) {
		File[] allContents = directoryToBeDeleted.listFiles();
		if (allContents != null) {
			for (File file : allContents) {
				deleteDir(file);
			}
		}
		return directoryToBeDeleted.delete();
	}
	
	public static String runCommand(boolean isLinux, String cmd, boolean isVerbose) throws IOException {
		StringBuffer output = new StringBuffer();
		logger.info("Running command: " + cmd);
        ProcessBuilder processBuilder = new ProcessBuilder();
        if ( isVerbose ) {
            System.out.println(HR_START);
            System.out.println("Running "+ ( isLinux ? "LINUX" : "WINDOWS" ) +" command: ");
            System.out.println();
            System.out.println(cmd);
            System.out.println();       	
        }
        //
        // This code HUNG on Windows 
        //
//       if ( isLinux )
//        	processBuilder.command("sh", "-c", cmd);
//        else
//        	processBuilder.command("cmd.exe", "/c", cmd);			// Windows
//
//        try {
//
//            Process process = processBuilder.start();
//
//            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
//
//            String line;
//            while ((line = reader.readLine()) != null) {
//                System.out.println(line);
//                output.append(line);
//            }
//
//            int exitCode = process.waitFor();
//            logger.debug("\nExited with error code : " + exitCode);
//            if ( isVerbose ) System.out.println("\nExited with error code : " + exitCode);
//
//        } catch (IOException e) {
//            e.printStackTrace();
//        } catch (InterruptedException e) {
//            e.printStackTrace();
//        }
		final File tmp = File.createTempFile("netdocOut", null);
		try {
			tmp.deleteOnExit();

			if (isLinux)
				processBuilder.command("sh", "-c", cmd).redirectErrorStream(true).redirectOutput(tmp);
			else
				processBuilder.command("cmd.exe", "/c", cmd).redirectErrorStream(true).redirectOutput(tmp); // Windows

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
	
}
