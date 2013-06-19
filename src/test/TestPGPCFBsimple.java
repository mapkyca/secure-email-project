/*
 * Oxford Brookes University Secure Email Proxy 
 * Copyright (C) 2002/3 Oxford Brookes University Secure Email Project
 * http://secemail.brookes.ac.uk
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 * 
 * The Secure Email Project is:
 * 
 * Marcus Povey <mpovey@brookes.ac.uk> or <icewing@dushka.co.uk>
 * Damian Branigan <dbranigan@brookes.ac.uk>
 * George Davson <gdavson@brookes.ac.uk>
 * David Duce <daduce@brookes.ac.uk>
 * Simon Hogg <simon.hogg@brookes.ac.uk>
 * Faye Mitchell <frmitchell@brookes.ac.uk>
 * 
 * For further information visit the secure email project website.
 */

package test;
import java.security.*;
import java.math.BigInteger;
import org.bouncycastle.jce.provider.*;
import core.algorithmhandlers.openpgp.*;
import core.algorithmhandlers.openpgp.packets.*;
import core.algorithmhandlers.keymaterial.*;
import core.algorithmhandlers.openpgp.util.*;
import java.io.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.spec.*;

/**
 * Test the CFB mode used for secret key material and symmetrically encrypted session key packets.
 */
public class TestPGPCFBsimple extends Test {
    
    public final int skalgorithm = 1;
    public final int hashalgorithm = 2;
    public final String csvColumnHeader = "Pass, Successful?, Data length, Failed at";
    
    private BufferedWriter file;
    protected String filenm;
    protected int itterations;
    
    private byte[] IV;
    
    /** Creates a new instance of TestPGPCFBsimple */
    public TestPGPCFBsimple(int its, String filename) {
        setTestName("Test PGPCFB simple mode"); // name of the test to be printed on the console.
        
        itterations = its;
        filenm = filename;
    }
    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        if (args.length <= 1) {
            System.out.println("TestPGPCFB (simple)");
            System.out.println();
            System.out.println("Usage: java test.TestPGPCFB itterations outputfile");
            System.out.println();
            System.out.println("Itterations = number of times the test is run & the max number of bytes\nto test with the cipher.");
            System.out.println("outputfile = filename to output the test trace to in CSV format.");
        } else {
            TestPGPCFBsimple t = new TestPGPCFBsimple(Integer.parseInt(args[0]), args[1]);

            t.printWelcome();

            t.doTest();
        }
    }
    
    protected byte[] encrypt(Key key, byte[] data) throws Exception {

        int blockSize = SymmetricAlgorithmSettings.getDefaultBlockSize(skalgorithm)/8;

        // create cipher
        Cipher cipher = Cipher.getInstance(SymmetricAlgorithmSettings.getCipherText(skalgorithm) + "/PGPCFB/" + SymmetricAlgorithmSettings.getPaddingText(skalgorithm),"BC");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        IV = cipher.getIV();
        
        return cipher.doFinal(data);  
    }
    
    protected byte[] decrypt(Key key, byte[] data) throws Exception {

        int blockSize = SymmetricAlgorithmSettings.getDefaultBlockSize(skalgorithm)/8;

        IvParameterSpec iv = new IvParameterSpec(IV); 
        
        // create cipher
        Cipher cipher = Cipher.getInstance(SymmetricAlgorithmSettings.getCipherText(skalgorithm) + "/PGPCFB/" + SymmetricAlgorithmSettings.getPaddingText(skalgorithm),"BC");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);

        return cipher.doFinal(data);
    }
    
    protected void writeCSV(int pass, boolean ok, int datalength, int failedat) throws Exception {
        file.write(pass + "," + ok + "," + datalength + "," + failedat);
        file.newLine();
        file.flush();
    }
    
    /** <p>Execute the test.</p>
     * <p>You should implement this method with your test. Return true if the test
     * was successful, otherwise return false.</p>
     */
    public boolean test() throws Exception {

        SecureRandom rnd;
        Key key;
       
        
        // initialising
        System.out.println("Output will be written to " + filenm);

        file = new BufferedWriter(new FileWriter(filenm));
        file.write(csvColumnHeader); // write CSV column headers
        file.newLine();
        file.flush();

        System.out.println("Adding Bouncy Castle JCE provider...");
        Security.addProvider(new BouncyCastleProvider());

        System.out.println("Initialising RNG...");
        rnd = SecureRandom.getInstance("SHA1PRNG");

        System.out.println("Generating key...");
        KeyGenerator k = KeyGenerator.getInstance(SymmetricAlgorithmSettings.getCipherText(skalgorithm), "BC");
        k.init(SecureRandom.getInstance("SHA1PRNG"));
        key = k.generateKey();

        
        
        
     
        System.out.println("Executing test, please wait...");
        boolean allok = true; // has every test so far been successful?
        for (int n = 0; n < itterations; n++) {
            
            // data and result registers
            boolean success = true; // is this test pass successful
            int failedat = -1;
            
            // execute test and record results
            try {
                byte raw[] = new byte[n+1];
                rnd.nextBytes(raw);
                
                byte enc[] = encrypt(key, raw);
                byte dec[] = decrypt(key, enc);
                
                // compare
                for (int na = 0; na < n+1; na++) {
                    if (dec[na]!= raw[na]) {
                        System.out.println("Pass " + n + ": has failed, check trace file for details.");
                        failedat = na;
                        success = false;
                        allok = false;
                        break;
                    }
                }
                
            } catch (Exception e) {
                System.out.println(e.getMessage());
                success = false;
                allok = false;
                
                throw e;
            }
            
            // write csv stuff
            writeCSV(n, success, n+1, failedat);
            
        }
        
        // close file
        file.flush();
        file.close();

        return allok;
    }
    
}
