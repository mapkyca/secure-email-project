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
 * <p>This test will test the SymmetricKeyEncryptedSessionKeyPacket class.</p>
 * <p>It generates two PGP files using both a generated session key and just a passphrase. As well as running
 * this test you should attempt to decode these files using a known good 3rd party implementation of pgp to ensure
 * they are being written in the correct format.</p>
 */
public class TestSKESKP extends Test {
    
    public final String passphrase = "test";
    
    public final int SymmetricAlgorithm = 1;
    public final int hashalgorithm = 2;
    
    /* Literal packet data 1 */
    public final byte format_1 = 't';   
    public final String rawdata_1 = "This is some literal data";
    public final String filename_1 = "AFilename.dat";
    
    /* Literal packet data 2 */
    public final byte format_2 = 't';
    public final String rawdata_2 = "This is some more literal data...";
    public final String filename_2 = "AnotherFilename.dat";
    
    public final String outputfile1 = "TestSKESKP.pgp";
    public final String outputfile2 = "TestSKESKP_nosessionkey.pgp";
   
    
    /** Creates a new instance of TestSKESKP */
    public TestSKESKP() {
        setTestName("Test Symmetric Key Encrypted Session Key Packet"); // name of the test to be printed on the console.
    }
    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        TestSKESKP t = new TestSKESKP();
        
        t.printWelcome();
        
        t.doTest();
    }
    
    protected SessionKey generateSessionKey() throws Exception {
            
        KeyGenerator k = KeyGenerator.getInstance(SymmetricAlgorithmSettings.getCipherText(SymmetricAlgorithm), "BC");
        k.init(SecureRandom.getInstance("SHA1PRNG"));
        Key key = k.generateKey();

        return new SessionKey(SymmetricAlgorithm, key.getEncoded());   
        
    }
    
    protected byte[] generateSalt() throws Exception {
      
        byte salt[] = new byte[8];

        SecureRandom rng = SecureRandom.getInstance("SHA1PRNG");
        rng.nextBytes(salt);

        return salt;
       
    }
    
    protected SymmetricallyEncryptedDataPacket generateDataPacket() throws Exception {
        SymmetricallyEncryptedDataPacket sedp = new SymmetricallyEncryptedDataPacket();

        LiteralDataPacket p1 = new LiteralDataPacket(format_1, filename_1,  rawdata_1.getBytes());

        LiteralDataPacket p2 = new LiteralDataPacket(format_2, filename_2,  rawdata_2.getBytes());

        sedp.add(p1);
        sedp.add(p2);

        return sedp;
    }
    
    protected boolean compare(SymmetricallyEncryptedDataPacket packet) throws Exception {
        
        boolean result = true;
        
        System.out.println("  Comparing packet 1...");
            
        LiteralDataPacket lp1 = (LiteralDataPacket)packet.unpack(0);

        // format
        System.out.print("    Format... ");
        if (lp1.getFormat()==format_1) {
            // ok
            System.out.println("Ok");
        } else {
            // error
            System.out.print(lp1.getFormat());
            System.out.println("...Error!");
            result = false;
        }

        // Filename
        System.out.print("    Filename... ");
        if (lp1.getFilename().compareTo(filename_1)==0) {
            // ok
            System.out.println("Ok");
        } else {
            // error
            System.out.print(lp1.getFilename());
            System.out.println("Error!");
            result = false;
        }

        // data only
        System.out.print("    Data... ");
        if (new String(lp1.getData()).compareTo(rawdata_1)==0) {
            // ok
            System.out.println("Ok");
        } else {
            // error
            System.out.println("Error!");
            result = false;
        }

        // Date
        System.out.print("    Date is... ");
        System.out.println(new Date(lp1.getModDate()*1000).toString());


    // compare packet 2
    System.out.println("  Comparing packet 2...");

        LiteralDataPacket lp2 = (LiteralDataPacket)packet.unpack(1);

        // format
        System.out.print("    Format... ");
        if (lp2.getFormat()==format_2) {
            // ok
            System.out.println("Ok");
        } else {
            // error
            System.out.print(lp2.getFormat());
            System.out.println("...Error!");
            result = false;
        }

        // Filename
        System.out.print("    Filename... ");
        if (lp2.getFilename().compareTo(filename_2)==0) {
            // ok
            System.out.println("Ok");
        } else {
            // error
            System.out.print(lp2.getFilename());
            System.out.println("Error!");
            result = false;
        }

        // data only
        System.out.print("    Data... ");
        if (new String(lp2.getData()).compareTo(rawdata_2)==0) {
            // ok
            System.out.println("Ok");
        } else {
            // error
            System.out.println(new String(lp2.getData()));
            System.out.println("Error!");
            result = false;
        }

        // Date
        System.out.print("    Date is... ");
        System.out.println(new Date(lp2.getModDate()*1000).toString());
        
        return result;
    }
    
    /** <p>Execute the test.</p>
     * <p>You should implement this method with your test. Return true if the test
     * was successful, otherwise return false.</p>
     */
    public boolean test() throws Exception {
        boolean result = true;
        
        System.out.println("Adding Bouncy Castle JCE provider...");
        Security.addProvider(new BouncyCastleProvider());     
                   
        try { // test with session key
            System.out.println("Testing using a Session key...");

            // create session key
            System.out.println("  Generating a session key ("+SymmetricAlgorithmSettings.getCipherText(SymmetricAlgorithm)+")...");
            SessionKey sk1 = generateSessionKey();
            
            // generate a salt
            System.out.println("  Generating salt...");
            byte [] salt1 = generateSalt();
                
            // create symmetric key encrypted session key packet
            System.out.println("  Creating session key packet...");
            SymmetricKeyEncryptedSessionKeyPacket skeskp1 = new SymmetricKeyEncryptedSessionKeyPacket(passphrase.getBytes(), SymmetricAlgorithm, new S2K(hashalgorithm, salt1), sk1);
            
            // create data packet
            System.out.println("  Creating data packet...");
            SymmetricallyEncryptedDataPacket dp1 = generateDataPacket();
            dp1.encryptAndEncode(sk1);
            
            // save out
            System.out.println("  Saving packets to " + outputfile1 + "...");
            OpenPGPPacketOutputStream stream1 = new OpenPGPPacketOutputStream(new FileOutputStream(outputfile1));
            stream1.writePacket(skeskp1);
            stream1.writePacket(dp1);
            stream1.close();
            
            // reading packets in
            System.out.println("  Reading packets from " + outputfile1 + "...");
            OpenPGPPacketInputStream r_stream1 = new OpenPGPPacketInputStream(new FileInputStream(outputfile1));
            SymmetricKeyEncryptedSessionKeyPacket r_skeskp1 = (SymmetricKeyEncryptedSessionKeyPacket)r_stream1.readPacket();
            SymmetricallyEncryptedDataPacket r_dp1 = (SymmetricallyEncryptedDataPacket)r_stream1.readPacket();

            // extracting session key
            System.out.println("  Extracting session key...");
            SessionKey r_sk1 = r_skeskp1.getSessionKey(passphrase.getBytes());

            // decrypt data packet
            System.out.println("  Decrypting data packet...");
            r_dp1.decryptAndDecode(r_sk1);
            
            // compare
            if (compare(r_dp1)==false)
                result = false;
            
        } catch (Exception e) {
            System.out.println(e.getMessage());
            result = false;
        }
        
        try { // test with no session key
            System.out.println("Testing using a pass phrase...");

            // generate a salt
            System.out.println("  Generating salt...");
            byte [] salt2 = generateSalt();
            
            // create symmetric key encrypted session key packet
            System.out.println("  Creating session key packet...");
            SymmetricKeyEncryptedSessionKeyPacket skeskp2 = new SymmetricKeyEncryptedSessionKeyPacket(SymmetricAlgorithm, new S2K(hashalgorithm, salt2));
                        
            // create data packet
            System.out.println("  Creating data packet...");
            SymmetricallyEncryptedDataPacket dp2 = generateDataPacket();
            dp2.encryptAndEncode(skeskp2.getSessionKey(passphrase.getBytes()));
            
            // save out
            System.out.println("  Saving packets to " + outputfile2 + "...");
            OpenPGPPacketOutputStream stream2 = new OpenPGPPacketOutputStream(new FileOutputStream(outputfile2));
            stream2.writePacket(skeskp2);
            stream2.writePacket(dp2);
            stream2.close();
            
            // reading packets in
            System.out.println("  Reading packets from " + outputfile2 + "...");
            OpenPGPPacketInputStream r_stream2 = new OpenPGPPacketInputStream(new FileInputStream(outputfile2));
            SymmetricKeyEncryptedSessionKeyPacket r_skeskp2 = (SymmetricKeyEncryptedSessionKeyPacket)r_stream2.readPacket();
            SymmetricallyEncryptedDataPacket r_dp2 = (SymmetricallyEncryptedDataPacket)r_stream2.readPacket();

            // extracting session key
            System.out.println("  Extracting session key...");
            SessionKey r_sk2 = r_skeskp2.getSessionKey(passphrase.getBytes());

            // decrypt data packet
            System.out.println("  Decrypting data packet...");
            r_dp2.decryptAndDecode(r_sk2);
            
            // compare
            if (compare(r_dp2)==false)
                result = false;
            
        } catch (Exception e) {
            System.out.println(e.getMessage());
            result = false;
        }   
        
        // if we got this far then the test should have gone ok
        return result;
    }
    
}
