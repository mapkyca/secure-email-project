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
import java.security.spec.RSAPublicKeySpec;

/**
 * <p>This test will attempt to verify a file signed by a third party application.</p>
 */
public class TestV3SignatureDecode extends Test {
    
    /* Filenames. */
    public final String sigfile = "test/testdata/TestMessage.dat.sig";
    public final String binfile = "test/testdata/TestMessage.dat";
    public final String secretkeyfile = "test/testdata/IcewingSecretKey_v4.packet";//"test/testdata/Test4Secring-sub.packet";//"test/testdata/IcewingSecretKey_v4.packet";
    
    /** Creates a new instance of TestV3SignatureDecode */
    public TestV3SignatureDecode() {
        setTestName("Test V3 Signature decode"); // name of the test to be printed on the console.
    }
    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        TestV3SignatureDecode t = new TestV3SignatureDecode();
        
        t.printWelcome();
        
        t.doTest();
    }
    
    /** <p>Execute the test.</p>
     * <p>You should implement this method with your test. Return true if the test
     * was successful, otherwise return false.</p>
     * @throws Exception if something went wrong.
     */
    public boolean test() throws Exception {
        boolean result = true;
        
        // generate and write demo packet.
        System.out.println("Adding Bouncy Castle JCE provider...");
        Security.addProvider(new BouncyCastleProvider());
        
        // Read in binary data
        System.out.println("Reading in binary file "+binfile+"...");
            FileInputStream binIn = new FileInputStream(binfile);
            byte data[] = new byte[binIn.available()];
            binIn.read(data);
            binIn.close();
        
        // read in signature
        System.out.println("Reading in signature file "+sigfile+"...");
            OpenPGPPacketInputStream sigIn = new OpenPGPPacketInputStream(new FileInputStream(sigfile));
            SignaturePacket sig = (SignaturePacket)sigIn.readPacket();
            sigIn.close();
            
        // output some debug info 
            debug.Debug.println(1,"Signature -------");
            debug.Debug.println(1,"Version : " + Integer.toString(sig.getVersion()));
            debug.Debug.println(1,"KeyID : ");
            debug.Debug.hexDump(1, sig.getKeyID());
            debug.Debug.println(1,"Signature material : ");
            debug.Debug.hexDump(1, sig.getSignatureData().getSignature());
            debug.Debug.println(1, "Length : " + Integer.toString(sig.getSignatureData().getSignature().length));
        
        // Read key info    
        System.out.println("Reading in key file "+secretkeyfile+"...");
            OpenPGPPacketInputStream keyIn = new OpenPGPPacketInputStream(new FileInputStream(secretkeyfile));
            SecretKeyPacket key = (SecretKeyPacket)keyIn.readPacket();
            keyIn.close();
        
        // decrypt key
        System.out.println("Decrypting secret key data...");
            byte [] pass = {'t','e','s','t'};
            key.decryptKeyData(pass);
        
        // output some debug info    
            RSAAlgorithmParameters keydata = (RSAAlgorithmParameters)key.getKeyData();

              
            debug.Debug.println(1,"Public ---------");
            debug.Debug.println(1,"MOD: "); debug.Debug.hexDump(1,keydata.getN().toByteArray());
            debug.Debug.println(1,"EXP: "); debug.Debug.hexDump(1,keydata.getE().toByteArray());  

            debug.Debug.println(1,"Private --------");
            debug.Debug.println(1,"EXP: "); debug.Debug.hexDump(1,keydata.getD().toByteArray()); 
                debug.Debug.println(1,"EXP Length: " + keydata.getD().bitLength()); 
            debug.Debug.println(1,"PRI: "); debug.Debug.hexDump(1,keydata.getP().toByteArray());
                debug.Debug.println(1,"PRI Length: " + keydata.getP().bitLength()); 
            debug.Debug.println(1,"PRI2: " ); debug.Debug.hexDump(1,keydata.getQ().toByteArray());
                debug.Debug.println(1,"PRI2 Length: " + keydata.getQ().bitLength()); 
            debug.Debug.println(1,"MUI: "); debug.Debug.hexDump(1,keydata.getU().toByteArray());
                debug.Debug.println(1,"MUI Length: " + keydata.getU().bitLength()); 

        // verify        
        System.out.print("Verifying...");  
            if (sig.verify(key.getKeyData().getPublicKey(), data)) {
                System.out.println("Ok.");
            } else {
                System.out.println("ERROR!");
                result = false;
            }
                
                
        return result;
    }
    
}
