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
 * <p>This test extracts a public key from a file, generates a public key encrypted session key packet using that public key and encrypts 
 * some literal data packets inside a data packet.</p>
 * <p>The resultant packet can be decoded using a ready made pgp program to test that the format is consistant with the pgp rfc.</p>
 */
public class TestSymmetricallyEncryptedDataPacket extends Test {
     
    /** Filenames. */
    public final String outputfile = "TestSymmetricallyEncryptedDataPacket.pgp";
    public final String publickeyfile = "test/testdata/IcewingPublicKey.packet";
    public final String publickeysigfile = "test/testdata/IcewingPublicKeySig.packet";
    
    /** Algorithm settings */
    public final int SymmetricAlgorithm = 1; // idea
    public final int PKAlgorithm = 1; // rsa enc & sign
    
    /* Literal packet data 1 */
    public final byte format_1 = 't';   
    public final String rawdata_1 = "This is some literal data";
    public final String filename_1 = "AFilename.dat";
    
    /* Literal packet data 2 */
    public final byte format_2 = 't';
    public final String rawdata_2 = "This is some more literal data...";
    public final String filename_2 = "AnotherFilename.dat";
    
    
    /** Creates a new instance of TestSymmetricallyEncryptedDataPacket */
    public TestSymmetricallyEncryptedDataPacket() {
        setTestName("Test SymmetricallyEncryptedDataPacket"); // name of the test to be printed on the console.
    }
    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        TestSymmetricallyEncryptedDataPacket t = new TestSymmetricallyEncryptedDataPacket();
        
        t.printWelcome();
        
        t.doTest();
    }
    
    /** <p>Execute the test.</p>
     * <p>You should implement this method with your test. Return true if the test
     * was successful, otherwise return false.</p>
     */
    public boolean test() throws Exception {
        boolean result = true;

        System.out.println("Adding Bouncy Castle JCE provider...");
        Security.addProvider(new BouncyCastleProvider());

        // Extract signature
        System.out.println("Extracting public key signature from "+publickeysigfile+"...");
            OpenPGPPacketInputStream sigin = new OpenPGPPacketInputStream(new FileInputStream(publickeysigfile));
            SignaturePacket sp = (SignaturePacket)sigin.readPacket();
            sigin.close();

        // decode public key and generate a public key object
        System.out.println("Extracting someone's public key from "+publickeyfile+"...");
            OpenPGPPacketInputStream tmpin = new OpenPGPPacketInputStream(new FileInputStream(publickeyfile));
            PublicKeyPacket pkp = (PublicKeyPacket)tmpin.readPacket();
            tmpin.close();

            RSAAlgorithmParameters keydata = (RSAAlgorithmParameters)pkp.getKeyData();

            RSAPublicKeySpec publickeyspec = new RSAPublicKeySpec(keydata.getN(), keydata.getE());
            KeyFactory keyFactory = KeyFactory.getInstance(PublicKeyAlgorithmSettings.getCipherText(PKAlgorithm));
            PublicKey publickey = keyFactory.generatePublic(publickeyspec);

            System.out.println("MOD: " + keydata.getN().toString(16));
            System.out.println("EXP: " + keydata.getE().toString(16));  
            System.out.println("BITLENGTH: " + keydata.getN().bitLength());
            System.out.println("CREATED: " + new Date(pkp.getCreateDate()*1000).toString());


        // create session key object
        System.out.println("Generating a session key ("+SymmetricAlgorithmSettings.getCipherText(SymmetricAlgorithm)+")...");
            KeyGenerator k = KeyGenerator.getInstance(SymmetricAlgorithmSettings.getCipherText(SymmetricAlgorithm), "BC");
            k.init(SecureRandom.getInstance("SHA1PRNG"));
            Key key = k.generateKey();

            SessionKey sk = new SessionKey(SymmetricAlgorithm, key.getEncoded());
            //System.out.println("SESSIONKEY: " + new String(sk.getSessionKey()));
            System.out.print("SESSIONKEY: ");
            byte [] skdat = sk.getSessionKey();
            for (int i = 0; i<skdat.length; i++) {
                //char d[] = new char[1];
                //d[0] = (char)(skdat[i] & 0xff);
                //System.out.print(new String(d));
                System.out.print(String.valueOf(skdat[i] & 0xff) + ",");
            }
            System.out.println();
            System.out.println("LENGTH: " + skdat.length);


        // create session key packet
        System.out.println("Creating new Public Key Encrypted Session Key Packet...");
            PublicKeyEncryptedSessionKeyPacket pkeskp = new PublicKeyEncryptedSessionKeyPacket(publickey,sp.getKeyID(),PKAlgorithm,sk);


        // Generate data packet
        System.out.println("Creating new Symmetrically Encrypted Data packet...");
            SymmetricallyEncryptedDataPacket sedp = new SymmetricallyEncryptedDataPacket();

            System.out.println("Creating and adding first literal packet...");
            LiteralDataPacket p1 = new LiteralDataPacket(format_1, filename_1,  rawdata_1.getBytes());

            System.out.println("Creating and adding second literal packet...");
            LiteralDataPacket p2 = new LiteralDataPacket(format_2, filename_2,  rawdata_2.getBytes());

            System.out.println("Adding packets...");
            sedp.add(p1);
            sedp.add(p2);

            System.out.println("Encrypting...");
            sedp.encryptAndEncode(sk);

        // write it out
        System.out.println("Writing packets to file...");
            System.out.println("  Opening packet stream to "+outputfile+"...");
            OpenPGPPacketOutputStream stream = new OpenPGPPacketOutputStream(new FileOutputStream(outputfile));

            System.out.println("  Writing sessionkey packet...");
            stream.writePacket(pkeskp);
            System.out.println("  Writing data packet...");
            stream.writePacket(sedp);

            System.out.println("  Closing stream...");
            stream.close();




        // read it in
        System.out.println("Reading packets from file...");
            System.out.println("  Opening packet stream to "+outputfile+"...");
            OpenPGPPacketInputStream instream = new OpenPGPPacketInputStream(new FileInputStream(outputfile));

            System.out.println("  Reading Session key packet (and discarding)...");
            PublicKeyEncryptedSessionKeyPacket r_skp = (PublicKeyEncryptedSessionKeyPacket)instream.readPacket();

            System.out.println("  Reading Data packet ...");
            SymmetricallyEncryptedDataPacket r_p = (SymmetricallyEncryptedDataPacket)instream.readPacket();

            System.out.println("  Closing stream...");
            instream.close();

        System.out.println("Decrypting...");
        r_p.decryptAndDecode(sk);

        // compare packet 1
        System.out.println("Comparing packet 1...");

            LiteralDataPacket lp1 = (LiteralDataPacket)r_p.unpack(0);

            // format
            System.out.print("  Format... ");
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
            System.out.print("  Filename... ");
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
            System.out.print("  Data... ");
            if (new String(lp1.getData()).compareTo(rawdata_1)==0) {
                // ok
                System.out.println("Ok");
            } else {
                // error
                System.out.println("Error!");
                result = false;
            }

            // Date
            System.out.print("  Date is... ");
            System.out.println(new Date(lp1.getModDate()*1000).toString());


        // compare packet 2
        System.out.println("Comparing packet 2...");

            LiteralDataPacket lp2 = (LiteralDataPacket)r_p.unpack(1);

            // format
            System.out.print("  Format... ");
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
            System.out.print("  Filename... ");
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
            System.out.print("  Data... ");
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
            System.out.print("  Date is... ");
            System.out.println(new Date(lp2.getModDate()*1000).toString());

        
        // if we got this far then the test should have gone ok
        return result;
    }
    
}
