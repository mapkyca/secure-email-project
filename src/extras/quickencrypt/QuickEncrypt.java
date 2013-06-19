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

package extras.quickencrypt;
import extras.websitemailer.DummyHandler;
import java.util.Date;
import java.io.*;
import java.util.Properties;
import core.*;
import core.interfaces.*;
import core.keyhandlers.*;
import core.keyhandlers.identifiers.*;
import core.algorithmhandlers.*;
import core.email.*;
import core.iptp.*;
import core.exceptions.*;
import core.protocolhandlers.*;
import core.algorithmhandlers.openpgp.util.*;
import system.*;

/**
 * <p>A quick encryption utility.</p>
 * <p>This is a very quick method that encrypts some data to a given public key id. It takes raw text
 * in standard in and produces an ascii armored encrypted message to stdout.</p>
 * <p>I wrote this for myself, but I figured someone else might find some use for it...</p>
 * <p><b>Config options are:</b></p>
 * <ul>
 *      <li><b>keymanager.openpgp.publiclist.<n>. :</b> A list of public key sources (see the config file options for the email proxy for the format of this).</li>
 *      <li><b>recipient.address:</b> Email address of the recipient</li>
 *      <li><b>recipient.name:</b> The recipient's name.</li>
 *      <li><b>mailserver.address:</b> Address of the SMTP server (same as in key ID).</li>
 *      <li><b>mailserver.port:</b> Port to connect to (same as key ID).</li>
 * </ul>
 *
 * <p><b>Command options are:</b></p>
 * <ul>
 *      <li><b>-f</b>: Specify the location of the config file.</li>
 *      <li><b>-F</b>: From name.</li>
 *      <li><b>-A</b>: From address.</li>
 * </ul>
 */
public class QuickEncrypt {
    
    private String recipientAddress;
    private OpenPGPStandardKeyIdentifier id;
    private int port;
    private String server;
    
    /** Creates a new instance of QuickEncrypt */
    public QuickEncrypt(String configFile, String fromname, String address) {
        try {
            
            // load configuration
            ConfigurationData config = new ConfigurationData(configFile);
            server = config.getSetting("mailserver.address", "localhost");
            port = Integer.parseInt(config.getSetting("mailserver.port", "25"));
            recipientAddress = config.getSetting("recipient.address", "");
                if (recipientAddress.compareTo("")==0) throw new Exception("You must specify a recipient address");
            String recipientName = config.getSetting("recipient.name", "");
                if (recipientName.compareTo("")==0) throw new Exception("You must specify a recipient name");
            
            id = new OpenPGPStandardKeyIdentifier(recipientName.getBytes(), recipientAddress.getBytes());
            
            // load key sources
            KeyHandler [] publicKeyManagers = KeyHandler.loadKeysourceList(config, "keymanager.openpgp.publiclist.");   
            KeyHandler [] secretKeyManagers = new KeyHandler[0];
            
            // read std in and parse POST variables
            BufferedReader in = new BufferedReader(new InputStreamReader(System.in));;
            StringBuffer message = new StringBuffer();
            String tmp = null;
            do {
                 tmp = in.readLine(); // read in variable list
                 if (tmp!=null) { 
                    message.append(tmp); 
                    message.append("\r\n");
                 }
            } while (tmp!=null);
            in.close();
            
            
            // construct dummy email
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.write(new String("From: \"" + fromname + "\" <"+ address +">\r\n").getBytes());
            out.write(new String("To: " + new String(id.getDefaultID()) + "\r\n").getBytes());
            out.write(new String("Content-Type: text/plain;\r\n\tcharset=\"iso-8859-1\"\r\n").getBytes());
            out.write(new String("Content-Transfer-Encoding: 7bit\r\n").getBytes());
            out.write(new String("\r\n").getBytes());
            out.write(message.toString().getBytes());
            out.write(new String("\r\n").getBytes());

            Email email = new Email(out.toByteArray());
             
            
            // encrypt mail
            OpenPGPHandler handler = new OpenPGPHandler(SymmetricAlgorithmSettings.IDEA); // use IDEA 
            email = handler.processOutgoingMail(true, false, publicKeyManagers, secretKeyManagers, email, null);
            
            
            // return data
            System.out.println(new String(email.getBody()));
            
        } catch (Exception e) {
            System.out.println(e.getMessage());
            e.printStackTrace(System.out);
        }
    }
    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        // load config file
        String configFile = "cgimailer.dat"; // default config file
        String from = "";
        String address = "";
        boolean quiet = false;
        
        for (int n = 0; n < args.length; n++) {
            if (args[n].compareTo("-f")==0) {
                if (n+1 < args.length)
                    configFile = args[n+1];
            }
            
            if (args[n].compareTo("-F")==0) {
                if (n+1 < args.length)
                    from = args[n+1];
            }
            
            if (args[n].compareTo("-A")==0) {
                if (n+1 < args.length)
                    address = args[n+1];
            }
        }

        QuickEncrypt c = new QuickEncrypt(configFile, from, address);
    }
    
}
