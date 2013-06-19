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

package extras.cgimailer;
import extras.websitemailer.DummyHandler;
import java.util.Date;
import java.io.*;
import java.util.Properties;
import java.net.URLDecoder;
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
 * <p>An appliation that performs a simular function to the websitemailer applet, only using CGI instead of applet technology.</p>
 * <p>Variables are passed using POST.</p>
 * <p><b>POST variables are:</b></p>
 * <ul>
 *      <li><b>subject :</b> The subject of the message.</li>
 *      <li><b>message :</b> The body of the message.</li>
 *      <li><b>name :</b> Who sent the message.</li>
 *      <li><b>address :</b> Their address.</li>
 * </ul>
 * <p>There are also a number of things loaded from the config file (default, cgimailer.dat - use the "-f" switch to change).</p>
 * <p><b>Config options are:</b></p>
 * <ul>
 *      <li><b>keymanager.openpgp.publiclist.<n>. :</b> A list of public key sources (see the config file options for the email proxy for the format of this).</li>
 *      <li><b>recipient.address:</b> Email address of the recipient</li>
 *      <li><b>recipient.name:</b> The recipient's name.</li>
 *      <li><b>mailserver.address:</b> Address of the SMTP server (same as in key ID).</li>
 *      <li><b>mailserver.port:</b> Port to connect to (same as key ID).</li>
 * </ul>
 * 
 * <p>TODO: Need to URL decode the messages.</p>
 */
public class CGIMailer {
    
    /** Version of the mailer.*/
    public static final String version = "1.0";
    
    private String recipientAddress;
    private OpenPGPStandardKeyIdentifier id;
    private int port;
    private String server;
    
    boolean quiet = false;
    

    /** Creates a new instance of CGIMailer */ 
    public CGIMailer() {
    }
    
    /** Creates a new instance of CGIMailer */ 
    public CGIMailer(String configFile, boolean quiet) {
        
        this.quiet = quiet;
        
        // write CGI content type junk
        System.out.println("Content-type: text/html\r\n\r\n");

         
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
            
            // read std in and parse POST variables
            BufferedReader in = new BufferedReader(new InputStreamReader(System.in));;
            String vars = in.readLine(); // read in variable list
                    
            vars = vars.replaceAll("&", "\r\n"); // replace all & chars with \r\n to make the data compatible with Properties
            
            Properties postVariables = new Properties();
            postVariables.load(new ByteArrayInputStream(vars.getBytes()));

            
            // construct email
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.write(new String("From: \"" + URLDecoder.decode(postVariables.getProperty("name",""), "UTF-8") + "\" <"+ URLDecoder.decode(postVariables.getProperty("address",""), "UTF-8") +">\r\n").getBytes());
            out.write(new String("To: " + new String(id.getDefaultID()) + "\r\n").getBytes());
            out.write(new String("Subject: " + URLDecoder.decode(postVariables.getProperty("subject",""), "UTF-8") + "\r\n").getBytes());
            out.write(new String("Date: " + new Date().toString() + "\r\n").getBytes());
            out.write(new String("Content-Type: text/plain;\r\n\tcharset=\"iso-8859-1\"\r\n").getBytes());
            out.write(new String("Content-Transfer-Encoding: 7bit\r\n").getBytes());
            out.write(new String("X-Mailer: CGIMailer v" + version + "\r\n").getBytes());
            out.write(new String("\r\n").getBytes());
            out.write(new String(URLDecoder.decode(postVariables.getProperty("message",""), "UTF-8") + "\r\n").getBytes());
            out.write(new String("\r\n").getBytes());

            Email email = new Email(out.toByteArray());
         
            // send email
            KeyHandler [] secretKeyManagers = new KeyHandler[0];
            
            SMTPHandler smtp = new SMTPHandler();
            smtp.initClientConnection(server,  port);
              
            DummyHandler dh = new DummyHandler(email);  
            OpenPGPHandler handler = new OpenPGPHandler(SymmetricAlgorithmSettings.IDEA); // use IDEA  

            CGIMailerEmailPipe pipe = new CGIMailerEmailPipe(
                dh, 
                handler, 
                secretKeyManagers,
                publicKeyManagers, 
                smtp               
            );    
            
            pipe.run();
            
        } catch (Exception e) {
            if (!quiet)
                System.out.println("<p>" + e.getMessage() + "</p>");
        }
        
    }
    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        
        // load config file
        String configFile = "cgimailer.dat"; // default config file
        boolean quiet = false;
        
        for (int n = 0; n < args.length; n++) {
            if (args[n].compareToIgnoreCase("-f")==0) {
                if (n+1 < args.length)
                    configFile = args[n+1];
            }
            
            if (args[n].compareToIgnoreCase("/quiet")==0) {
                quiet = true;
            }
        }

        CGIMailer c = new CGIMailer(configFile, quiet);
    }
    
    
    
    /** <p>Override of Outgoing email pipe to handle this special case.</p>
     * <p>Could probably be written better with a more intelligent use of inheritance, but this is just a 
     * demo so I'm not going to bother. </p>
     */
    public class CGIMailerEmailPipe extends OutgoingEmailPipe {
        
        /**
         * <p>Outgoing email pipe constructor. </p>
         * @throws ProxyServerCoreException if either protocolServerHandler or protocolClientHandler are null.
         */
        public CGIMailerEmailPipe(SendPipeServerInterface protocolServerHandler,
                                 AlgorithmHandler algorithmHandler,
                                 KeyHandler secKeyHandlers[],
                                 KeyHandler pubKeyHandlers[],
                                 SendPipeClientInterface protocolClientHandler
                                 ) throws ProxyServerCoreException {
                                       
                                     super(protocolServerHandler, 
                                        algorithmHandler, 
                                        secKeyHandlers,
                                        pubKeyHandlers, 
                                        protocolClientHandler, 
                                        true, 
                                        false);
                                       
                                     setPipeStatusPrefix("Website Mailer");
                                     
        }
        
        /** Print a nice status message to the console. */
        protected void printStatus(String status) {
            if (!quiet)
                System.out.println("<p>" + getPipeStatusPrefix() + ": " + status + "</p>");
        }
        
        /** Print a nice error message to the console and display a popup message. */
        protected void printErr(String status) {
            printStatus(status);
        }
        
        /** Principal run loop, except that it only runs once. */
        public void run() {
            try {
                
                // Create an email object
                Email email = null;
                EmailEnvelope envelope = null;
                boolean decoupled = false;
                
                // Connection accepted, try and connect to mail server
                printStatus("Connecting to Email server...");
                protocolClient.connect();
                
                if (protocolClient.isConnectedToServer()) {
                    
                    printStatus("Processing commands...");
                    
                    while (protocolClient.isConnectedToServer()) {
                    
                        IPTPCommand outgoing = null;
                        IPTPCommandResponse incoming = null;

                        // await response from server
                        if (!decoupled) {
                            incoming = protocolClient.awaitCommandResponse();

                            // analyse response

                            // test for quit
                            if (incoming instanceof IPTPQuitResponse) {
                                protocolServer.sendCommandResponse(incoming);
                                protocolServer.disconnectFromClient();
                                protocolClient.disconnectFromServer();
                                break;
                            }

                            if (!incoming.isOk()){
                                printErr(incoming.getClass().toString());
                               printErr("Mail server reported an error, will try and continue.");
                            }
                        
                            // send response to email client
                            protocolServer.sendCommandResponse(incoming);
                        }

                        // await command
                        outgoing = protocolServer.awaitCommand();

                        // analyse command, send command to email server
                        if (outgoing instanceof IPTPMail) {
                            // Mail capture begin .. transaction is decoupled and all command responses are faked.
                            decoupled = true;

                            printStatus("Capturing outgoing email...");

                            IPTPMail mailcommand = (IPTPMail)outgoing;

                            // Create an envelope
                            envelope = new EmailEnvelope();
                            envelope.setSender(mailcommand.getSender());

                            // acknowledge
                            protocolServer.sendCommandResponse(new IPTPMailResponse(true));
                        }
                        else if (outgoing instanceof IPTPRcpt) {
                            // Add a recipient
                            decoupled = true;
                            printStatus("Adding recipient...");

                            IPTPRcpt rcpt = (IPTPRcpt)outgoing;

                            envelope.addRecipient(rcpt.getRecipient());

                            // acknowledge
                            protocolServer.sendCommandResponse(new IPTPRcptResponse(true));
                        }
                        else if (outgoing instanceof IPTPData) {
                            // Client requested to send an email
                            decoupled = true;
                            printStatus("Processing email...");

                            // acknowledge and begin mail transfer
                            protocolServer.sendCommandResponse(new IPTPDataResponse(true));

                            // await data
                            printStatus("Receiving email from client...");
                            IPTPCommand data = protocolServer.awaitCommand();

                            if (data instanceof IPTPSendData) {
                                // construct email
                                IPTPSendData tmp = (IPTPSendData)data;
                                email = new Email(tmp.getMessageData().getBytes());
                                envelope.wrapEmail(email);

                                // do encryption / signing
                                if (algorithm!=null) {

                                    printStatus("Encrypting/Signing email...");
                                    email = algorithm.processOutgoingMail(true, false, publicKeyHandlers, secretKeyHandlers, email, passPhrases);

                                }

                                // Send email to mail server
                                    printStatus("Sending email to server...");

                                    // initiate transfer
                                    protocolClient.sendCommand(new IPTPMail(envelope.getSender()));
                                    if (!protocolClient.awaitCommandResponse().isOk())
                                        throw new ProxyServerCoreException("Mail server did not accept sender.");

                                    // recipients
                                    for (int n = 0; n < envelope.getNumberOfRecipients(); n++) {
                                        protocolClient.sendCommand(new IPTPRcpt(envelope.getRecipient(n)));
                                        if (!protocolClient.awaitCommandResponse().isOk())
                                            throw new ProxyServerCoreException("Mail server did not accept recipient.");
                                    }

                                    // data
                                    protocolClient.sendCommand(new IPTPData());
                                    if (!protocolClient.awaitCommandResponse().isOk())
                                        throw new ProxyServerCoreException("Mail server did not accept data send request.");

                                    // send data
                                    protocolClient.sendCommand(new IPTPSendData(new String(email.getBytes())));
                                    if (!protocolClient.awaitCommandResponse().isOk())
                                        throw new ProxyServerCoreException("Mail server did not accept email.");

                                // return final ok (if we got this far then we should be ok)
                                protocolServer.sendCommandResponse(new IPTPSendDataResponse(true));
                                printStatus("Email successfully sent to mail server.");

                            }
                        } else {
                            // anything other than certain commands recouple the server
                            decoupled = false;
                           
                            // send command to server
                            protocolClient.sendCommand(outgoing);
                        }
                    }
                    
                } else {
                    throw new PipeCommunicationException("Unable to connect to mail server on port " + port + "...");
                }

            } catch (Exception e) {
                System.out.println("<pre>");
                e.printStackTrace(System.out);
                System.out.println("</pre>");
                printErr(e.getMessage());
            }
            
            stopPipe(); // halt the pipe
            System.gc();
        }

    }
}
