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

package extras.websitemailer;
import java.util.Date;
import java.io.*;
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

/**
 * <p>This is the main applet class for the OpenPGP Website Mailer.</p>
 * <p>It serves as a demo of a possible application for the source code.</p>
 * <p>To use you must install the bouncy castle JCE in the jvm's java.security file by adding the following
 * line "security.provider.<n>=org.bouncycastle.jce.provider.BouncyCastleProvider", where <n> is the priority 
 * you want to give the provider (just put it after the other ones).</p>
 * <p>Note, this code is only here for an example... it probably shouldn't be used on
 * a live system.</p>
 * <p><b>Parameters supported by the applet are :</b></p>
 * <table width="90%" border="1" cellspacing="1" cellpadding="2">
 *   <tr> 
 *     <th>Parameter</th>
 *     <th>Default</th>
 *     <th>Description</th>
 *   </tr>
 *   <tr valign="top"> 
 *     <td><font face="Courier New, Courier, mono">port</font></td>
 *     <td><font face="Courier New, Courier, mono">25</font></td>
 *     <td>The port the SMTP server listens on. Note, due to applet security restrictions 
 *       the applet will connect to &quot;localhost&quot; to look for the mailserver.</td>
 *   </tr>
 *   <tr valign="top"> 
 *     <td><font face="Courier New, Courier, mono">server</font></td>
 *     <td><font face="Courier New, Courier, mono"></font></td>
 *     <td>The address of the mailserver. Note, due to applet security this MUST be the same as the website server.</td>
 *   </tr>
 *   <tr valign="top"> 
 *     <td><font face="Courier New, Courier, mono">publickeyfileurl</font></td>
 *     <td><font face="Courier New, Courier, mono"></font></td>
 *     <td>The full path and filename on the server of the file containing the public 
 *       key in URL form. </td>
 *   </tr>
 *   <tr valign="top"> 
 *     <td><font face="Courier New, Courier, mono">keyidname</font></td>
 *     <td><font face="Courier New, Courier, mono"></font></td>
 *     <td>The name portion of the key ID</td>
 *   </tr>
 *   <tr valign="top"> 
 *     <td><font face="Courier New, Courier, mono">keyidaddress</font></td>
 *     <td><font face="Courier New, Courier, mono"></font></td>
 *     <td>The address portion of the key ID if different from &quot;address&quot;. 
 *       Mandatory, and must be the recipient's email address.</td>
 *   </tr>
 * </table>
 * @see <a href="doc-files/example.html">Example of how to use the applet.</a>
 */
public class OpenPGPWebsiteMailer extends javax.swing.JApplet {
    
    /** Version of the applet.*/
    public static final String version = "1.0";
    
    
    private String recipientAddress;
    private OpenPGPPublicKeyring publicFile;
    private OpenPGPStandardKeyIdentifier id;
    private int port;
    private String server;
    
        
    /** Creates new form OpenPGPWebsiteMailer */
    public OpenPGPWebsiteMailer() {
        initComponents();
    }
    
    public void init() {
        try {
            // load settings
            recipientAddress = getParameter("address");
            server = getParameter("server");
            String serverPort = getParameter("port");
            String keyIDName = getParameter("keyidname");
            String keyIDaddress = getParameter("keyidaddress");
            String keyfile = getParameter("publickeyfileurl");
                   
            if (keyIDName == null) throw new Exception("You must specify a key ID.");
            if (keyIDaddress == null) throw new Exception("You must specify a key ID address.");
            if (serverPort == null) serverPort = "25";
            if (server == null) throw new Exception("You must specify a server address.");
            if (keyfile==null) throw new Exception("You must specify the full URL of the public key file.");

            port = Integer.parseInt(serverPort);
            publicFile = new OpenPGPPublicKeyringURLReader(keyfile, null);
            id = new OpenPGPStandardKeyIdentifier(keyIDName.getBytes(), keyIDaddress.getBytes());
            
        } catch (Exception e) {
            println(e.getMessage());
        }
    }
    
    
    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    private void initComponents() {//GEN-BEGIN:initComponents
        jPanel1 = new javax.swing.JPanel();
        sendButton = new javax.swing.JButton();
        clearButton = new javax.swing.JButton();
        jPanel2 = new javax.swing.JPanel();
        jPanel4 = new javax.swing.JPanel();
        jPanel5 = new javax.swing.JPanel();
        jLabel2 = new javax.swing.JLabel();
        website = new javax.swing.JTextField();
        jPanel6 = new javax.swing.JPanel();
        jLabel1 = new javax.swing.JLabel();
        from = new javax.swing.JTextField();
        jLabel4 = new javax.swing.JLabel();
        emailAddy = new javax.swing.JTextField();
        jPanel7 = new javax.swing.JPanel();
        jLabel3 = new javax.swing.JLabel();
        subject = new javax.swing.JTextField();
        jScrollPane2 = new javax.swing.JScrollPane();
        emailBody = new javax.swing.JTextArea();
        jScrollPane1 = new javax.swing.JScrollPane();
        status = new javax.swing.JTextArea();

        setName("OpenPGP Website Mailer v" + version);
        sendButton.setMnemonic('s');
        sendButton.setText("Send email!");
        sendButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                sendButtonActionPerformed(evt);
            }
        });

        jPanel1.add(sendButton);

        clearButton.setMnemonic('c');
        clearButton.setText("Clear");
        clearButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                clearButtonActionPerformed(evt);
            }
        });

        jPanel1.add(clearButton);

        getContentPane().add(jPanel1, java.awt.BorderLayout.SOUTH);

        jPanel2.setPreferredSize(new java.awt.Dimension(500, 450));
        jPanel4.setLayout(new java.awt.BorderLayout());

        jLabel2.setText("Website : ");
        jPanel5.add(jLabel2);

        website.setColumns(33);
        website.setText("http://");
        jPanel5.add(website);

        jPanel4.add(jPanel5, java.awt.BorderLayout.CENTER);

        jLabel1.setText("Name :");
        jLabel1.setToolTipText("null");
        jPanel6.add(jLabel1);

        from.setColumns(10);
        jPanel6.add(from);

        jLabel4.setText("Email :");
        jPanel6.add(jLabel4);

        emailAddy.setColumns(20);
        jPanel6.add(emailAddy);

        jPanel4.add(jPanel6, java.awt.BorderLayout.NORTH);

        jLabel3.setText("Subject : ");
        jPanel7.add(jLabel3);

        subject.setColumns(33);
        jPanel7.add(subject);

        jPanel4.add(jPanel7, java.awt.BorderLayout.SOUTH);

        jPanel2.add(jPanel4);

        jScrollPane2.setViewportBorder(new javax.swing.border.TitledBorder("Message"));
        emailBody.setColumns(40);
        emailBody.setLineWrap(true);
        emailBody.setRows(15);
        jScrollPane2.setViewportView(emailBody);

        jPanel2.add(jScrollPane2);

        jScrollPane1.setHorizontalScrollBarPolicy(javax.swing.JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        status.setColumns(40);
        status.setEditable(false);
        status.setRows(3);
        jScrollPane1.setViewportView(status);

        jPanel2.add(jScrollPane1);

        getContentPane().add(jPanel2, java.awt.BorderLayout.CENTER);

    }//GEN-END:initComponents

    private void sendButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_sendButtonActionPerformed
        // Add your handling code here:

        try {
            // send an email

            // create email
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.write(new String("From: \"" + from.getText() + "\" <"+ emailAddy.getText() +">\r\n").getBytes());
            out.write(new String("To: " + new String(id.getDefaultID()) + "\r\n").getBytes());
            out.write(new String("Subject: " + subject.getText() + "\r\n").getBytes());
            out.write(new String("Date: " + new Date().toString() + "\r\n").getBytes());
            out.write(new String("Content-Type: text/plain;\r\n\tcharset=\"iso-8859-1\"\r\n").getBytes());
            out.write(new String("Content-Transfer-Encoding: 7bit\r\n").getBytes());
            out.write(new String("X-Mailer: OpenPGPWebsiteMailer v" + version + "\r\n").getBytes());
            out.write(new String("X-Senders-Website: " + website.getText() + "\r\n").getBytes());
            out.write(new String("\r\n").getBytes());
            out.write(new String(emailBody.getText() + "\r\n").getBytes());
            out.write(new String("\r\n").getBytes());

            Email email = new Email(out.toByteArray());
  
            
            // create pipe
            KeyHandler [] publicKeyManagers = new KeyHandler[1];
            KeyHandler [] secretKeyManagers = new KeyHandler[0];
            publicKeyManagers[0] = (KeyHandler)publicFile;
           
            SMTPHandler smtp = new SMTPHandler();
            smtp.initClientConnection(server,  port);
              
            DummyHandler dh = new DummyHandler(email);  
            OpenPGPHandler handler = new OpenPGPHandler(SymmetricAlgorithmSettings.IDEA); // use IDEA  

            WebsiteMailerEmailPipe pipe = new WebsiteMailerEmailPipe(
                dh, 
                handler, 
                secretKeyManagers,
                publicKeyManagers, 
                smtp               
            );    
            
            pipe.start();
          
        } catch (Exception e) {
            println(e.getMessage());
        }
    }//GEN-LAST:event_sendButtonActionPerformed

    private void clearButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_clearButtonActionPerformed
        // Add your handling code here:
        clearForm();
        clearStatus(); 
    }//GEN-LAST:event_clearButtonActionPerformed

    public void clearForm() {
        from.setText(null);
        emailAddy.setText(null);
        website.setText("http://");
        subject.setText(null);
        emailBody.setText(null);
    }
        
    public void clearStatus() {
        status.setText(null);
    }
    
    /** 
     * Append text to the output
     */
    public void println(String text) {
        status.append(text+"\n");
        jScrollPane1.getVerticalScrollBar().setValue(status.getHeight() - status.getVisibleRect().height );
    }    
    
    
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JPanel jPanel7;
    private javax.swing.JPanel jPanel6;
    private javax.swing.JPanel jPanel5;
    private javax.swing.JPanel jPanel4;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JTextField emailAddy;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JTextArea status;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JTextField subject;
    private javax.swing.JTextField from;
    private javax.swing.JButton clearButton;
    private javax.swing.JTextArea emailBody;
    private javax.swing.JTextField website;
    private javax.swing.JButton sendButton;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel1;
    // End of variables declaration//GEN-END:variables

    /** <p>Override of Outgoing email pipe to handle this special case.</p>
     * <p>Could probably be written better with a more intelligent use of inheritance, but this is just a 
     * demo so I'm not going to bother. </p>
     */
    public class WebsiteMailerEmailPipe extends OutgoingEmailPipe {
        
        /**
         * <p>Outgoing email pipe constructor. </p>
         * @throws ProxyServerCoreException if either protocolServerHandler or protocolClientHandler are null.
         */
        public WebsiteMailerEmailPipe(SendPipeServerInterface protocolServerHandler,
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
            println(status);
        }

        /** Print a nice error message to the console and display a popup message. */
        protected void printErr(String status) {
            println(status);
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
                
                
                clearForm(); // clear the applet form if the mail was sent with no error
                
            } catch (Exception e) {
                printErr(e.getMessage());
            }
            
            stopPipe(); // halt the pipe
            System.gc();
        }
        
        /** <p>Stop the pipe.</p>
         * <p>Stops the email pipe. </p>
         * <p>When stopping the protocolServer object stopPipe will handle any exception generated as a result of the socket
         * being in an accept state.<p>
         *
         */
        public void stopPipe() {
            try {
                if (protocolClient!=null)
                    protocolClient.disconnectFromServer();
            }
            catch (ProxyServerCoreException e) {
                printErr(e.getMessage());
            }
        }   

    }
    
}
