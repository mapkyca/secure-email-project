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

package ui;
import core.keyhandlers.*;
import core.keyhandlers.identifiers.*;
import core.keyhandlers.keydata.*;
import core.keyhandlers.parameters.*;
import core.algorithmhandlers.keymaterial.*;
import core.algorithmhandlers.openpgp.util.*;
import java.security.*;
import javax.swing.SwingUtilities;
import java.util.Date;


 
/**
 * <p>A simple dialog that displays a progress message while a new keyring is being generated...</p>
 */
public class KeyGenStatusDlg extends javax.swing.JDialog {
    
    /** A nested class that generates a new key on a separate thread. */
    public class KeyGenerator implements Runnable {
            private int symmetricAlg;
            private int dsa;
            private int pka;
            private byte [] name;
            private byte [] address;
            private byte [] passphrase;
            private KeyHandler pubkeyring;
            private KeyHandler seckeyring;

            private KeyData [] keys;
            private OpenPGPStandardKeyIdentifier uid[];
            private OpenPGPAddKeyParameters pubparam[];
            private OpenPGPAddSecretKeyParameters secparam[];
    
            public KeyGenerator(KeyHandler pubkeyring, KeyHandler seckeyring, int symmetricAlg, int dsa, int pka, byte [] name, byte [] address, byte [] passphrase) {
                this.symmetricAlg = symmetricAlg;
                this.dsa = dsa;
                this.pka = pka;
                this.name = name;
                this.address = address;
                this.passphrase = passphrase;
                this.pubkeyring = pubkeyring;
                this.seckeyring = seckeyring;
            }
            
            public void run() {
                try {
                    
                    Date now = new Date(); // make a note of the date and time in order to generate the correct key ID
                    
                    show();
                    setCursor(new java.awt.Cursor(java.awt.Cursor.WAIT_CURSOR));

                    setStatusText("Generating keys (this may take some time)...");
                    setIndeterminate(true);

                    // init
                    AsymmetricAlgorithmParameters [] keymaterial = new AsymmetricAlgorithmParameters[2];
                    keys = new KeyData[2];

                    uid = new OpenPGPStandardKeyIdentifier[2];
                    uid[0] = new OpenPGPStandardKeyIdentifier(name, address);

                    pubparam = new OpenPGPAddKeyParameters[2];
                    secparam = new OpenPGPAddSecretKeyParameters[2];

                    // generate signing key
                    if ((dsa == PublicKeyAlgorithmSettings.RSA_ENCRYPTSIGN) || (dsa == PublicKeyAlgorithmSettings.RSA_SIGN)) {
                        keymaterial[0] = new RSAAlgorithmParameters();
                        keymaterial[0].generateKeyPair(PublicKeyAlgorithmSettings.getDefaultKeySize(dsa), SecureRandom.getInstance("SHA1PRNG"));
                        keys[0] = new KeyData(keymaterial[0]);
                    } else if (dsa == PublicKeyAlgorithmSettings.DSA) {
                        keymaterial[0] = new DSAAlgorithmParameters();
                        keymaterial[0].generateKeyPair(PublicKeyAlgorithmSettings.getDefaultKeySize(dsa), SecureRandom.getInstance("SHA1PRNG"));
                        keys[0] = new KeyData(keymaterial[0]);
                    } else {
                        throw new Exception("Signature algorithm is not supported.");
                    }
                    
                    // generate pk key
                    if ((pka == PublicKeyAlgorithmSettings.RSA_ENCRYPTSIGN) || (pka == PublicKeyAlgorithmSettings.RSA_ENCRYPT)) {
                        keymaterial[1] = new RSAAlgorithmParameters();
                        keymaterial[1].generateKeyPair(PublicKeyAlgorithmSettings.getDefaultKeySize(pka), SecureRandom.getInstance("SHA1PRNG"));
                        keys[1] = new KeyData(keymaterial[1]);
                    } else {
                        throw new Exception("Encryption algorithm is not supported.");
                    }
                    
                    // save new keys
                    pubparam[0] = new OpenPGPAddKeyParameters(now, dsa, null);
                    secparam[0] = new OpenPGPAddSecretKeyParameters(now, dsa, null, passphrase, symmetricAlg, HashAlgorithmSettings.SHA1);
                    pubparam[1] = new OpenPGPAddKeyParameters(now, pka,null);
                    secparam[1] = new OpenPGPAddSecretKeyParameters(now, pka, null, passphrase, symmetricAlg, HashAlgorithmSettings.SHA1);
 
                    
                    setIndeterminate(false);
                    
                    setValue(50);
                    
                    setStatusText("Saving keys...");
                    pubkeyring.addKeys(keys, uid, pubparam);
                    setValue(75);
                    seckeyring.addKeys(keys, uid, secparam);
                    setValue(100);

                    setStatusText("Done");
                   
                    
                } catch (Exception e) {
                    setStatusText("Error!");
                    System.out.println(e.getMessage());
                    javax.swing.JOptionPane.showMessageDialog(null, e.getMessage(), "Problem", javax.swing.JOptionPane.ERROR_MESSAGE);
                }

                setCursor(new java.awt.Cursor(java.awt.Cursor.DEFAULT_CURSOR));
                hide();
            }
        }
    
    /** Creates new form OpenPGPKeyGenDlg */
    public KeyGenStatusDlg(java.awt.Frame parent, boolean modal) {
        super(parent, modal);
        initComponents();
    }
    
    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    private void initComponents() {//GEN-BEGIN:initComponents
        jPanel1 = new javax.swing.JPanel();
        jPanel2 = new javax.swing.JPanel();
        jProgressBar1 = new javax.swing.JProgressBar();
        jPanel3 = new javax.swing.JPanel();
        jLabel1 = new javax.swing.JLabel();

        setDefaultCloseOperation(javax.swing.WindowConstants.DO_NOTHING_ON_CLOSE);
        setTitle("Generating key...");
        setCursor(new java.awt.Cursor(java.awt.Cursor.DEFAULT_CURSOR));
        setResizable(false);
        addWindowListener(new java.awt.event.WindowAdapter() {
            public void windowClosing(java.awt.event.WindowEvent evt) {
                closeDialog(evt);
            }
        });

        jPanel1.setLayout(new java.awt.BorderLayout());

        jPanel1.setPreferredSize(new java.awt.Dimension(330, 100));
        jProgressBar1.setIndeterminate(true);
        jProgressBar1.setPreferredSize(new java.awt.Dimension(250, 14));
        jPanel2.add(jProgressBar1);

        jPanel1.add(jPanel2, java.awt.BorderLayout.SOUTH);

        jPanel3.add(jLabel1);

        jPanel1.add(jPanel3, java.awt.BorderLayout.CENTER);

        getContentPane().add(jPanel1, java.awt.BorderLayout.CENTER);

        pack();
        java.awt.Dimension screenSize = java.awt.Toolkit.getDefaultToolkit().getScreenSize();
        java.awt.Dimension dialogSize = getSize();
        setLocation((screenSize.width-dialogSize.width)/2,(screenSize.height-dialogSize.height)/2);
    }//GEN-END:initComponents
    
    /** Closes the dialog */
    private void closeDialog(java.awt.event.WindowEvent evt) {//GEN-FIRST:event_closeDialog
        setVisible(false);
        dispose();
    }//GEN-LAST:event_closeDialog
    
    public void setMaximum(int max) {
        jProgressBar1.setMaximum(max);
    }
    
    public void setMinimum(int min) {
        jProgressBar1.setMinimum(min);
    }
    
    public void setValue(int n) {
        jProgressBar1.setValue(n);
    }
    
    public void setIndeterminate(boolean newValue) {
        jProgressBar1.setIndeterminate(newValue);
    }
    
    public void setStatusText(String text) {
        jLabel1.setText(text);
    }

    public void generateOpenPGPKey(KeyHandler pubkeyring, KeyHandler seckeyring, int symmetricAlg, int dsa, int pka, byte [] name, byte [] address, byte [] passphrase) throws Exception {

        KeyGenerator r = new KeyGenerator(pubkeyring, seckeyring, symmetricAlg, dsa, pka, name, address, passphrase);
       
        Thread thread = new Thread(r);
        thread.start();
    }
    
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JPanel jPanel3;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JProgressBar jProgressBar1;
    private javax.swing.JLabel jLabel1;
    // End of variables declaration//GEN-END:variables

}

