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

/**
 * <p>A class encapsulating the return value of EnterPassphraseDlg.</p>
 */
public class PassphraseDlgReturnValue {
    
    /** Abort button pressed. */
    public static final int ABORT = 1;
    /** Send anyway pressed. */
    public static final int SENDANYWAY = 2;
    /** Ok pressed. */
    public static final int OK = 3;
    
    /** Which button is pressed. */
    private int buttonPressed;
    
    /** The passphrase entered. */
    private byte [] passPhrase;
    
    /** Creates a new instance of PassphraseDlgReturnValue */
    public PassphraseDlgReturnValue(int buttonpressed, byte [] passphrase) {
        buttonPressed = buttonpressed;
        passPhrase = passphrase;
    }
    
    /** Return the button pressed. */
    public int getButtonPressed() {
        return buttonPressed;
    }
    
    /** Return the passphrase entered. */
    public byte [] getPassphrase() {
        return passPhrase;
    }
}
