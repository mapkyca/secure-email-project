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
import java.lang.Exception;

/**
 * <p>Root class for all tests.</p>
 * <p>This class defines a common test interface that can be called from other classes if desired, and provides 
 * useful utilities and a common way of reporting success or failure.</p>
 */
public abstract class Test {
    
    /** Version of the framework we are using. */
    private final String frameworkVersion = "1.1";
    /** The name of the test. */
    private String testName;
    
    /** Creates a new instance of Test */
    public Test() {
        
    }
    
    /** Prints a welcome message, version no and test name. */
    protected void printWelcome() {
        System.out.println();
        System.out.println("Email Proxy Test Framework v" + frameworkVersion);
        System.out.println("Oxford Brookes University Secure Email Project");  
        System.out.println("--- " + getTestName() + " ---");
    }
    
    /** Set the name of the test. */
    protected void setTestName(String name) {
        testName = name;
    }
    
    /** Return the name of the test. */
    public String getTestName() {
        return testName;
    }
    
    /** <p>Performs the test by calling test and prints a formatted result to the console.</p> */
    public void doTest() {
        debug.Debug.setLevel(1); // set default debug verbosity
        
        boolean result = false;
        
        try {
            result = test();
        } catch (Exception e) {
            result = false;
            
            System.err.println(e.getMessage());
            e.printStackTrace();
        }
        
        if (result) 
            System.out.println("<<< Test PASSED >>>");
        else {
            System.out.println("<<< Test FAILED >>>");
            Runtime.getRuntime().exit(-1); // force exit on error
        }
    }
    
    /** <p>Execute the test.</p>
     * <p>You should implement this method with your test. Return true if the test
     * was successful, otherwise return false.</p>
     * @throws Exception if something went wrong.
     */
    public abstract boolean test() throws Exception;
    
}
