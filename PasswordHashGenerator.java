//******************************************************************************
//
// File:    PasswordHashGenerator.java
// Package: ---
// Unit:    Class PasswordHashGenerator
// 
// The snippet of code for hashing the password was taken from the example snippets on the course website
// 
// Author: Marko Galesic
//******************************************************************************


import java.security.*;
import java.io.*;
import edu.rit.util.Hex;
import java.util.*;
/*
 * Objects of this class compute password hash of a password in a dictionary then returns that value
 * to a HashMap value
 * 
 * @author Marko Galesic
 */
public class PasswordHashGenerator implements Runnable
{
	// Hidden member variables
	private String password;
	private HashMap<String, SynchronizedPlaintextPassword> passwordHashMap;

	/**
	 * Constructor for PasswordHashGenerator class takes a dictionary and a database for lookup
	 *
	 * @param password   plaintext password to hash
	 * @param passwordHashMap   reference to a record keeper to poll when hash is ready
	 */
	public PasswordHashGenerator(String password, HashMap<String, SynchronizedPlaintextPassword> passwordHashMap)
	{
		this.password = password;
		this.passwordHashMap = passwordHashMap;
	}

	/*
         * Creates a hash from a password by running SHA-256 on it 100K times
	 *
	 * @param password plaintext password to hash
	 * @return hashed password as a String
	 */
	public static String hashPassword(String password)
	{
		MessageDigest md = null;
		
		try
		{
			md = MessageDigest.getInstance("SHA-256");
		}
		catch(NoSuchAlgorithmException e)
		{
			System.err.println("SHA-256 was not found.");
		}

		byte[] data = null;
		
		try
		{
			data = password.getBytes("UTF-8");
		}
		catch(UnsupportedEncodingException e)
		{
			System.err.println("UTF-8 is unsupported.");
		}
		
		// Hash 100K times
		for(int i = 0; i < 100000; i++)
		{
			md.update(data);
			data = md.digest();
		}

		String hex = Hex.toString(data);
		return hex;
	}

	/**
	 * Hash plaintext password then ask the record keeper for the object where the plaintext
	 * password should be stored - finally store the plaintext password in that object
	 */
	@Override
	public void run()
	{
		SynchronizedPlaintextPassword plaintextPassword;
		String passwordHash = hashPassword(password);
		synchronized(passwordHashMap)
		{
			// Get the synchronized object where we will store the plaintext password
			plaintextPassword = passwordHashMap.get(passwordHash);	
		}
		
		if (plaintextPassword != null)
		{		
			plaintextPassword.set(password); // Set the password
		}
	}
}
