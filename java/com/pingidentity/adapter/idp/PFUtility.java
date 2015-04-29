package com.pingidentity.adapter.idp;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import javax.naming.ServiceUnavailableException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.phonefactor.pfsdk.*;
import java.util.regex.Pattern;

public class PFUtility {
    
    public static Logger logger = LoggerFactory.getLogger(PFUtility.class);
    public static PFAuth pf = null;
        
    public static String configDirectory = null;
    public static String certificatePassword = null;
    
    public PFUtility(String _configDirectory, String _certificatePassword) {
    	PFUtility.configDirectory = _configDirectory;
    	PFUtility.certificatePassword = _certificatePassword;
    }
    
    public static boolean Call(String user, String country, String number) throws PFException {
    	    	
    	pf = new PFAuth();

		/* Initialize the object by pointing it to the directory where
		 * our license, cert, and private key reside.  We also have to provide
		 * the password for the encrypted private key.  This can be an empty
		 * string -- the decision to use an encrypted key and find a way to 
		 * securely get the password here is your call.  It is obviously 
		 * superior to use a non blank password, but either method is supported.
		 */
    	
    	if (configDirectory == null || certificatePassword == null)
    		throw new PFException("PhoneFactor not initialised");
    	
		pf.initialize(PFUtility.configDirectory, PFUtility.certificatePassword);

		/* Now we transition to what should be done in the various threads in
		 * your application that need to use PhoneFactor.  The code above this
		 * point should be done at application initialization or a similar 
		 * point in your application.
		 */

		/* Call PFAuth.authenticate.  Catch all exceptions you wish to handle
		 * specifically and then use the PFException base class to catch the
		 * rest that are specific to the pfsdk in a generic fashion.  If no 
		 * exception is thrown, the result of the authentication request is
		 * available via the PFAuthResult object returned.
		 */
		PFAuthResult r = null;
			
		try
		{
			r = pf.authenticate(user, country, number, null, null, null);
		}
		catch (net.phonefactor.pfsdk.SecurityException e)
		{
			/* Perhaps log this?
			 */
			logger.error("BAD AUTH -- Security issue!");
			throw e;
		}
		catch (TimeoutException e)
		{
			/* Perhaps log this and alert a network management system?
			 */
			logger.error("BAD AUTH -- Server timeout!");
			return false;
		}
		catch (PFException e)
		{
			/* Catches all other exceptions authenticate throws via their 
			 * common base class.
			 */
			logger.error("BAD AUTH -- PFAuth failed with a PFException");
			logger.error(e.toString());
			throw e;
		}

		/* Obviously if an exception is thrown you should fail the auth that
		 * depended on it or take the correct action for that case.
		 *
		 * If an exception wasn't thrown, the PFAuthResult will be valid and
		 * you can consult it to determine the result of the authentication
		 * request.
		 */

		if (r.getAuthenticated())
		{
			/* We were authenticated!
			 */
			
			logger.info("GOOD AUTH");
			logger.info("Call Status: " + r.getCallStatusString());

			switch(r.getCallStatus())
			{
				case PFAuthResult.CALL_STATUS_PIN_ENTERED:
					logger.info("PIN was entered.");
					break;
			 
				case PFAuthResult.CALL_STATUS_NO_PIN_ENTERED:
					logger.info("NO PIN was entered.");
					break;

				default:
			}
			
			return true;
		}
		else
		{
			/* We were not authenticated.  Perhaps we should check if there is 
			 * an error code or error message.
			 */
			logger.error("BAD AUTH");
			logger.error("Call Status: " + r.getCallStatusString());

			switch(r.getCallStatus())
			{
				case PFAuthResult.CALL_STATUS_USER_HUNG_UP:
					logger.info("I have detected that the user hung up.");
					break;
			 
				case PFAuthResult.CALL_STATUS_PHONE_BUSY:
					logger.info("I have detected that the phone was busy.");
					break;

				default:
			}

			if (r.getMessageErrorId() != 0)
			{
				logger.error("Message Error ID: " + r.getMessageErrorId());

				String messageError = r.getMessageError();
				
				if (messageError != null)
					logger.error("Message Error: " + messageError);
			}
		}
		
		return false;
    	
    }
}
