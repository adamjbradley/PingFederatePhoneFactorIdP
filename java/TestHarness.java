import java.io.UnsupportedEncodingException;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.naming.NamingException;

import junit.framework.Assert;

import org.apache.log4j.Logger;
import org.apache.log4j.LogManager;
import org.junit.Test;

import java.io.UnsupportedEncodingException;
import java.util.List;
import java.util.Map;

import net.phonefactor.pfsdk.PFException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.log4j.Logger;
import org.junit.Test;

import com.pingidentity.adapter.idp.PFUtility;
import com.pingidentity.adapter.idp.PhoneNumber;

public class TestHarness {

	public Logger log = Logger.getLogger(this.getClass());
	
	@Test
	public void FilterTest() {
		String userName = "user1-3@detfed1.adambradleyconsulting.com";
		String filter = "userPrincipalName=${username}".replace("${username}", userName);		
	}
	
	@Test
	public void PhoneFactor() {
		try {
			PFUtility pfu = new PFUtility("c:/pf/", "RIVHJIMDZAJZCSA5");
			PhoneNumber number = new PhoneNumber("+61406680548");
			if (PFUtility.Call("user1-1@idc05.onmicrosoft.com", number.country, number.mobile))
			{
				System.out.println("Success");
			} else {
				System.out.println("Failure");
			}
		} catch (PFException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			System.out.println("Failure");
		}
	}

	@Test
	public void ParseMobile() {
		PhoneNumber number = new PhoneNumber("+61406680548");
		number = new PhoneNumber("0406680548");
	}
}
