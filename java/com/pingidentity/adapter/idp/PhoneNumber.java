package com.pingidentity.adapter.idp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.regex.Pattern;

public class PhoneNumber {

    public String country = null;
    public String mobile = null;

    public static Logger logger = LoggerFactory.getLogger(PhoneNumber.class);

    public PhoneNumber(String number) {
    	ParseNumber(number);
    }
        
    public void ParseNumber(String number) {
    	String GSMDigits = "\\+?\\d{8,16}";
    	String tenDigits = "\\d{10}";
    	    	
    	if (Pattern.matches(tenDigits, number))
    	{
    		this.country = "61";
    		this.mobile = number.substring(1, number.length());
    		return;
    	}
    	else if (Pattern.matches(GSMDigits, number)) {
    		this.country = "61";
    		this.mobile = number.substring(3, number.length());
    	}
    	else {
    		logger.error("Unable to parse " + number);
    		return;
    	}
    }

}
