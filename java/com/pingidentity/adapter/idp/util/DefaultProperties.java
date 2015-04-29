package com.pingidentity.adapter.idp.util;

import java.io.IOException;
import java.util.Properties;
import org.apache.log4j.Logger;

public class DefaultProperties
{
  private Logger log = Logger.getLogger(DefaultProperties.class);
  public static final String USER_ATTRIBUTE_SUBJECT = "USER_ATTRIBUTE_SUBJECT";
  public static final String USER_ATTRIBUTE_SUBJECT_DEFAULT = "subject";
  public static final String USER_ATTRIBUTE_EMAIL = "USER_ATTRIBUTE_EMAIL";
  public static final String USER_ATTRIBUTE_EMAIL_DEFAULT = "email";
  public static final String USER_ATTRIBUTE_IS_AUTHENTICATED = "USER_ATTRIBUTE_IS_AUTHENTICATED";
  public static final String USER_ATTRIBUTE_IS_AUTHENTICATED_DEFAULT = "isUserAuthenticated";
  public static final String LDAP_SEARCH_SCOPE = "LDAP_SEARCH_SCOPE";
  public static final int LDAP_SEARCH_SCOPE_DEFAULT = 3;
  public static final String LDAP_COUNT_LIMIT = "LDAP_COUNT_LIMIT";
  public static final int LDAP_COUNT_LIMIT_DEFAULT = 1;
  public static final String REQUEST_TOKEN_LIFETIME = "REQUEST_TOKEN_LIFETIME";
  public static final int REQUEST_TOKEN_LIFETIME_DEFAULT = 300;
  private String userAttributeSubject;
  private String userAttributeEmail;
  private String userAttributeIsAuthenticated;
  private int ldapSearchScope;
  private int ldapCountLimit;
  private String sessionAttrUserAuthenticated;
  private String sessionAttrRequestId;
  private int requestTokenLifetime;
  
  public DefaultProperties()
  {
    loadDefaultProperties();
  }
  
  private void loadDefaultProperties()
  {
    Properties defaultProperties = new Properties();
    try
    {
      ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
      defaultProperties.load(classLoader.getResourceAsStream("default.properties"));
    }
    catch (IOException io)
    {
      this.log.warn("Could not load default properties, using default values instead. Error Message: " + io.getMessage());
    }

    this.userAttributeSubject = (defaultProperties.containsKey("USER_ATTRIBUTE_SUBJECT") ? defaultProperties.getProperty("USER_ATTRIBUTE_SUBJECT") : "subject");
        
    this.userAttributeEmail = (defaultProperties.containsKey("USER_ATTRIBUTE_EMAIL") ? defaultProperties.getProperty("USER_ATTRIBUTE_EMAIL") : "email");
    
    this.userAttributeIsAuthenticated = (defaultProperties.containsKey("USER_ATTRIBUTE_IS_AUTHENTICATED") ? defaultProperties.getProperty("USER_ATTRIBUTE_IS_AUTHENTICATED") : "isUserAuthenticated");
    
    this.ldapSearchScope = (defaultProperties.containsKey("LDAP_SEARCH_SCOPE") ? Integer.parseInt(defaultProperties.getProperty("LDAP_SEARCH_SCOPE")) : 3);
    
    this.ldapCountLimit = (defaultProperties.containsKey("LDAP_COUNT_LIMIT") ? Integer.parseInt(defaultProperties.getProperty("LDAP_COUNT_LIMIT")) : 1);
            
    this.requestTokenLifetime = (defaultProperties.containsKey("REQUEST_TOKEN_LIFETIME") ? Integer.parseInt(defaultProperties.getProperty("REQUEST_TOKEN_LIFETIME")) : 300);
  }
    
  public String getUserAttributeSubject()
  {
    return this.userAttributeSubject;
  }
    
  public String getUserAttributeEmail()
  {
    return this.userAttributeEmail;
  }
  
  public String getUserAttributeIsAuthenticated()
  {
    return this.userAttributeIsAuthenticated;
  }
  
  public int getLdapSearchScope()
  {
    return this.ldapSearchScope;
  }
  
  public int getLdapCountLimit()
  {
    return this.ldapCountLimit;
  }
    
  public int getRequestTokenLifetime()
  {
    return this.requestTokenLifetime;
  }
}
