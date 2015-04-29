package com.pingidentity.adapter.idp;

import java.io.IOException;
import java.lang.Object;
import java.lang.String;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import javax.naming.NamingException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.collections.MapUtils;
import org.apache.log4j.Logger;
import org.sourceid.common.ResponseTemplateRenderer;
import org.sourceid.common.Util;
import org.sourceid.saml20.adapter.AuthnAdapterException;
import org.sourceid.saml20.adapter.attribute.AttributeValue;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.gui.AdapterConfigurationGuiDescriptor;
import org.sourceid.saml20.adapter.gui.TextFieldDescriptor;
import org.sourceid.saml20.adapter.gui.CheckBoxFieldDescriptor;
import org.sourceid.saml20.adapter.gui.LdapDatastoreFieldDescriptor;
import org.sourceid.saml20.adapter.gui.validation.impl.IntegerValidator;
import org.sourceid.saml20.adapter.gui.validation.impl.RequiredFieldValidator;
import org.sourceid.saml20.adapter.gui.PasswordCredentialValidatorFieldDescriptor;
import org.sourceid.saml20.adapter.idp.authn.AuthnPolicy;
import org.sourceid.saml20.adapter.idp.authn.IdpAuthnAdapterDescriptor;
import org.sourceid.saml20.domain.SpConnection;
import org.sourceid.saml20.domain.mgmt.MgmtFactory;
import org.sourceid.saml20.metadata.MetaDataFactory;
import org.sourceid.saml20.metadata.partner.MetadataDirectory;

import com.pingidentity.adapter.idp.util.*;
import com.pingidentity.common.security.InputValidator;
import com.pingidentity.common.security.UsernameRule;
import com.pingidentity.common.util.HTMLEncoder;
import com.pingidentity.sdk.AuthnAdapterResponse;
import com.pingidentity.sdk.IdpAuthenticationAdapterV2;
import com.pingidentity.sdk.AuthnAdapterResponse.AUTHN_STATUS;


//Dependent Classes
import net.phonefactor.pfsdk.PFException;

import com.pingidentity.adapter.idp.util.*;


/**
 * <p>
 * This class is an example of an IdP authentication adapter that uses a
 * velocity HTML form template to display a form to the user. The username is
 * provided by a previous adapter and can not be changed. If not username
 * provided the authn will fail with an exception.
 * </p>
 */
public class PhoneFactorAdapter implements IdpAuthenticationAdapterV2 {

    private static final String ADAPTER_NAME = "PhoneFactor Adapter";
	private static final String ADAPTER_VERSION = "1.2";
    private final Logger log = Logger.getLogger(this.getClass());
    
    //Session
    private static final SecureRandom secureRandom = new SecureRandom();
    private static final String REQUEST_TOKEN_SESSION_KEY = "RequestToken";

    //Templates
    public static String FAILED_MESSAGE = "Failed - Please try again";

    public static final String FIELD_LOGIN_TEMPLATE_NAME = "Login Template";
    public static final String DEFAULT_LOGIN_TEMPLATE_NAME = "html.form.blank.template.html";
    public static final String DESC_LOGIN_TEMPLATE_NAME = "HTML template (in <pf_home>/server/default/conf/template) to render for login.  The default value is " + DEFAULT_LOGIN_TEMPLATE_NAME + ".";

    public static final String FIELD_FAILURE_TEMPLATE_NAME = "Failure Template";
    public static final String DEFAULT_FAILURE_TEMPLATE_NAME = "html.form.blank-failure.template.html";
    public static final String DESC_FAILURE_TEMPLATE_NAME = "HTML template (in <pf_home>/server/default/conf/template) to render in the case that authentication fails. The default value is " + DEFAULT_FAILURE_TEMPLATE_NAME + ".";

    //Field Names
    public static final String ATTR_NAME_AUTH_STATUS = "authentication_status";
    public static final String ATTR_NAME_USER_NAME = "username";
    public static final String ATTR_NAME_ERROR = "error_message";

    // HTML form field names
    private static final String FORM_FIELD_STATE = "state";
    private static final String FORM_FIELD_ARG1 = "input1";
    private static final String FORM_FIELD_REQUEST_ID = "request_id";

    private String htmlTemplate;
    private String htmlFailureTemplate;
    private boolean allowOptOut = false;
    private boolean allowNonInteractive = false;

    //LDAP
    private Properties properties = new Properties();
    private LDAPQuery ldapQuery = null;
    
    public PhoneFactorAdapter() {   
    }

    private void debug_message(String message) {
        log.debug(message);
        System.out.println("**********************************");
        System.out.println(message);
    }

    public IdpAuthnAdapterDescriptor getAdapterDescriptor() {
    	AdapterConfigurationGuiDescriptor guiDescriptor = new AdapterConfigurationGuiDescriptor();

        //Configuration File Settings location
        TextFieldDescriptor baseFileLocationField = new TextFieldDescriptor("Configuration File Location", "The directory location for configuration files.");
        guiDescriptor.addField(baseFileLocationField);
        
        TextFieldDescriptor certificatePasswordField = new TextFieldDescriptor("Certificate Password", "The password for the Certificate supplied with your PhoneFactor deployment.");
        guiDescriptor.addField(certificatePasswordField);

        //Template Handling
        TextFieldDescriptor loginTemplateName = new TextFieldDescriptor(FIELD_LOGIN_TEMPLATE_NAME, DESC_LOGIN_TEMPLATE_NAME);
        loginTemplateName.addValidator(new RequiredFieldValidator());
        loginTemplateName.setDefaultValue(DEFAULT_LOGIN_TEMPLATE_NAME);
        guiDescriptor.addField(loginTemplateName);

        TextFieldDescriptor failureTemplateName = new TextFieldDescriptor(FIELD_FAILURE_TEMPLATE_NAME, DESC_FAILURE_TEMPLATE_NAME);
        failureTemplateName.addValidator(new RequiredFieldValidator());
        failureTemplateName.setDefaultValue(DEFAULT_FAILURE_TEMPLATE_NAME);
        guiDescriptor.addField(failureTemplateName);

        //LDAP
        LdapDatastoreFieldDescriptor ldapDatastoreFieldDescriptor = new LdapDatastoreFieldDescriptor("LDAP Data source", "The LDAP data source used for retrieving additional user attributes");
        guiDescriptor.addAdvancedField(ldapDatastoreFieldDescriptor);
                
        TextFieldDescriptor baseDomainField = new TextFieldDescriptor("Base Domain", "The base domain for attribute retrieval.");
        guiDescriptor.addField(baseDomainField);
        
        TextFieldDescriptor ldapFilterField = new TextFieldDescriptor("Filter", "The filter for attribute retrieval. ${username} may be used to refer to the subject. Example: userPrincipalName=${username}");
        guiDescriptor.addField(ldapFilterField);
        
        TextFieldDescriptor attributeField = new TextFieldDescriptor("Attribute", "The LDAP attributes to return.");
        guiDescriptor.addField(attributeField);
                        
        //Other
        Set<String> attrNames = new HashSet<String>();
        attrNames.add(ATTR_NAME_USER_NAME);
        
        return new IdpAuthnAdapterDescriptor(this, this.ADAPTER_NAME, attrNames, false, guiDescriptor, false, this.ADAPTER_VERSION);
    }

    @SuppressWarnings("rawtypes")
    public boolean logoutAuthN(Map authnIdentifiers, HttpServletRequest req,
                               HttpServletResponse resp, String resumePath)
    throws AuthnAdapterException, IOException {

        return true;
    }

    public void configure(Configuration configuration) {

        debug_message("configure");

        htmlTemplate = configuration.getFieldValue(FIELD_LOGIN_TEMPLATE_NAME);
        htmlFailureTemplate = configuration.getFieldValue(FIELD_FAILURE_TEMPLATE_NAME);

		properties.setProperty("configurationFileLocation", configuration.getFieldValue("Configuration File Location"));
		properties.setProperty("certificatePassword", configuration.getFieldValue("Certificate Password"));

		properties.setProperty("host", configuration.getFieldValue("LDAP Data source"));
		properties.setProperty("baseDN",configuration.getFieldValue("Base Domain"));
		properties.setProperty("filter",configuration.getFieldValue("Filter"));
		properties.setProperty("attribute",configuration.getFieldValue("Attribute"));
		
		ldapQuery = new LDAPQuery(configuration.getFieldValue("LDAP Data source"));
    }

    public Map<String, Object> getAdapterInfo() {
        return null;
    }

    private static String setRequestToken(HttpServletRequest req) {
        String requestToken = new BigInteger(20 * 8, secureRandom).toString(32);
        req.getSession().setAttribute(REQUEST_TOKEN_SESSION_KEY, requestToken);
        return requestToken;
    }

    @SuppressWarnings( { "rawtypes", "unchecked" })
    public AuthnAdapterResponse lookupAuthN(HttpServletRequest req,
                                            HttpServletResponse resp, Map<String, Object> inParameters)
    throws AuthnAdapterException, IOException {

        debug_message(ADAPTER_NAME + " lookupAuthN");
        AuthnAdapterResponse authnAdapterResponse = new AuthnAdapterResponse();
        authnAdapterResponse.setAuthnStatus(AuthnAdapterResponse.AUTHN_STATUS.IN_PROGRESS);

        HashMap<String, Object> adapterAttributes = new HashMap<String, Object>();

        Map<String, AttributeValue> chainedAttributes = (Map<String, AttributeValue>) inParameters.get(
                IN_PARAMETER_NAME_CHAINED_ATTRIBUTES);        
        
        if (MapUtils.isNotEmpty(chainedAttributes)) {
            log.info("ChainedAttributes:");
            for (Map.Entry<String, AttributeValue> e : chainedAttributes.entrySet()) {
                StringBuffer sb = new StringBuffer();
                sb.append(" " + e.getKey());
                if ((e.getValue() != null) && (e.getValue() instanceof AttributeValue))
                    sb.append(" : " + e.getValue().toString());
                log.info(sb.toString());
            }
        }

        log.info("InParameters:");
        for (Map.Entry<String, Object> e : inParameters.entrySet()) {
            StringBuffer sb = new StringBuffer();
            sb.append(" " + e.getKey());
            if (e.getValue() != null)
                sb.append(" : " + e.getValue().toString());
            log.info(sb.toString());
        }
        
        log.info("Request Parameters:");
        for (Map.Entry<String, String[]> reqParam : req.getParameterMap().entrySet()) {
            log.info(" " + reqParam.getKey() + " : " + reqParam.getValue()[0].toString());
        }

        // Make sure we're in an interactive session
        AuthnPolicy authnPolicy = (AuthnPolicy) inParameters.get(IN_PARAMETER_NAME_AUTHN_POLICY);
        if (!authnPolicy.allowUserInteraction()) {
            if(allowNonInteractive) {
                authnAdapterResponse.setAuthnStatus(AuthnAdapterResponse.AUTHN_STATUS.SUCCESS);
            } else {
                authnAdapterResponse.setAuthnStatus(AuthnAdapterResponse.AUTHN_STATUS.FAILURE);
            }
            return authnAdapterResponse;
        }

        String resumePath = inParameters.get(IN_PARAMETER_NAME_RESUME_PATH).toString();
        String partnerEntityId = inParameters.get(IN_PARAMETER_NAME_PARTNER_ENTITYID).toString();
        String userName = chainedAttributes.get("username").getValue().toString();
        
        String responseTemplate = htmlTemplate;
        Map<String, Object> responseParams = new HashMap<String, Object>();
        responseParams.put("url", resumePath);

        //Session Management
        String requestToken = (String)req.getSession().getAttribute(REQUEST_TOKEN_SESSION_KEY);

        //Initialise PhoneFactor
    	PFUtility pfu = new PFUtility(properties.getProperty("configurationFileLocation"), properties.getProperty("certificatePassword"));

        // Validate Postback
        if (requestToken != null) {
            debug_message("Session requestToken = " + requestToken);
            
            // Success is the ultimate result of second-factor authentication
            if(req.getSession().getAttribute("success").equals("true")) {
                responseTemplate = null;
                authnAdapterResponse.setAuthnStatus(AuthnAdapterResponse.AUTHN_STATUS.SUCCESS);
                req.getSession().removeAttribute(REQUEST_TOKEN_SESSION_KEY);
                debug_message("Success!");
            } else if(req.getSession().getAttribute("success").equals("false")) {                
            	responseTemplate = htmlFailureTemplate;
                authnAdapterResponse.setAuthnStatus(AuthnAdapterResponse.AUTHN_STATUS.FAILURE);
                req.getSession().removeAttribute(REQUEST_TOKEN_SESSION_KEY);
                debug_message("Failure!");
            }            
            else {
                //Lookup LDAP
            	List<String>attributes = new ArrayList<String>();
            	attributes.add(properties.getProperty("attribute"));
            	String filter = properties.getProperty("filter").replace("${username}", userName);
    			List<String>result = ldapQuery.getAttributes(properties.getProperty("baseDN"), filter, attributes);
    			
    			log.debug("Searching for " + userName + " with filter " + filter); 
    			if (result.size() == 1) {												
    				log.debug("Result of LDAP call " + result.get(0));
    							
    				// Set the authentication response
    		        try {		        	
    		        	log.debug("Attempting to call PFUtility");
    		        	PhoneNumber number = new PhoneNumber(result.get(0));
    		        			        			    
    	    			if (PFUtility.Call(userName, number.country, number.mobile))
    					{
    			        	log.info("Success!");
    			            req.getSession().setAttribute("success", "true");				
    					}
    					else
    					{
    			        	log.info("Failure!");				        
    			            req.getSession().setAttribute("success", "false");				
    					}					
    				} catch (PFException e) {
    		        	log.info("Failure! "+ e.toString());
    		            req.getSession().setAttribute("success", "false");				
    				}										
    			}
    			else
    			{
    				log.debug("No results found for the user " + userName);
    	            req.getSession().setAttribute("success", "false");				
    			}                			             
            }
        } else {
            debug_message("First call");
            setRequestToken(req);  
            req.getSession().setAttribute("success","");
        }
        
        if (responseTemplate != null) {
        	ResponseTemplateRenderer renderer = ResponseTemplateRenderer.getInstance();
            renderer.render(req, resp, responseTemplate, responseParams);
        }

        adapterAttributes.put(ATTR_NAME_USER_NAME, userName);
        authnAdapterResponse.setAttributeMap(adapterAttributes);
        return authnAdapterResponse;
    }

    /**
     * This method is deprecated. It is not called when
     * IdpAuthenticationAdapterV2 is implemented. It is replaced by
     * {@link #lookupAuthN(HttpServletRequest, HttpServletResponse, Map)}
     *
     * @deprecated
     */
    @SuppressWarnings(value = { "rawtypes" })
    public Map lookupAuthN(HttpServletRequest req, HttpServletResponse resp,
                           String partnerSpEntityId, AuthnPolicy authnPolicy, String resumePath)
    throws AuthnAdapterException, IOException {

        throw new UnsupportedOperationException();
    }

}
