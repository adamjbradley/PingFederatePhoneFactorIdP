package com.pingidentity.adapter.idp.util;

import com.pingidentity.access.DataSourceAccessor;
import java.util.ArrayList;
import java.util.List;
import javax.naming.directory.SearchControls;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sourceid.saml20.domain.LdapDataSource;
import org.sourceid.saml20.domain.datasource.info.LdapInfo;
import org.sourceid.util.log.AttributeMap;

public class LDAPQuery {
  private Log log = null;
  private LdapDataSource ldapDataSource = null;

  public LDAPQuery(String ldapInstanceID) {
    log = LogFactory.getLog(this.getClass());
    log.debug("LDAPQuery() start...");
    ldapDataSource = new LdapDataSource();
    setLdapInstance(ldapInstanceID);
    log.debug("LDAPQuery() end...");
  }

  public void setLdapInstance(String ldapInstanceID) {
    log.debug("setLdapInstance() start...");
    LdapInfo ldapInfo = (new DataSourceAccessor()).getLdapInfo(ldapInstanceID);
    ldapDataSource.setId(ldapInstanceID);
    ldapDataSource.setHost(ldapInfo.getHost());
    ldapDataSource.setPrincipal(ldapInfo.getPrincipal());
    ldapDataSource.setCredentials(ldapInfo.getCredentials());
    ldapDataSource.setUseSSL(ldapInfo.isUseSSL());
    log.debug("setLdapInstance() end...");
  }

  public List<String> getAttributes(String ldapBaseDN, String ldapFilter, List<String> ldapAttributes) {
    log.debug("getAttributes() start...");

    List<String> attributes = new ArrayList<String>();
    String[] attributesToReturn = ldapAttributes.toArray(new String[ldapAttributes.size()]);
    try {
      List<AttributeMap> ldapResult = ldapDataSource.getAttributesOfMatchingObjects(ldapBaseDN, ldapFilter, SearchControls.SUBTREE_SCOPE, attributesToReturn, 0);
      if (ldapResult.size() > 0) {
        log.debug("LDAP query: " + ldapResult.size() + " objects found");
        for (AttributeMap attributeMap : ldapResult) {
          for (String attribute : ldapAttributes) {
            String attributeValue = attributeMap.getSingleValue(attribute);
            attributes.add(attributeValue);
            log.debug("LDAP attribute: " + attributeValue);
          }
        }
      } else {
        log.warn("LDAP query: no attributes found for " + ldapFilter + ". BaseDN " + ldapBaseDN);
      }
    } catch(Exception e) {
      log.error("There was an error querying the directory.", e);
    }

	log.debug("getAttributes() end...");
    return attributes;
  }
}
