/* 
 * The Fascinator - Common Library
 * Copyright (C) 2008-2009 University of Southern Queensland
 * Copyright (C) 2012 Queensland Cyber Infrastructure Foundation (http://www.qcif.edu.au/)
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
package com.googlecode.fascinator.authentication.custom.ldap;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.googlecode.fascinator.api.authentication.AuthenticationException;

/**
 * A custom LDAP authentication Handler based on:
 * <ul>
 * <li>https://github.com/the-fascinator-contrib/plugin-authentication-ldap/blob/master/src/main/java/com/googlecode/fascinator/authentication/ldap/LdapAuthenticationHandler.java</li>
 * <li>https://github.com/fcrepo/fcrepo/blob/master/fcrepo-security/fcrepo-security-jaas/src/main/java/org/fcrepo/server/security/jaas/auth/module/LdapModule.java</li>
 * </ul>
 * <p>
 * The handler handles 3 types of binding:
 * <ul>
 * <li>direct bind</li>
 * <li>bind search compare</li>
 * <li>bind search bind</li>
 * </ul>
 * @author danielt@intersect.org.au
 */
public class CustomLdapAuthenticationHandler {

	/** Logging */
	private static Logger log = LoggerFactory
			.getLogger(CustomLdapAuthenticationHandler.class);

	private final static String LDAP_PASSWORD_REGEX = "\\{(.+)\\}(.+)";

    private final static Pattern LDAP_PASSWORD_PATTERN = Pattern.compile(LDAP_PASSWORD_REGEX);

    /** LDAP environment */
	private Hashtable<String, String> env;

	/** LDAP Base DN */
	private String baseDn;

	/** Name of the LDAP attribute that defines the role */
	private String ldapRoleAttr;

	/** LDAP identifier attribute */
	private String idAttr;

	/** Base LDAP URL */
	private String baseUrl;

	/** LDAP security principal */
	private String ldapSecurityPrincipal;

	/** LDAP security credentials */
	private String ldapSecurityCredentials;

	/** Prefix for the LDAP query filter */
	private String filterPrefix = "";

	/** Suffix for the LDAP query filter */
	private String filterSuffix = "";

	private Map<String, List<String>> ldapRolesMap;

	/** Bind mode for LDAP */
	private String bindMode;

	/**
	 * Creates an LDAP authenticator for the specified server and base DN, using
	 * the default identifier attribute "uid"
	 * 
	 * @param baseUrl
	 *            LDAP server URL
	 * @param baseDn
	 *            LDAP base DN
	 */
	public CustomLdapAuthenticationHandler(String baseUrl, String baseDn,
			String ldapSecurityPrincipal, String ldapSecurityCredentials) {
		this(baseUrl, baseDn, ldapSecurityPrincipal, ldapSecurityCredentials,
				"objectClass", "uid");
	}

	/**
	 * Creates an LDAP authenticator for the specified server, base DN and given
	 * identifier attribute
	 * 
	 * @param baseUrl
	 *            LDAP server URL
	 * @param baseDn
	 *            LDAP base DN
	 * @param ldapSecurityPrincipal
	 *            LDAP Security Principal
	 * @param ldapSecurityCredentials
	 *            Credentials for Security Principal
	 * @param ldapRoleAttr
	 *            Name of the LDAP attribute that defines the role
	 * @param idAttr
	 *            LDAP user identifier attribute
	 */
	public CustomLdapAuthenticationHandler(String baseUrl, String baseDn,
			String ldapSecurityPrincipal, String ldapSecurityCredentials,
			String ldapRoleAttr, String idAttr) {
		// Set public variables
		this.baseDn = baseDn;
		this.idAttr = idAttr;
		this.ldapRoleAttr = ldapRoleAttr;
		this.baseUrl = baseUrl;
		this.ldapSecurityPrincipal = ldapSecurityPrincipal;
		this.ldapSecurityCredentials = ldapSecurityCredentials;
		// Initialise the LDAP environment
		env = new Hashtable<String, String>();
		env.put(Context.INITIAL_CONTEXT_FACTORY,
				"com.sun.jndi.ldap.LdapCtxFactory");
		env.put(Context.PROVIDER_URL, baseUrl);
		env.put(Context.SECURITY_AUTHENTICATION, "simple");
		if (!ldapSecurityPrincipal.equals("")) {
			env.put(Context.SECURITY_PRINCIPAL, ldapSecurityPrincipal);
			env.put(Context.SECURITY_CREDENTIALS, ldapSecurityCredentials);
		}

	}

	/**
	 * Creates an LDAP authenticator for the specified server, base DN and given
	 * identifier attribute
	 * 
	 * @param baseUrl
	 *            LDAP server URL
	 * @param baseDn
	 *            LDAP base DN
	 * @param ldapSecurityPrincipal
	 *            LDAP Security Principal
	 * @param ldapSecurityCredentials
	 *            Credentials for Security Principal
	 * @param ldapRoleAttr
	 *            Name of the LDAP attribute that defines the role
	 * @param idAttr
	 *            LDAP user identifier attribute
	 * @param ldapRolesMap
	 *            Maps relevant LDAP roles to Fascinator roles
	 */
	public CustomLdapAuthenticationHandler(String baseUrl, String baseDn,
			String ldapSecurityPrincipal, String ldapSecurityCredentials,
			String ldapRoleAttr, String idAttr,
			Map<String, List<String>> ldapRolesMap) {
		this(baseUrl, baseDn, ldapSecurityPrincipal, ldapSecurityCredentials,
				ldapRoleAttr, idAttr);
		this.ldapRolesMap = ldapRolesMap;
	}

	/**
	 * Creates an LDAP authenticator for the specified server, base DN and given
	 * identifier attribute
	 * 
	 * @param baseUrl
	 *            LDAP server URL
	 * @param baseDn
	 *            LDAP base DN
	 * @param ldapSecurityPrincipal
	 *            LDAP Security Principal
	 * @param ldapSecurityCredentials
	 *            Credentials for Security Principal
	 * @param ldapRoleAttr
	 *            Name of the LDAP attribute that defines the role
	 * @param idAttr
	 *            LDAP user identifier attribute
	 * @param ldapRolesMap
	 *            Maps relevant LDAP roles to Fascinator roles
	 */
	public CustomLdapAuthenticationHandler(String baseUrl, String baseDn,
			String ldapSecurityPrincipal, String ldapSecurityCredentials,
			String ldapRoleAttr, String idAttr, String filterPrefix,
			String filterSuffix, Map<String, List<String>> ldapRolesMap) {
		this(baseUrl, baseDn, ldapSecurityPrincipal, ldapSecurityCredentials,
				ldapRoleAttr, idAttr, ldapRolesMap);
		this.filterPrefix = filterPrefix;
		this.filterSuffix = filterSuffix;
	}

	/**
	 * Tries to authenticate user by using default settings, otherwise searches
	 * for the DN of the user
	 * 
	 * @param username
	 *            a username
	 * @param password
	 *            a password
	 * @return <code>true</code> if authentication was successful,
	 *         <code>false</code> otherwise
	 * @throws NamingException 
	 * @throws AuthenticationException
	 */
	public boolean authenticate(String username, String password)
			throws AuthenticationException, NamingException {
		if ("bind-search-compare".equals(bindMode)) {
			return bindSearchX(username, password, env, false);
		} else if ("bind-search-bind".equals(bindMode)) {
			return bindSearchX(username, password, env, true);
		} else if("bind".equals(bindMode)){
			return bind(username, password);
		} else{
			throw new AuthenticationException("wrong binding mode used");
		}
	}

	/**
	 * Attempts to authenticate user credentials with the LDAP server
	 * 
	 * @param username
	 *            a username
	 * @param password
	 *            a password
	 * @param dn
	 *            if precise dn known, otherwise should be empty string
	 * @return <code>true</code> if authentication was successful,
	 *         <code>false</code> otherwise
	 */
	private boolean bind(String username, String password) {
		try {
			String principal = String.format("%s=%s,%s", idAttr, username, baseDn);
			env.put(Context.SECURITY_PRINCIPAL, principal);
			env.put(Context.SECURITY_CREDENTIALS, password);
			DirContext ctx = new InitialDirContext(env);
			ctx.lookup(principal);
			ctx.close();
			return true;
		} catch (NamingException ne) {
			log.warn("Failed LDAP lookup doAuthenticate", ne);
		}
		return false;
	}

	private boolean bindSearchX(String username, String password,
			Hashtable<String, String> env, boolean bind)
			throws AuthenticationException, NamingException {

		env.put(Context.SECURITY_PRINCIPAL, ldapSecurityPrincipal);
		env.put(Context.SECURITY_CREDENTIALS, ldapSecurityCredentials);

		DirContext ctx = null;
		try {
			ctx = new InitialDirContext(env);
		} catch (NamingException ne) {
			log.error("Failed to bind as: {}", ldapSecurityPrincipal);
		}

		// ensure we have the userPassword attribute at a minimum
		String[] attributeList = new String[] { "userPassword" };

		SearchControls sc = new SearchControls();
		sc.setSearchScope(SearchControls.SUBTREE_SCOPE);
		sc.setReturningAttributes(attributeList);
		sc.setDerefLinkFlag(true);
		sc.setReturningObjFlag(false);
		sc.setTimeLimit(5000);

		String filter = "(" + filterPrefix + idAttr + "=" + username
				+ filterSuffix + ")";
		// Do the search
		NamingEnumeration<SearchResult> results = ctx.search(baseDn, filter, sc);
		if (!results.hasMore()) {
			log.warn("no valid user found.");
			return false;
		}

		SearchResult result = results.next();
		log.debug("authenticating user: {}", result.getNameInNamespace());

		if (bind) {
			// setup user context for binding
			Hashtable<String, String> userEnv = new Hashtable<String, String>();
			userEnv.put(Context.INITIAL_CONTEXT_FACTORY,
					"com.sun.jndi.ldap.LdapCtxFactory");
			userEnv.put(Context.SECURITY_AUTHENTICATION, "simple");
			userEnv.put(Context.PROVIDER_URL, baseUrl);
			userEnv.put(Context.SECURITY_PRINCIPAL, result.getNameInNamespace());
			userEnv.put(Context.SECURITY_CREDENTIALS, password);

			try {
				new InitialDirContext(userEnv);
			} catch (NamingException ne) {
				log.error("failed to authenticate user: "
						+ result.getNameInNamespace());
				throw ne;
			}
		} else {
			// get userPassword attribute
			Attribute up = result.getAttributes().get("userPassword");
			if (up == null) {
				log.error("unable to read userPassword attribute for: {}",
						result.getNameInNamespace());
				return false;
			}

			byte[] userPasswordBytes = (byte[]) up.get();
			String userPassword = new String(userPasswordBytes);

			// compare passwords - also handles encodings
			if (!passwordsMatch(password, userPassword)) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Performs a search of LDAP
	 * 
	 * @param username
	 *            The username to be used in the search
	 * @param dc
	 *            The directory context to use for the search
	 * @return An enumeration containing the search results
	 * @throws NamingException
	 */
	private NamingEnumeration<SearchResult> performLdapSearch(String username,
			DirContext dc) throws NamingException {
		SearchControls sc = new SearchControls();
		sc.setSearchScope(SearchControls.SUBTREE_SCOPE);

		String filter = "(" + filterPrefix + idAttr + "=" + username
				+ filterSuffix + ")";

		NamingEnumeration<SearchResult> ne = dc.search(baseDn, filter, sc);
		log.trace(String.format(
				"performing LDAP search using baseDn: %s, filter: %s", baseDn,
				filter));
		return ne;
	}

	/**
	 * Get the value of an attribute from a search result
	 * 
	 * @param attrName
	 *            The name of the attribute that we're interested in
	 * @param sr
	 *            The search result
	 * @return The attribute value
	 * @throws NamingException
	 */
	private String getAttrValue(String attrName, SearchResult sr)
			throws NamingException {
		// Get all attributes
		Attributes entry = sr.getAttributes();

		// Get the attribute value and return
		Attribute attrValues = entry.get(attrName);
		if (attrValues == null) return null;
		String[] strArr = attrValues.toString().split(":");
		return strArr[1].trim();
	}

	/**
     * Method to compare two passwords. The method attempts to encode the user
     * password based on the ldap password encoding extracted from the storage
     * format (e.g. {SHA}g0bbl3d3g00ka12@#19/=).
     *
     * @param userPassword
     *        the password that the user entered
     * @param ldapPassword
     *        the password from the ldap directory
     * @return true if userPassword equals ldapPassword with respect to encoding
     */
    private static boolean passwordsMatch(String userPassword,
                                          String ldapPassword) {
        Matcher m = LDAP_PASSWORD_PATTERN.matcher(ldapPassword);

        boolean match = false;
        if (m.find() && m.groupCount() == 2) {
            // if password is encoded in the LDAP, encode the password before
            // compare
            String encoding = m.group(1);
            String password = m.group(2);
            if (log.isDebugEnabled()) {
                log.debug("Encoding: {}, Password: {}", encoding, password);
            }

            MessageDigest digest = null;
            try {
                digest = MessageDigest.getInstance(encoding.toUpperCase());
            } catch (NoSuchAlgorithmException e) {
                log.error("Unsupported Algorithm used: {}", encoding);
                log.error(e.getMessage());
                return false;
            }

            byte[] resultBytes = digest.digest(userPassword.getBytes());
            byte[] result = Base64.encodeBase64(resultBytes);

            String pwd = new String(password);
            String ldp = new String(result);
            match = pwd.equals(ldp);
        } else {
            // if passwords are not encoded, just do raw compare
            match = userPassword.equals(ldapPassword);
        }

        return match;
    }

    /**
	 * Tries to find the value of the given attribute. Note that this method
	 * only uses the first search result.
	 * 
	 * @param username
	 *            a username
	 * @param attrName
	 *            the name of the attribute to find
	 * @return the value of the attribute, or an empty string
	 */
	public String getAttr(String username, String attrName) {
		String val = "";
		try {
			DirContext dc = new InitialDirContext(env);
			NamingEnumeration<SearchResult> ne = performLdapSearch(username, dc);

			if (ne.hasMore()) {
				val = getAttrValue(attrName, ne.next());
			}

			ne.close();
			dc.close();
		} catch (NamingException ne) {
			log.warn("Failed LDAP lookup getAttr", ne);
			log.warn("username:", username);
			log.warn("attrName:", attrName);
		}

		log.trace(String.format("getAttr search result: %s", val));
		return val;
	}

	/**
	 * Tries to find the value(s) of the given attribute. Note that this method
	 * uses all search results.
	 * 
	 * @param username
	 *            a username
	 * @param attrName
	 *            the name of the attribute to find
	 * @return a list of values for the attribute, or an empty list
	 */
	public List<String> getAllAttrs(String username, String attrName) {
		List<String> resultList = new ArrayList<String>();

		try {
			DirContext dc = new InitialDirContext(env);
			NamingEnumeration<SearchResult> ne = performLdapSearch(username, dc);

			while (ne.hasMore()) {
				resultList.add(getAttrValue(attrName, ne.next()));
			}

			ne.close();
			dc.close();
		} catch (NamingException ne) {
			log.warn("Failed LDAP lookup getAllAttrs" + username, ne);
		}

		log.trace("getAllAttrs search result: " + resultList);
		if (log.isTraceEnabled()) {
			log.trace("getAllAttrs search result: " + resultList);
		}

		return resultList;
	}

	/**
	 * Searches through the role attribute values and tries to match the given
	 * string.
	 * 
	 * @param username
	 *            a username
	 * @param testSubj
	 *            the string to look for
	 * @return <code>true</code> if string was found <code>false</code>
	 *         otherwise
	 */
	public boolean testIfInObjectClass(String username, String testSubj) {
		try {
			List<String> attrValues = getAllAttrs(username, ldapRoleAttr);
			for (String attrValue : attrValues) {
				String[] allVals = attrValue.split(",");
				for (int i = 0; i < allVals.length; i++) {
					if (testSubj.equals(allVals[i].trim())) {
						return true;
					}
				}
			}
		} catch (Exception e) {
			// Some problem exists, return false for now
			return false;
		}
		return false;
	}

	/**
	 * Get the list of roles that the user is a member of. Maps LDAP roles to
	 * Fascinator roles.
	 * 
	 * @param username
	 *            The username that identifies the user
	 * @return A list of Fascinator role names
	 */
	
	public List<String> getRoles(String username) {
	    
	    Set<String> roles = new LinkedHashSet<String>();
	    List<String> attrValues = getAllAttrs(username, ldapRoleAttr);
	    
	    List<String> userRoles = new ArrayList<String>();
	    //it's always in one row ..
	    if (attrValues.isEmpty()) {
	        return new ArrayList<String>();
	    } 
	    for (String rolesString : attrValues) {
	        addRole(rolesString, userRoles);
	    }
	    for (String objectClass : userRoles) {
	        String[] roleNames = objectClass.split(",");
	        String roleName = roleNames[0];
            if (!roleName.startsWith("CN=")) continue;
            List<String> roleList = ldapRolesMap.get(roleName.substring("CN=".length() ).trim());
            if (roleList != null) {
                roles.addAll(roleList);
            }
        }
	    return new ArrayList<String>(roles);
	}

	private void addRole(String rolesString, List<String> userRoles) {
        String[] roles = rolesString.split(" ");
        for (String role: roles) {
            if (!userRoles.contains(role)) {
                userRoles.add(role);
                int commaPos = role.indexOf(",");
                if (commaPos > -1   && (role.startsWith("CN")  || role.startsWith("cn"))) {
                    String roleName = role.substring(0, commaPos);
                    String location = role.substring(commaPos+1);
                    if (location.endsWith(",")) location = location.substring(0, location.length() -1 );
                    String attrValues = performRoleSearch(location, roleName);
                    //check if role has more children                
                    if (attrValues != null) {
                        addRole(attrValues, userRoles);
                    }
                }
                
            }
        }
        
    }

    private String performRoleSearch(String location, String roleName) {
        String val = null;
        try {

            DirContext dc = new InitialDirContext(env);
            SearchControls sc = new SearchControls();
            sc.setSearchScope(SearchControls.ONELEVEL_SCOPE);

            //String filter = "(" + filterPrefix + roleName + ")";
            NamingEnumeration<SearchResult> ne = dc.search(location, roleName, sc);
            if (ne.hasMore()) {
                val = getAttrValue("memberOf", ne.next());
            }
            ne.close();
            dc.close();
        } catch (NamingException ne) {
            log.warn("Failed LDAP lookup getAttr", ne);
            log.warn("roleName:", roleName);
            log.warn("location:", location);
        }
        return val;

    }

    public String getBindMode() {
		return bindMode;
	}

	public void setBindMode(String bindMode) {
		this.bindMode = bindMode;
	}

    public Map<String, List<String>> getLdapRolesMap() {
        return ldapRolesMap;
    }

    public void setLdapRolesMap(Map<String, List<String>> ldapRolesMap) {
        this.ldapRolesMap = ldapRolesMap;
    }
	
	

}