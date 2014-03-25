package com.googlecode.fascinator.authentication.custom.ldap;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.naming.NamingException;

import net.sf.ehcache.Cache;
import net.sf.ehcache.CacheManager;
import net.sf.ehcache.Element;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.googlecode.fascinator.api.PluginDescription;
import com.googlecode.fascinator.api.authentication.AuthenticationException;
import com.googlecode.fascinator.api.authentication.User;
import com.googlecode.fascinator.api.roles.Roles;
import com.googlecode.fascinator.api.roles.RolesException;
import com.googlecode.fascinator.authentication.ldap.LDAPAuthentication;
import com.googlecode.fascinator.authentication.ldap.LDAPUser;
import com.googlecode.fascinator.common.JsonSimple;
import com.googlecode.fascinator.common.JsonSimpleConfig;

/**
 * This plugin is the extension of the LDAPAuthentication
 * https://github.com/the-fascinator-contrib/plugin-authentication-ldap <h3>
 * 
 * <p>
 * Configuration</h3>
 * <p>
 * Standard configuration table:
 * </p>
 * <table border="1">
 * <tr>
 * <th>Option</th>
 * <th>Description</th>
 * <th>Required</th>
 * <th>Default</th>
 * </tr>
 * 
 * <tr>
 * <td>ldap/baseURL</td>
 * <td>URL of the LDAP server</td>
 * <td><b>Yes</b></td>
 * <td>ldap://ldap.uq.edu.au:389</td>
 * </tr>
 * <tr>
 * <td>ldap/baseDN</td>
 * <td>The base Distinguished Name to search under</td>
 * <td><b>Yes</b></td>
 * <td>ou=people,o=The University of Queensland,c=AU</td>
 * </tr>
 * <tr>
 * <td>ldap/ldapSecurityPrincipal</td>
 * <td>Security Principal for non-anonymous binding</td>
 * <td><b>Yes</b></td>
 * <td>cn=JohnDoe,ou=Sample Account,dc=sample,dc=edu,dc=au</td>
 * </tr>
 * <tr>
 * <td>ldap/ldapSecurityCredentials</td>
 * <td>Credentials for ldapSecurityPrincipal</td>
 * <td><b>Yes</b></td>
 * <td>*******</td>
 * </tr>
 * <tr>
 * <td>ldap/idAttribute</td>
 * <td>The name of the attribute for which the username will be searched under</td>
 * <td><b>Yes</b></td>
 * <td>uid</td>
 * </tr>
 * <tr>
 * <td>ldap/ldapRoleAttribute</td>
 * <td>The name of the LDAP attribute that contains the role values</td>
 * <td><b>No</b></td>
 * <td>objectClass</td>
 * </tr>
 * 
 * <tr>
 * <td>ldap/bindMode</td>
 * <td>The binding mode for the LDAP which is one of bind, bind-search-compare, or bind-search0bind</td>
 * <td><b>No</b></td>
 * <td>bind</td>
 * </tr>
 * </table>
 * 
 * 
 * @author danielt@intersect.org.au
 */
public class ActiveDirectoryLDAPExtension extends LDAPAuthentication implements Roles {
    private static final String PLUGIN_ID = "activedirectory";
    private Cache userCache;
    private Cache credentialCache;
	/** Logging **/
	@SuppressWarnings("unused")
	private final Logger log = LoggerFactory
			.getLogger(LDAPAuthentication.class);

	/** User object */
	private LDAPUser user_object;

	/** Ldap authentication class */
	private CustomLdapAuthenticationHandler ldapAuth;
	public CustomLdapAuthenticationHandler getAuthenticationHandler() {
	    return ldapAuth;
	}
	@Override
	public String getId() {
		return PLUGIN_ID;
	}

	@Override
	public String getName() {
		return "ActiveDirectory LDAP Extension";
	}

	/**
	 * Gets a PluginDescription object relating to this plugin.
	 * 
	 * @return a PluginDescription
	 */
	@Override
	public PluginDescription getPluginDetails() {
		return new PluginDescription(this);
	}

	/**
	 * Initialisation of LDAP Authentication plugin
	 * 
	 * @throws AuthenticationException
	 *             if fails to initialise
	 */
	@Override
	public void init(String jsonString) throws AuthenticationException {
		try {
			setConfig(new JsonSimpleConfig(jsonString));
		} catch (UnsupportedEncodingException e) {
			throw new AuthenticationException(e);
		} catch (IOException e) {
			throw new AuthenticationException(e);
		}
	}

	@Override
	public void init(File jsonFile) throws AuthenticationException {
		try {
			setConfig(new JsonSimpleConfig(jsonFile));
		} catch (IOException ioe) {
			throw new AuthenticationException(ioe);
		}
	}
	private void buildCache() {
	    CacheManager singletonManager = CacheManager.create();
	    userCache = new Cache("userCache", 500, false, false, 3600, 1800);
	    singletonManager.addCache(userCache);
	    credentialCache = new Cache("credentialCache", 500, false, false, 3600, 1800);
        singletonManager.addCache(credentialCache);
	}
	/**
	 * Set default configuration
	 * 
	 * @param config
	 *            JSON configuration
	 * @throws IOException
	 *             if fails to initialise
	 */
	private void setConfig(JsonSimpleConfig config) throws IOException {
	    buildCache();
		user_object = new LDAPUser();
		String url = config.getString(null, "authentication", PLUGIN_ID, "baseURL");
		String baseDN = config.getString(null, "authentication", PLUGIN_ID, "baseDN");
		String idAttribute = config.getString(null, "authentication", PLUGIN_ID, "idAttribute");
		String secPrinc = config.getString(null, "authentication", PLUGIN_ID, "ldapSecurityPrincipal");
		String secCreds = config.getString(null, "authentication", PLUGIN_ID, "ldapSecurityCredentials");
		String bindMode = config.getString("bind", "authentication", PLUGIN_ID, "bindMode");
		String ldapRoleParam = config.getString("memberOf", PLUGIN_ID, "ldapRoleAttribute");
		// Need to get these values from somewhere, ie the config file passed in
		ldapAuth = new CustomLdapAuthenticationHandler(url, baseDN, secPrinc,
				secCreds, ldapRoleParam, idAttribute);
		ldapAuth.setBindMode(bindMode);
		Map<String, List<String>> ldapToFascinatorRolesMap = new HashMap<String, List<String>>();
        List<JsonSimple> objectClassRolesList = config.getJsonSimpleList(
                        "roles", PLUGIN_ID, "ldapRoleMap");
        if (objectClassRolesList != null) {
                for (JsonSimple q : objectClassRolesList) {
                        String ldapRole = q.getString(null, "ldapRoleAttrValue");
                        List<String> fascinatorRolesList = q.getStringList("roles");
                        ldapToFascinatorRolesMap.put(ldapRole, fascinatorRolesList);
                }
        }
        ldapAuth.setLdapRolesMap(ldapToFascinatorRolesMap);


	}

	/**
	 * Tests the user's username/password validity.
	 * 
	 * @param username
	 *            The username of the user logging in.
	 * @param password
	 *            The password of the user logging in.
	 * @return A user object for the newly logged in user.
	 * @throws AuthenticationException
	 *             if there was an error logging in.
	 */
	@Override
	public User logIn(String username, String password)
			throws AuthenticationException {
	    User user = null;
		// Check to see if users authorised.
		try {
		    Element userObject = userCache.get(username); 
		    if  (userObject != null) {
		        return (User)userObject.getObjectValue();
		    }
			if (ldapAuth.authenticate(username, password)) {
				// Return a user object.
			    user = getUser(username);
			    userCache.put(new Element(username, user));
			    return getUser(username);
			} else {
				throw new AuthenticationException(
						"Invalid password or username.");
			}
		} catch (NamingException e) {
			throw new AuthenticationException("Invalid password or username.");
		}
	}

	/**
	 * Describe the metadata the implementing class needs/allows for a user.
	 * 
	 * TODO: This is a placeholder of possible later SQUIRE integration.
	 * 
	 * @return TODO: possibly a JSON string.
	 */
	@Override
	public String describeUser() {
		return user_object.describeMetadata();
	}

	/**
	 * Returns a User object if the implementing class supports user queries
	 * without authentication.
	 * 
	 * @param username
	 *            The username of the user required.
	 * @return An user object of the requested user.
	 * @throws AuthenticationException
	 *             if there was an error retrieving the object.
	 */
	@Override
	public User getUser(String username) throws AuthenticationException {
		// Get a new user object and try to find the users common name
		//cache user
	    user_object = new LDAPUser();
		String cn = ldapAuth.getAttr(username, "cn");
		if (cn.equals("")) {
			// Initialise the user with displayname the same as the username
			user_object.init(username);
		} else {
			// Initialise the user with different displayname and username
			user_object.init(username, cn);
		}
		return user_object;
	}
	
	 /**
     * Find and return all roles this user has.
     *
     * @param username
     * The username of the user.
     * @return An array of role names (String).
     */
    @Override
    public String[] getRoles(String username) {
            //cache roles
            Element rolesElement = credentialCache.get(username);
            
            if (rolesElement != null) {
                return  (String[])rolesElement.getObjectValue();
                
            }
            String[] roles = getAuthenticationHandler().getRoles(username).toArray(new String[] {}); 
            credentialCache.put(new Element(username, roles));
            return roles ;
    }

    /**
     * Returns a list of users who have a particular role.
     *
     * @param role
     * The role to search for.
     * @return An array of usernames (String) that have that role.
     */
    @Override
    public String[] getUsersInRole(String role) {
            return new String[0];
    }

    /**
     * Method for testing if the implementing plugin allows the creation,
     * deletion and modification of roles.
     *
     * @return true/false reponse.
     */
    @Override
    public boolean supportsRoleManagement() {
            return false;
    }

    /**
     * Assign a role to a user.
     *
     * @param username
     * The username of the user.
     * @param newrole
     * The new role to assign the user.
     * @throws RolesException
     * if there was an error during assignment.
     */
    @Override
    public void setRole(String username, String newrole) throws RolesException {
            throw new RolesException("Cannot set role with LDAP plugin!");
    }

    /**
     * Remove a role from a user.
     *
     * @param username
     * The username of the user.
     * @param oldrole
     * The role to remove from the user.
     * @throws RolesException
     * if there was an error during removal.
     */
    @Override
    public void removeRole(String username, String oldrole)
                    throws RolesException {
            throw new RolesException("Cannot remove role with LDAP plugin!");
    }

    /**
     * Create a role.
     *
     * @param rolename
     * The name of the new role.
     * @throws RolesException
     * if there was an error creating the role.
     */
    @Override
    public void createRole(String rolename) throws RolesException {
            throw new RolesException(
                            "Role creation is not support by this plugin as a "
                                            + "stand-alone function. Call setRole() with a new "
                                            + "role and it will be created automatically.");
    }

    /**
     * Delete a role.
     *
     * @param rolename
     * The name of the role to delete.
     * @throws RolesException
     * if there was an error during deletion.
     */
    @Override
    public void deleteRole(String rolename) throws RolesException {
            throw new RolesException("Cannot delete role with LDAP plugin!");
    }

    /**
     * Rename a role.
     *
     * @param oldrole
     * The name role currently has.
     * @param newrole
     * The name role is changing to.
     * @throws RolesException
     * if there was an error during rename.
     */
    @Override
    public void renameRole(String oldrole, String newrole)
                    throws RolesException {
            throw new RolesException("Cannot rename role with LDAP plugin!");
    }

    /**
     * Returns a list of roles matching the search.
     *
     * @param search
     * The search string to execute.
     * @return An array of role names that match the search.
     * @throws RolesException
     * if there was an error searching.
     */
    @Override
    public String[] searchRoles(String search) throws RolesException {
            throw new RolesException("Cannot search roles with LDAP plugin!");
    }
}
