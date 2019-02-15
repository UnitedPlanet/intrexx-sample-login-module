/*
 * Copyright 2000-2019 United Planet GmbH, Freiburg Germany
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */


package org.example.auth.module;


import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.uplanet.jdbc.JdbcConnection;
import de.uplanet.lucy.auth.LOGIN_TOKEN_TYPE;
import de.uplanet.lucy.security.principal.IxDsClassPrincipal;
import de.uplanet.lucy.server.ContextConnection;
import de.uplanet.lucy.server.auth.AuthConfiguration;
import de.uplanet.lucy.server.auth.PrincipalUtil;
import de.uplanet.lucy.server.auth.module.LoginDomainCallback;
import de.uplanet.lucy.server.auth.module.LoginTokens;
import de.uplanet.lucy.server.auth.module.PasswordCallback;
import de.uplanet.lucy.server.common.auth.module.LoginNameCallback;
import de.uplanet.lucy.server.usermanager.IntrexxServerSecret;
import de.uplanet.lucy.server.usermanager.usecases.ILoginUtil;
import de.uplanet.lucy.server.usermanager.usecases.LoginUtil;
import de.uplanet.lucy.usermanager.NotFoundException;


/**
 * This login module authenticates a user whose credentials are stored in the
 * Intrexx database using user name, login domain, and password as credentials.
 * @author <a href="mailto:alexander.veit@unitedplanet.com">Alexander Veit</a>
 */
@LoginTokens({
	LOGIN_TOKEN_TYPE.USER_NAME,
	LOGIN_TOKEN_TYPE.DOMAIN_NAME,
	LOGIN_TOKEN_TYPE.PASSWORD})
public final class MyPasswordLoginModule implements LoginModule
{
	/** Helper for logging. */
	private static final Logger ms_log = LoggerFactory.getLogger(MyPasswordLoginModule.class);

	private final ILoginUtil m_loginUtil = new LoginUtil();

	/** The subject. */
	private Subject m_subject;

	/** The callback handler used. */
	private CallbackHandler m_cbh;

	/** Login status flag. */
	private boolean m_bLoginSucceeded;

	/** Commit status flag. */
	private boolean m_bCommitSucceeded;

	/** The user's login name. */
	private String m_strLoginName;

	/** The user's login domain. */
	private String m_strLoginDomain;

	/** The user's unique identifier. */
	private String m_strId;

	/** Flag to allow empty password logins (default: <code>false</code>). */
	private boolean m_bAllowEmptyPwd;

	/**
	 * Flag to ignore login domains that are stored in the Intrexx user database
	 * (default: <code>false</code>).
	 */
	private boolean m_bIgnoreLoginDomain;

	/** The debugging option flag. */
	private boolean m_bDebug;


	/*
	 * Explicit default constructor.
	 */
	public MyPasswordLoginModule()
	{
	}


	@Override
	public void initialize(Subject p_subject, CallbackHandler p_cbh, Map<String, ?> p_sharedState, Map<String, ?> p_options)
	{
		m_subject            = p_subject;
		m_cbh                = p_cbh;
		m_bAllowEmptyPwd     = "true".equalsIgnoreCase((String)p_options.get("allowEmptyPassword"));
		m_bIgnoreLoginDomain = "true".equalsIgnoreCase((String)p_options.get("ignoreLoginDomain"));

		m_bDebug =
			"true".equalsIgnoreCase((String)p_options.get("debug")) ||
			AuthConfiguration.getInstance().isDebug() ||
			ms_log.isDebugEnabled();
	}


	@Override
	public boolean login() throws LoginException
	{
		final LoginNameCallback    l_cbLoginName;
		final LoginDomainCallback  l_cbLoginDomain;
		final PasswordCallback     l_cbPassword;
		final String               l_strPassword;
		final JdbcConnection       l_conn;
		final IntrexxServerSecret  l_secret;

		m_bLoginSucceeded = false;

		try
		{
			l_cbLoginName   = new LoginNameCallback();
			l_cbLoginDomain = new LoginDomainCallback();
			l_cbPassword    = new PasswordCallback();

			// get the login credentials (user name, login domain, password)
			try
			{
				m_cbh.handle(new Callback[]	{l_cbLoginName, l_cbLoginDomain, l_cbPassword});
			}
			catch (UnsupportedCallbackException l_e)
			{
				if (m_bDebug)
					ms_log.info("Unsupported callback (" + l_e.getMessage() + "). Ignoring the login module.");

				return false; // ignore this login module
			}

			m_strLoginName   = l_cbLoginName.getLoginName();
			m_strLoginDomain = l_cbLoginDomain.getLoginDomain();
			l_strPassword    = l_cbPassword.getPassword();

			// print logging information
			if (m_bDebug)
			{
				final StringBuilder l_sbuf = new StringBuilder(128);

				l_sbuf.append("Try to login user = ");
				l_sbuf.append(_quoted(m_strLoginName));

				l_sbuf.append(", domain = ");
				l_sbuf.append(_quoted(m_strLoginDomain));

				l_sbuf.append('.');

				ms_log.info(l_sbuf.toString());
			}

			if (m_strLoginName == null)
				throw new FailedLoginException("No login name specified.");

			if (l_strPassword == null)
				throw new FailedLoginException("No password specified.");

			// get a database connection
			l_conn = ContextConnection.get();

			if (l_conn == null)
				throw new LoginException("No database connection available.");

			l_secret = m_loginUtil.getServerSecretFromLoginName
				(l_conn, m_strLoginName, m_strLoginDomain, m_bIgnoreLoginDomain);

			// the user GUID is used to uniquely identify the user in the commit step
			m_strId = l_secret.getUserGuid();

			// attempt login
			if (m_bAllowEmptyPwd || l_strPassword.length() > 0)
			{
				if (_authenticationSuccessful(m_strLoginName, m_strLoginDomain, l_strPassword))
					m_bLoginSucceeded = true;
				else
					m_bLoginSucceeded = false;
			}
			else
			{
				ms_log.warn("Login with empty passwords is denied.");

				m_bLoginSucceeded = false; // be explicit
			}
		}
		catch (LoginException l_e)
		{
			throw l_e;
		}
		catch (NotFoundException l_e)
		{
			// normally, we suppress this error since authentication
			// with other login modules may succeed
			if (m_bDebug)
				ms_log.error("Login failed.", l_e);

			throw new LoginException(l_e.getMessage());
		}
		catch (Exception l_e)
		{
			ms_log.error("Login failed.", l_e);

			throw new LoginException(l_e.getMessage());
		}

		return true;
	}


	/**
	 * Attempt the login.
	 * @param p_strLoginName The user name.
	 * @param p_strLoginDomain The login domain (optional).
	 * @param p_strPassword The password.
	 * @return <code>true</code> if the login with this login
	 *    module succeeded, or <code>false</code> otherwise.
	 */
	private boolean _authenticationSuccessful(String p_strLoginName,
	                                          String p_strLoginDomain,
	                                          String p_strPassword)
	{
		// TODO implement your custom login code here
		return true;
	}


	@Override
	public boolean commit() throws LoginException
	{
		final Set<IxDsClassPrincipal> l_principals;
		final JdbcConnection          l_conn;

		m_bCommitSucceeded = false;

		if (!m_bLoginSucceeded)
			return false;

		l_conn = ContextConnection.get();

		try
		{
			l_principals = PrincipalUtil.getUserSubjectPrincipals(l_conn, m_strId);

			m_subject.getPrincipals().addAll(l_principals);

			m_bCommitSucceeded = true;
		}
		catch (Exception l_e)
		{
			ms_log.error("Commit login failed.", l_e);

			throw new LoginException(l_e.getMessage());
		}

		return true;
	}


	@Override
	public boolean abort() throws LoginException
	{
		if (m_bLoginSucceeded)
		{
			logout();

			return true;
		}

		return false;
	}


	@Override
	public boolean logout() throws LoginException
	{
		if (m_subject != null)
			m_subject.getPrincipals().clear();

		m_bLoginSucceeded  = false;
		m_bCommitSucceeded = false;

		return true;
	}


	public boolean isLoginSuccess()
	{
		return m_bLoginSucceeded;
	}


	public boolean isCommitSuccess()
	{
		return m_bCommitSucceeded;
	}


	private static final String _quoted(String p_str)
	{
		if (p_str != null)
			return "'" + p_str + "'";
		else
			return "null";
	}
}

