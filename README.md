# intrexx-sample-login-module

## Introduction

This project shows how to implement a simple `javax.security.auth.spi.LoginModule`
that can be used to authenticate users in Intrexx.
The login credentials used are user name, an optional login domain, and a password.


## Requirements

* Intrexx 12 or greater
* Java SE Development Kit 21

For Intrexx 8.0, 8.1, 9.2, 10.0, 11.0, 12.0 see tags intrexx-v8.0, intrexx-v8.1, intrexx-v9.2,
intrexx-v10.0, intrexx-v11.0, and intrexx-v12.0 respectively.


## Building from source

```bash
git clone https://github.com/UnitedPlanet/intrexx-sample-login-module.git
cd intrexx-sample-login-module
./gradlew :clean :build
```


## Import as an Eclipse project

This assumes that you have [Buildship](https://projects.eclipse.org/projects/tools.buildship) installed.

```bash
git clone https://github.com/UnitedPlanet/intrexx-sample-login-module.git
```

In Eclipse open `File/Import.../Gradle/Existing Gradle Project`, choose the directory
`intrexx-sample-login-module` and finish the import wizard.

Then go to the todo marker in the source code and start implementing your authentication logic.


## Configuration in `internal/cfg/LucyAuth.cfg`

```
MyVerySpecialAuth
{
	org.example.auth.module.MyPasswordLoginModule sufficient
		allowEmptyPassword=false
		ignoreLoginDomain=false
		debug=false;

	de.uplanet.lucy.server.auth.module.anonymous.AnonymousLoginModule sufficient
		debug=false;
};
```



## Additional Documentation

[Java Authentication and Authorization Service (JAAS): LoginModule Developer's Guide](https://docs.oracle.com/en/java/javase/21/security/java-authentication-and-authorization-service-jaas-loginmodule-developers-guide1.html)

