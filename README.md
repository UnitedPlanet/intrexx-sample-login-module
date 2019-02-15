# intrexx-sample-login-module

## Introduction

This project shows how to implement a simple `javax.security.auth.spi.LoginModule`
that can be used to authenticate users in Intrexx.
The login credentials used are user name, an optional login domain, and a password.


## Requirements

* Intrexx 8 or greater
* Java SE Development Kit 8


## Building from source

```bash
git clone https://github.com/UnitedPlanet/intrexx-sample-login-module.git
cd intrexx-sample-login-module
./gradlew :clean :build
```


## Import as an Eclipse project

This assumes that you have [Buildship Gradle Integration](https://marketplace.eclipse.org/content/buildship-gradle-integration)
installed.

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

