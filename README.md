# nginx-session

[![Sauce Test Status](https://saucelabs.com/buildstatus/heisz)](https://app.saucelabs.com/u/heisz)


Baseline implementation of an nginx module and session manager to support session-based resource access control.
Illustrates/supports various forms of login, from username/password to full single sign-on, for managing access to
controlled resources.

The intent of this module was to provide a single session management solution for a set of disparate web
applications on a web-site instance.  Contained nginx configuration directives allow for the definition of various
rules for validating the session information and directing it appropriately for the downstream application
instances.

### Current Status

[![Sauce Test Status](https://saucelabs.com/browser-matrix/heisz.svg)](https://saucelabs.com/u/heisz)

### Acknowledgements and Thanks

<a href="https://saucelabs.com"><img height="70" src="https://www.heisz.org/images/saucepowered.svg" alt="Powered by SauceLabs"></a>
Cross-browser Testing Platform and Open Source <3 Provided by [Sauce Labs][https://saucelabs.com].

### License

[MIT][/LICENSE?raw=true]
