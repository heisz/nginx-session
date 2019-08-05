# nginx-session
Baseline implementation of an nginx module and session manager to support session-based resource access control.
Illustrates/supports various forms of login, from username/password to full single sign-on, for managing access to
controlled resources.

The intent of this module was to provide a single session management solution for a set of disparate web
applications on a web-site instance.  Contained nginx configuration directives allow for the definition of various
rules for validating the session information and directing it appropriately for the downstream application
instances.

## Nginx Module Directives

Note: the nginx session module supports the majority of the binary upstream directives with the 'session' prefix.
This includes _session_socket_keepalive_, _session_connect_timeout_, _session_send_timeout_, _session_buffer_size_
and _session_read_timeout_.  These can all be defined in the http, server or location block. Refer to the Nginx documentation for the details on these standard upstream
configuration options.

###session_verify <upstream> <target>
* This directive (for location or if block) enables a session authentication/verification request to the manager
for any request in this location.  _<upstream>_ defines the associate configuration block for the upstream
definition to access the associated manager instance. _<target>_ defines the redirection target to process the
request if the authentication succeeds - this can either be a URI (in which case nginx turns the request into a get
of the indicated URL) or a named location (@...) which preserves the request against the internal configuration.

###session_cookie <id>
* This directive defines the name of a cookie that contains the session identifier for use in the session_verify
associated request.  Defaults to 'sid' if unspecified.  The cookie takes precedence over all other mechanisms of
determining the session identifier for validation.

More to come...
