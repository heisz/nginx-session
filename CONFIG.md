# Configuring the nginx-session Module and Manager

This document details the various directives for configuring the nginx-session
module (for session determination, verification and management) followed by
configuration information for the various supported 'modes' of session
authentication.

## Module Directives

This section outlines the various directives used to configure the
nginx-session module, organized by major functional areas.

### Session Determination

There are a number of directives that control the determination of an incoming
session identifier, as the token can arrive via several possible HTTP
mechanisms depending on the actual authentication model being used.  The
following lists the various directives in priority order, in that the first
one to find a potential session identifier (non-empty value) will be
used - the module and associated manager will not validate _all_ possible
session idenitifier values in the hope of finding a valid instance.

> Syntax: **session_form_parameter** [_name_];  
> Default: depends on context  
> Context: main, http, server, location, if - location recommended

While this is the highest priority directive for determination of session, it
is also the least desirable due to the side effects of enabling it (see notes
at end of this paragraph).  If the _name_ is provided, then it will examine
(when applicable) the POST/PUT www-form-urlencoded request body for the given
_name_ as a potential session parameter.  If no _name_ is specified, then this
directive modifies the behaviour of the `session_parameter`, `session_bearer`
and `session_oauth` directives to include testing for form-encoded session
values (see below for additional details).  Note that enabling this directive
will cause the nginx-session module to potentially alter the flow for the
POST/PUT content (needing to resolve the entire body for large datasets) and
as such should not be used indiscriminately as it might affect downstream
information consumers.

> Syntax: **session_cookie** _name_;  
> Default: not applicable  
> Context: main, http, server, location, if

Specifies that the module should look for a possible session identifier in the
inbound request cookie of the given _name_.

> Syntax: **session_parameter** _name_;  
> Default: not applicable  
> Context: main, http, server, location, if

Specifies that the module should look for a possible session identifier in a
query parameter with the given _name_.  If the `session_form_parameter`
directive has been used without an associated argument, then it modifies this
setting to also include examining any POST/PUT www-form-encoded request content
for the parameter _name_ as a possible session identifier.

> Syntax: **session_bearer** [_mode_];  
> Default: header query  
> Context: main, http, server, location, if

Specifies that the module should look for a session identifier as an
OAuth2.0/Bearer _access token_ in accordance with RFC 6750.  That is, the
session identifier/access token can appear as a credential of type _Bearer_
in the _Authorization_ header or as an _access\_token_ query parameter,
depending on the bitmask set provided in the optional argument.  By default,
the www-form-encoded POST/PUT mechanism of providing the access token is not
supported unless the `session_form_parameter` directive has been specified
with no argument.

> Syntax: **session_oauth** [_mode_];  
> Default: header query  
> Context: main, http, server, location, if

Specifies that the module should look for a session identifier as an OAuth 1.0
_access token_ in accordance with RFC 5849.  That is, the session identifier
or access token can appear as a credential of type _OAuth_ in the
_Authorization_ header (see the RFC for encoding) or as an _oauth\_token_
query parameter, depending on the bitmask set provided in the optional
argument.  By default, the www-form-encoded POST/PUT mechanism of providing
the access token is not supported unless the `session_form_parameter`
directive has been specified with no argument.  At present, the nginx-session
module does not validate any elements (e.g. signature, version) of the
OAuth 1.0 client specification, aside from extracting the _oauth\_token_ value.

### Manager Connection

The session module connects to the manager via the standard Nginx upstream
mechanism.  The module supports a subset of the configuration options for the
upstream:

> Syntax: **session_socket_keepalive** _on_ | _off_;
> Default: _off_ (system dependent)
> Context: main, http, server, location, if

Controls the TCP keepalive behaviour for the connection to the manager.  By
default, the flag is unmodified and the standard system behaviour is engaged.
If set to _on_, the SO_KEEPALIVE socket option is set.

> Syntax: **session_connect_timeout** _time_;
> Default: 60s
> Context: main, http, server, location, if

Defines the connection timeout for the upstream socket establishment to the
session manager.  Cannot exceed 75 seconds per Nginx limits.

> Syntax: **session_send_timeout** _time_;
> Default: 60s
> Context: main, http, server, location, if

Defines the timeout between pending write operations to the session manager
(not the entire request) before the manager connection will be closed.

> Syntax: **session_read_timeout** _time_;
> Default: 60s
> Context: main, http, server, location, if

Defines the timeout between pending read operations from the session manager
(not the entire response) before the manager connection will be closed.

> Syntax: **session_buffer_size** _size_;
> Default: platform dependent - 4k | 8k
> Context: main, http, server, location, if

Defines the _size_ of the buffer to read the response from the manager.  Due
to the design of the manager protocol, the entire response needs to fit in this
buffer or an error will be generated by Nginx.  The driving factor for the
size of the response is the total amount of content being driven by session
attributes/variables.
