# Build, Installation and Basic Setup

```
NOTE: these instructions are based on a standard 'out-of-the-box' installation of the nginx-session components.  Due to the variability of environments and installation choices, not to mention the ability to customize the codebase to the specifics of your requirements, these should be treated as a starting point/reference as opposed to a set of de facto instructions.
```

## System Requirements
To build the nginx-session components, the following major elements are required:

* standard C and autoconf/automake build tools
* the source tree and build options used to build the NGINX server instance
* a suitable/supported C-based database interface library (PostgreSQL)

## Build/Compile/Install

There are two components to be compiled and installed; the module that is added to the NGINX server instance to parse/filter the associated HTTP requests and the manager that provides session management.  Each is covered in separate sections as follows:

### NGINX Dynamic Module

To build the NGINX dynamic module instance, the source tree and build directives that match the installed NGINX server are required.  This may require the manual compilation of the NGINX source, even if it is not the copy that is actually installed (for prebuilt binary instances). In either situation, you must have the original options used to build the NGINX instance to properly configure the module build.

From the original NGINX source tree location, (re)execute the same `configure` command used to compile the NGINX server instance, adding an additional `--add-dynamic-module` option pointing to the `module` directory of the _nginx-session_ source tree.  For example:

```
$ ./configure <options> --add-dynamic-module=<source_dir>/nginx-session/module
```

You can then rebuild the entire NGINX source tree using the `make` command or alternatively just compile the module instance with the command

```
$ make modules
```

The resultant dynamic module library will then be found in _objs/ng_http_session_module.so_, either perform a `make install` or manually copy the module library to the location specified in the _modules-path_ option of the original NGINX server configuration.

To load the module as part of the NGINX server process, use the `load_module` directive in the appropriate NGINX configuration file, for example:

```
load_module modules/ngx_http_session_module.so;
```

use the `nginx -t` command to test that the module is propery installed and loadable by the NGINX server.

For more information on the specifics of dynamic module compiling/loading, refer to the corresponding [NGINX documentation](https://www.nginx.com/resources/wiki/extending/converting/#compiling-dynamic).

### Session Manager Daemon

The source for the corresponding daemon process that handles authentication and session management is located in the _manager_ subdirectory.  There is a git submodule reference contained within to the generic _toolkit_ library; ensure that the submodule contents are up to date (as git does not automatically clone submodules unless the _-recursive_ option is specified) using the command:

```
$ git submodule update --init --recursive
```

Build the _autoconf_ configuration elements using the command:

```
$ autoreconf -vfi
```

This should create the `configure` script that is used to set up the build for the manager process binary.  Using the `--help` option will list the available options for configuration, the main ones of interest are the `--prefix` option to determine the root installation location and any options for linking to the target database client.  Once the appropriate options are chosen, run the following commands:

```
$ ./configure <options>
$ make
$ make install
```

Which will install the `ngxsessmgr` binary in the target location (typically _\<prefix>/bin_) as well as copying an example configuration file to the configured sysconfdir location (typically _\<prefix>/etc_) which is the default origin for the manager configuration if not specified on the command line.

The `configure` script will also generate a _systemd_ service file (_ngx-session-manager.service_) with the correct details for the configured installation locations.  On systems that support _systemd_ service management, this file can be copied into the _/etc/systemd/system_ directory, after which the following two commands can be used to start the manager and register it to be restarted on system reboot:

```
$ systemctl start ngx-session-manager
$ systemctl enable ngx-session-manager
```

## Basic Configuration
