Simple network sandbox for everywhere!
Support Linux/Unix and Windows.

## What it is

netsand is a small library to inject into a program to prevent
it from connecting where it should not.

This is similar to a firewall, except that:

-   you do not need specific privileges to use it
-   only injected process and its sub-processes are affected, not
    the full system

## Installation

### Linux/Unix

Provided you have a C compiler, GNU or BSD make on a Unix box:

    $ git clone https://github.com/aishee/netsand
    $ cd netsand
    $ make os=$(uname -s)

-   32bit
     $ make os=$(uname -s) bits=32

-   Compile with debug information:

     $ CFLAGS=-g make os=$(uname -s)

### Windows

Download binaries (coming soon) or compile using Visual Studio.

## Using it

### Unix

    $ ./sand -d -a '*.google.com' -a '*.bing.com' -b '*' firefox

This invokes firefox, allowing only outgoing connection to my ISP
provided name servers, to all google.com and bing.com addresses.

Everything else will be blocked, with connection blocking messages
displayed on stderr.

`sand` is a helper script that will set appropriate variables for you:

    $ ./sand -h
    Network SandBox - By Aishee Nguyen - BreakTeam
    Usage: sand [OPTION]... [--] COMMAND [ARGS]
    Prevent connections to blocked addresses in COMMAND.
    If no COMMAND is specified but some addresses are configured to be allowed or
    blocked, then shell snippets to set the chosen configuration are displayed.

    OPTIONS:
     -d, --allow-dns                   	Allow connections to DNS nameservers.
     -a, --allow=ADDRESS[/BITS][:PORT] 	Allow connections to ADDRESS[/BITS][:PORT].
     -b, --block=ADDRESS[/BITS][:PORT] 	Prevent connections to ADDRESS[/BITS][:PORT]. BITS is the number of bits in CIDR notation prefix. When BITS is specified, the rule matches the IP range.
     -h, --help                        	Print this help message.
     -t, --log-target=LOG              	Where to log. LOG is a comma-separated list that can contain the following values:
                                       	  - stderr      This is the default
                                       	  - syslog      Write to syslog
                                       	  - file        Write to COMMAND.sand file
     -p, --log-path=PATH               	Path for file log.
     -l, --log-level=LEVEL             	What to log. LEVEL can contain one of the following values:
                                       	  - silent      Do not log anything
                                       	  - error       Log errors
                                       	  - block       Log errors and blocked connections
                                       	  - allow       Log errors, blocked and allowed connections
                                       	  - debug       Log everything
     -v, --version                     	Print netsand version.

### Windows

-   Coming soon.

## Use cases

You can use netsand to:

1.  Sandbox an untrusted application to prevent all ourgoing connections from it
2.  Monitor where an application is connecting to understand how it works
3.  Filter out advertising sites during your web navigation
