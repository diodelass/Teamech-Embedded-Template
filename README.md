# Teamech
## A Simple Application Layer for the Intranet of Things
  
## Overview
See also: main documentation on the 
[Teamech server page](https://github.com/diodelass/Teamech-Server "Teamech Server").  
This is a reference template for the Teamech embedded client. You can use it to develop special-purpose
clients for device controllers, especially Raspberry Pis, which can then be operated over a network using
a Teamech server.  
In its provided state, this program will compile and run, but will not do anything besides contact the
specified server and then wait indefinitely. You can add your own code to its structure to do whatever you 
might need, such as GPIO or serial access, status information reporting and debugging, or basic system
control. 

### Building
To build the Teamech embedded client, follow these steps:  
1. Install an up-to-date stable distribution of Rust (per the Rust website, you can do this on most
Linux distributions by running `curl https://sh.rustup.rs -sSf | sh`).
2. Clone this repository (`git clone https://github.com/diodelass/Teamech-Embedded-Template`) and `cd` 
into the main directory (`cd Teamech-Embedded-Template`).
3. Run `cargo build --release`.
4. The binary executable will be written to `Teamech-Server/target/release/teamech-embedded-template` 
where it can be run or copied into a `bin/` directory to install it system-wide.  
  
## Additional Setup
In order to work, both the Teamech server and client must use a large symmetric key file, referred
to elsewhere as a pad file. In theory, any file will work as a pad file, but for optimal security,
the pad file should be generated using a secure random number generator.  
For optimal security, you should replace the pad file and install a new one on all of the network's 
devices every time the network exchanges a total of about half the pad file's size using that pad.
This is not operationally necessary, and there are currently no known vulnerabilities that would cause
failure to update the pads to allow an attacker to gain access to the system or decrypt its messages,
but by doing this, you ensure that you're at least a moving target should this change.  
Pad files should be large enough to be reasonably sure of including every possible byte at least once.
Practically, they should be as large as you can make them while still reasonably holding and transporting
them using the storage media you have available. A few megabytes is probably reasonable.  
On Linux, you can generate a pad file easily using `dd` and `/dev/urandom`. For instance, to create
a 10-megabyte pad:  
`dd if=/dev/urandom of=teamech-september-2018.pad bs=1M count=10 status=progress`  
You should then copy this pad file to the server and all clients, and select it as the pad file to
use at the command line.  
I make absolutely no guaratees about the security of any Teamech network, no matter what key size 
and key life cycle practices you adhere to. This software is a personal project to familiarize myself
with cryptography, network programming, and version control, and you shouldn't trust it in any context.
You probably shouldn't use it at all, but I can't stop you if you're determined.
