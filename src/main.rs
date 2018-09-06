/* Teamech Embedded Client v0.1
 * September 2018
 * License: GPL v3.0
 *
 * This source code is provided with ABSOLUTELY NO WARRANTY. You are fully responsible for any
 * operations that your computers carry out as a result of running this code or anything derived
 * from it. The developer assumes the full absolution of liability described in the GPL v3.0
 * license.

    Cargo.toml:
    [package]
    name = "teamech-embedded-template"
    version = "0.1.0"
    authors = ["ellie"]

    [dependencies]
    tiny-keccak = "1.4.2"
    rand = "0.3"

*/

static MSG_VALID_TIME:u64 = 10_000; // Tolerance interval in ms for packet timestamps outside of which to mark them as suspicious

extern crate rand;
extern crate tiny_keccak;
use tiny_keccak::Keccak;
use std::env::args;
use std::process;
use std::thread::sleep;
use std::error::Error;
use std::io;
use std::io::prelude::*;
use std::time::{Duration,SystemTime,UNIX_EPOCH};
use std::net::{UdpSocket,SocketAddr,ToSocketAddrs};
use std::collections::HashSet;
use std::fs;
use std::path::Path;

// gets the unixtime in milliseconds.
fn systime() -> u64 {
	match SystemTime::now().duration_since(UNIX_EPOCH) {
		Ok(time) => {
			return time.as_secs()*1_000 + (time.subsec_nanos() as u64)/1_000_000 ;
		},
		Err(_why) => {
			return 0;
		},
	};
}

// int2bytes: splits up an unsigned 64-bit int into eight bytes (unsigned 8-bit ints).
// Endianness is preserved, but Teamech still needs to modified for big endian because the
// specification requires that all messages be little endian.
fn int2bytes(n:&u64) -> [u8;8] {
	let mut result:[u8;8] = [0;8];
	for i in 0..8 {
		result[7-i] = (0xFF & (*n >> i*8)) as u8;
	}
	return result;
}

// bytes2int: Inverse of the above. Combines eight bytes into one 64-bit int.
// Same endianness concerns as above apply.
fn bytes2int(b:&[u8;8]) -> u64 {
	let mut result:u64 = 0;
	for i in 0..8 {
		result += (b[i] as u64)*2u64.pow(((7-i) as u32)*8u32);
	}
	return result;
}

// bytes2hex converts a vector of bytes into a hexadecimal string. This is used mainly for
// // debugging, when printing a binary string.
fn bytes2hex(v:&Vec<u8>) -> String {
	let mut result:String = String::from("");
	for x in 0..v.len() {
		if v[x] == 0x00 {
			result.push_str(&format!("00"));
		} else if v[x] < 0x10 {
			result.push_str(&format!("0{:x?}",v[x]));
		} else {
			result.push_str(&format!("{:x?}",v[x]));
		}
		if x < v.len()-1 {
			result.push_str(" ");
		}
	}
	return result;
}

// Teacrypt implementation: Generate single-use key and secret seed.
// Generates a single-use encryption key from a provided key size, pad file and authentication 
// nonce, and returns the key and its associated secret seed.
fn keygen(nonce:&[u8;8],padpath:&Path,keysize:&usize) -> Result<(Vec<u8>,Vec<u8>),io::Error> {
	let mut padfile:fs::File = match fs::File::open(&padpath) {
		Err(e) => return Err(e),
		Ok(file) => file,
	};
	// Finding the pad size this way won't work if the pad is a block device instead of a regular
	// file. If using the otherwise-valid strategy of using a filesystemless flash device as a pad,
	// this block will need to be extended to use a different method of detecting the pad size.
	let padsize:u64 = match fs::metadata(&padpath) {
		Err(e) => return Err(e),
		Ok(metadata) => metadata.len(),
	};
	let mut inbin:[u8;1] = [0];
	let mut seed:[u8;8] = [0;8];
	let mut seednonce:[u8;8] = nonce.clone();
	let mut newseednonce:[u8;8] = [0;8];
	// Hash the nonce, previous hash, and previous byte retrieved eight times, using each hash to 
	// index one byte from the pad file. These eight bytes are the secret seed.
	// The hash is *truncated* to the first eight bytes (64 bits), then *moduloed* to the length of
	// the pad file. (If you try to decrypt by just moduloing the whole hash against the pad
	// length, it won't work.)
	for x in 0..8 {
		let mut sha3 = Keccak::new_sha3_256();
		sha3.update(&nonce.clone());
		sha3.update(&seednonce);
		if x >= 1 {
			sha3.update(&[seed[x-1]]);
		}
		sha3.finalize(&mut newseednonce);
		seednonce = newseednonce;
		let _ = padfile.seek(io::SeekFrom::Start(bytes2int(&seednonce) % padsize));
		let _ = padfile.read_exact(&mut inbin);
		seed[x] = inbin[0];
	}
	let mut keybytes:Vec<u8> = Vec::with_capacity(*keysize);
	let mut keynonce:[u8;8] = seed;
	let mut newkeynonce:[u8;8] = [0;8];
	// Hash the seed, previous hash, and previous byte retrieved n times, where n is the length of
	// the key to be generated. Use each hash to index bytes from the pad file (with the same
	// method as before). These bytes are the key.
	for x in 0..*keysize {
		let mut sha3 = Keccak::new_sha3_256();
		sha3.update(&seed);
		sha3.update(&keynonce);
		if x >= 1 {
			sha3.update(&[keybytes[x-1]]);
		}
		sha3.finalize(&mut newkeynonce);
		keynonce = newkeynonce;
		let _ = padfile.seek(io::SeekFrom::Start(bytes2int(&keynonce) % padsize));
		let _ = padfile.read_exact(&mut inbin);
		keybytes.push(inbin[0]);
	}
	return Ok((keybytes,seed.to_vec()));
}

// Teacrypt implementation: Encrypt a message for transmission.
// Depends on keygen function; generates a random nonce, produces a key, signs the message using
// the secret seed, and returns the resulting encrypted payload (including the message,
// signature, and nonce).
fn encrypt(message:&Vec<u8>,padpath:&Path) -> Result<Vec<u8>,io::Error> {
	let nonce:u64 = rand::random::<u64>();
	let noncebytes:[u8;8] = int2bytes(&nonce);
	let keysize:usize = message.len()+8;
	// Use the keygen function to create a key of length n + 8, where n is the length of the
	// message to be encrypted. (The extra eight bytes are for encrypting the signature.)
	let (keybytes,seed) = match keygen(&noncebytes,&padpath,&keysize) {
		Ok((k,s)) => (k,s),
		Err(e) => return Err(e),
	};
	let mut signature:[u8;8] = [0;8];
	let mut sha3 = Keccak::new_sha3_256();
	// Generate the signature by hashing the secret seed, the unencrypted message, and the key used
	// to encrypt the signature and message. 
	sha3.update(&seed);
	sha3.update(&message);
	sha3.update(&keybytes);
	sha3.finalize(&mut signature);
	let mut verimessage = Vec::new();
	verimessage.append(&mut message.clone());
	verimessage.append(&mut signature.to_vec());
	let mut payload = Vec::new();
	for x in 0..keysize {
		payload.push(verimessage[x] ^ keybytes[x]);
	}
	payload.append(&mut noncebytes.to_vec());
	return Ok(payload);
}

// Teacrypt implementation: Decrypt a received message.
// Depends on keygen function; uses the nonce attached to the payload to generate the same key and
// secret seed, decrypt the payload, and verify the resulting message with its signature. The
// signature will only validate if the message was the original one encrypted with the same pad 
// file as the one used to decrypt it; if it has been tampered with, generated with a different
// pad, or is just random junk data, the validity check will fail and this function will return an
// io::ErrorKind::InvalidData error.
fn decrypt(payload:&Vec<u8>,padpath:&Path) -> Result<Vec<u8>,io::Error> {
	let mut noncebytes:[u8;8] = [0;8];
	// Detach the nonce from the payload, and use it to generate the key and secret seed.
	noncebytes.copy_from_slice(&payload[payload.len()-8..payload.len()]);
	let keysize = payload.len()-8;
	let ciphertext:Vec<u8> = payload[0..payload.len()-8].to_vec();
	let (keybytes,seed) = match keygen(&noncebytes,&padpath,&keysize) {
		Ok((k,s)) => (k,s),
		Err(e) => return Err(e),
	};
	let mut verimessage = Vec::new();
	// Decrypt the message and signature using the key.
	for x in 0..keysize {
		verimessage.push(ciphertext[x] ^ keybytes[x]);
	}
	let mut signature:[u8;8] = [0;8];
	// Detach the signature from the decrypted message, and use it to verify the integrity of the
	// message. If the check succeeds, return Ok() containing the message content; if it fails,
	// return an io::ErrorKind::InvalidData error.
	signature.copy_from_slice(&verimessage[verimessage.len()-8..verimessage.len()]);
	let message:Vec<u8> = verimessage[0..verimessage.len()-8].to_vec();
	let mut rightsum:[u8;8] = [0;8];
	let mut sha3 = Keccak::new_sha3_256();
	sha3.update(&seed);
	sha3.update(&message);
	sha3.update(&keybytes);
	sha3.finalize(&mut rightsum);
	if signature == rightsum {
		return Ok(message);
	} else {
		return Err(io::Error::new(io::ErrorKind::InvalidData,"Payload signature verification failed"));
	}
}

// Sends a vector of bytes to a specific host over a specific socket, automatically retrying in the event of certain errors
// and aborting in the event of others.
fn sendraw(listener:&UdpSocket,destaddr:&SocketAddr,payload:&Vec<u8>) -> Result<(),io::Error> {
	// loop until either the send completes or an unignorable error occurs.
	loop {
		match listener.send_to(&payload[..],destaddr) {
			Ok(nsend) => match nsend < payload.len() {
				// If the message sends in its entirety, exit with success. If it sends
				// incompletely, try again.
				false => return Ok(()),
				true => (),
			},
			Err(why) => match why.kind() {
				// Interrupted just means we need to try again.
				// WouldBlock for a send operation usually means that the transmit buffer is full.
				io::ErrorKind::Interrupted => (),
				io::ErrorKind::WouldBlock => {
					return Err(why);
				},
				_ => {
					return Err(why);
				},
			},
		};
	}
}

// Automatically encrypts a vector of bytes and sends them over the socket.
fn sendbytes(listener:&UdpSocket,destaddr:&SocketAddr,bytes:&Vec<u8>,padpath:&Path) -> Result<(),io::Error> {
    let mut stampedbytes = bytes.clone();
    stampedbytes.append(&mut int2bytes(&systime()).to_vec());
	let payload = match encrypt(&stampedbytes,&padpath) {
	    Err(why) => {
	        return Err(why);
	    },
	    Ok(b) => b,
	};
	return sendraw(&listener,&destaddr,&payload);
}

fn main() {
	if args().count() < 3 || args().count() > 4 {
		// If the user provides the wrong number of arguments, remind them of how to use this program.
		println!("Usage: teamech-console [host:remoteport] [localport] [keyfile]");
		process::exit(1);
	}
	let mut argv:Vec<String> = Vec::new();
	let mut flags:HashSet<char> = HashSet::new();
	let mut switches:HashSet<String> = HashSet::new();
    for arg in args() {
        // bin arguments into -flags, --switches, and positional arguments.
        if arg.starts_with("--") {
            let _ = switches.insert(arg);
        } else if arg.starts_with("-") {
            for c in arg.as_bytes()[1..arg.len()].iter() {
                let _ = flags.insert(*c as char);
            }
        } else {
            argv.push(arg);
        }
    }
	let mut port:u16 = 0;
	let mut padpath:&Path = Path::new("");
	// If a port number was specified (3 arguments), try to parse it and use it. If the second
	// argument of three was not a valid port number, or there were only three arguments
	// provided, then we will pass 0 to the OS as the port number, which tells it to
	// automatically allocate a free UDP port. Unlike for the server, this is a perfectly
	// reasonable thing to do for the client.
	if argv.len() == 4 {
		padpath = Path::new(&argv[3]);
		if let Ok(n) = argv[2].parse::<u16>() {
			port = n;
		} else {
			println!("Warning: Argument #2 failed to parse as a valid port number. Passing port 0 (auto-allocate) to the OS instead.");
		}
	} else if argv.len() == 3 {
		padpath = Path::new(&argv[2]);
	}
	let serverhosts:Vec<SocketAddr> = match argv[1].to_socket_addrs() {
		Err(_) => {
			// Failure to parse a remote address is always a fatal error - if this doesn't work, we
			// have nothing to do.
			println!("Could not parse argument #1 as an IP address or hostname.");
			process::exit(1);
		},
		Ok(addrs) => addrs.collect(),
	};
	let serverhost:SocketAddr = serverhosts[0];
	'recovery:loop {
		// Recovery and operator loop structure is similar to that used in the server; the operator
		// loop runs constantly while the program is active, while the recovery loop catches breaks
		// from the operator and smoothly restarts the program in the event of a problem.
		let listener:UdpSocket = match UdpSocket::bind(&format!("0.0.0.0:{}",port)) {
			Ok(socket) => socket,
			Err(why) =>	{
				// Error condition: bind to local address failed. This is probably caused by a
				// network issue, a transient OS issue (e.g. network permissions/firewall), or
				// another program (or another instance of this one) occupying the port the user 
				// specified. In any case, we can't continue, so we'll let the user know what the
				// problem is and quit.
				println!("Could not bind to local address: {}",why.description());
				process::exit(1);
			},
		};
		match listener.set_nonblocking(true) {
			Ok(_) => (),
			Err(why) => {
				// This is probably a platform error - it's not clear to me when this would happen,
				// but it probably means that the OS doesn't support nonblocking UDP sockets, which
				// is weird and means this program won't really work. Hopefully, the error message
				// will be useful to the user.
				println!("Could not set socket to nonblocking mode: {}",why.description());
				process::exit(1);
			},
		}
		// Set up some system state machinery
		let mut inbin:[u8;500] = [0;500]; // input buffer for receiving bytes
		let mut lastmsgs:Vec<Vec<u8>> = Vec::new(); // keeps track of messages that have already been received, to merge double-sends.
		'authtry:loop {
			println!("Trying to contact server...");
			match sendbytes(&listener,&serverhost,&vec![],&padpath) {
				Err(why) => {
				    println!("Could not send authentication payload - {}",why.description());
					sleep(Duration::new(5,0));
					continue 'authtry;
				},
				Ok(_) => (),
			};
			for _ in 0..10 {
				sleep(Duration::new(0,100_000_000));
				match listener.recv_from(&mut inbin) {
					Err(why) => match why.kind() {
						io::ErrorKind::WouldBlock => (),
						_ => {
						    println!("Could not receive authentication response - {}",why.description());
							sleep(Duration::new(5,0));
							continue 'authtry;
						},
					},
					Ok((nrecv,srcaddr)) => {
					    if nrecv == 25 && srcaddr == serverhost {
						    match decrypt(&inbin[0..25].to_vec(),&padpath) {
						        Ok(message) => match message[0] {
						            0x02 => {
						                println!("Subscribed to server at {}",serverhost);
							            break 'authtry;
							        },
							        0x19 => {
							            println!("Pad file is correct, but subscription was rejected by server. Server may be full.");
							            sleep(Duration::new(5,0));
							        },
							        other => {
							            println!("Server at {} sent an unknown status code {}. Is this the latest client version?",
							                                                                                        serverhost,other);
							        },
							    }, // decrypt Ok
							    Err(why) => match why.kind() {
							        io::ErrorKind::InvalidData => {
							            println!("Response from server did not validate. Local pad file is incorrect or invalid.");
							            sleep(Duration::new(5,0));
							        }
							        _ => {
							            println!("Failed to decrypt response from server - {}",why.description());
							            sleep(Duration::new(5,0));
							        },
							    }, // match why.kind
                            }; // match inbin[0]
                        } else { // if nrecv == 1
							println!("Got invalid message of length {} from {}.",nrecv,srcaddr);
							sleep(Duration::new(5,0));
                        }
					}, // recv Ok
				}; // match recv
			} // for 0..10
		} // 'authtry
		// Yay! If we made it down here, that means we're successfully authenticated and
		// subscribed, and can start doing the things this program is actually meant for.
		'operator:loop {
			sleep(Duration::new(0,1_000_000));
			// ATTENTION
			// Code that should run continuously (not just once every time a new message comes in)
			// should go here. It may call sendbytes() as necessary to send outgoing messages, and
			// should let go of the thread often (e.g. don't add any infinite loops here) to allow
			// messages to be received.
			'receiver:loop {
				match listener.recv_from(&mut inbin) {
					Err(why) => match why.kind() {
						io::ErrorKind::WouldBlock => break 'receiver,
						_ => {
							// Receive error
							println!("Could not receive packet: {}. Trying again in 5 seconds...",why.description());
							sleep(Duration::new(5,0));
						},
					},
					Ok((nrecv,srcaddr)) => {
						if srcaddr != serverhost {
							continue 'operator;
						}
						if nrecv > 24 {
							if lastmsgs.contains(&inbin[0..nrecv].to_vec()) {
								// Ignore the payload if it's a duplicate. This will never
								// false-positive, because even repeated messages will be encrypted
								// with different keys and generate different payloads. Repeated
								// payloads are always messages that were double-sent or replayed,
								// and not the client deliberately sending the same thing again.
								continue 'operator;
							} else {
								lastmsgs.push(inbin[0..nrecv].to_vec());
								if lastmsgs.len() > 32 {
									lastmsgs.reverse();
									let _ = lastmsgs.pop();
									lastmsgs.reverse();
								}
							}
							let payload:Vec<u8> = inbin[0..nrecv].to_vec();
							match decrypt(&payload,&padpath) {
								Err(why) => match why.kind() {
									io::ErrorKind::InvalidData => {
										// Validation failed
										println!("Warning: Message failed to validate. Pad file may be incorrect.");
										let _ = sendbytes(&listener,&srcaddr,&vec![0x15],&padpath);
										sleep(Duration::new(2,0));
										break 'operator;
									},
									_ => {
										// Other decryption error.
										println!("Decrypting of message failed - {}.",why.description());
										let _ = sendbytes(&listener,&srcaddr,&vec![0x1A],&padpath);
									},
								},
								Ok(message) => {
									let messagechars:Vec<u8> = message[0..message.len()-8].to_vec();
									let mut messagetext:String = String::from_utf8_lossy(&messagechars).to_string();
									let mut timestamp:[u8;8] = [0;8];
									timestamp.copy_from_slice(&message[message.len()-8..message.len()]);
									let msgtime:u64 = bytes2int(&timestamp);
									if msgtime + MSG_VALID_TIME < systime() {
										continue 'operator;
									} else if msgtime - MSG_VALID_TIME > systime() {
										continue 'operator;
						            }
						            if nrecv == 25 {
							            // payloads of one byte are messages from the server.
								        println!("[SRV]: 0x{}",&bytes2hex(&vec![message[0]]));
							            if inbin[0] == 0x19 { // END OF MEDIUM
								            // Handle deauthentications
								            println!("Subscription expiration notification received - renewing subscription to {}",serverhost);
								            continue 'recovery;
							            }
							            continue 'operator;
						            } 
									if switches.contains("--showhex") || flags.contains(&'h') {
									    println!("\r[REM]: {} [{}]",messagetext,bytes2hex(&messagechars));
									} else {
									    println!("\r[REM]: {}",messagetext);
									}
									// ATTENTION
									// From here on, you can add your own handlers for incoming
									// messages and whatever else that should happen every time a
									// new message arrives (this block will not run continuously;
									// see above for where to put your code if you want that).
									// You can put if statements and match blocks here. Here are
									// the available variables:
									// - payload:Vec<u8> - the message in encrypted form.
									// - messagetext:String - the verbatim text of the message.
									// - messagechars:Vec<u8> - the message in byte form.
									// - message:Vec<u8> - the message in byte form, including the
									//                     timestamp.
									// - timestamp:[u8;8] - Unix timestamp of the message (bytes).
									// - msgtime:u64 - Unix timestamp of the message (int).
									// - serverhost:SocketAddr - address of the server (with port).
									// - lastmsgs:Vec<Vec<u8>> - the last <32 messages received
									//                           from the server in encrypted form.
									let _ = sendbytes(&listener,&srcaddr,&vec![0x06],&padpath);
									let mut reply:String = String::new();
			                        match &messagetext as &str { 
			                            // Match various messages that you might want to do
			                            // something upon receiving (e.g. commands to read a sensor
			                            // or provide status information, or change the state of a
			                            // piece of equipment).
				                        "Hello world!" => { 
					                        reply = String::from("Hello world!");
				                        },
				                        _ => (),
			                        }; // match &messagetext
			                        if reply.len() > 0 {
			                            let replybytes:Vec<u8> = reply.as_bytes().to_vec();
					                    if switches.contains("--showhex") || flags.contains(&'h') {
						                    println!("\r[LOC]: {} [{}]",reply,bytes2hex(&replybytes));
					                    } else {
						                    println!("\r[LOC]: {}",reply);
					                    }
					                    // Send (and encrypt) the message.
					                    match sendbytes(&listener,&serverhost,&replybytes,&padpath) {
						                    Err(why) => {
							                    println!("Encrypting message failed - {}",why.description());
							                    continue 'operator;
						                    },
						                    Ok(_) => (),
					                    };
					                } // if reply.len() > 0
								}, // decrypt Ok(message)
							}; // match decrypt
						} // if nrecv > 24
					}, // recv Ok((nrecv,srcaddr))
				}; // match recv_from
			} // 'receiver
		} // 'operator
	} // 'recovery
} // fn main

