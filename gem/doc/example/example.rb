#!/usr/bin/env ruby

begin
	require 'rubygems'
	require_gem 'WiKID'
rescue LoadError
	require 'WiKID'
end

=begin rdoc
 Instantiation
 
 This section instantiates the connection between the network client 
 application and the WiKID server.  For this to succeed, the network client 
 must have been issued a certificate from the WiKID server.  The certificate 
 is contained withing a PKCS12 certificate store and requires a passphrase to 
 access.
 
 When the Auth_WiKID object is instantiated it will load the cert and establish 
 a persistent authenticated SSL connection.  This is normally done once per 
 server or application and shared by multiple threads.  In this example the 
 object is created and destroyed each page request.  This greatly (1000 times) 
 increases overhead of the process but allows all the functions to be shown 
 in this single example page.
 
 Parameters are:
 
 WiKID.new(String host, int port, String keyfile, String pass)
 
 host = IP address of WIKID server
 port = TCP port number to connect to (default 8388)
 keyfile = Path to the PKCS12 certificate file
 pass = Passphrase to open the PKCS12 file
=end

servercode_default  = "127000000001"
server_host         = "wikid-server.example.com"
server_port         = 8388
ca_cert_file        = "WiKID-ca.pem"
client_key_file     = "issued-client-cert-and-key.pem"
client_key_pass     = "changeme"

status = ''

action = ARGV.shift
username = ARGV.shift

wc = WiKID::Auth.new(server_host, server_port, client_key_file, client_key_pass, ca_cert_file)
if (wc.nil?)
	puts "Unable to load ruby WiKID module!!"
else
	puts "WiKID module loaded!"
end

=begin rdoc
 Registration

 The registration process associates a device that has regitered its key with 
 the WiKID server to a userid that represents a individual with rights in the 
 network. * Devices can register with the server at will but have no access 
 rights until registered to a userid. * Inactive registrations are purged from 
 the system automatically.

 The registration process should be completed *only* after validating that the 
 user is not an imposter. * This may be done in various ways according to local 
 security policy. * It is assumed that whatever validation is required has been 
 completed successfully before callint the registerUsername function.

 Parameters are:

 registerUsername(String user, String regcode, String servercode)

 user = userid with which to associate device
 regcode = the registration code provided to the device
 servercode = the 12-digit code that represents the server/domain

 This method returns an integer representing the result of the registration.
=end

res = -1
if (action == "register")
		regcode = ARGV.shift
    res = wc.registerUsername(username, regcode, servercode)
    if (res == 0)
			status = "Success"
    else 
			status = "Failed ("+res+")"
    end
end

=begin rdoc
 Login Online

 This function is the normal-state login for users. * This is called when the 
 users device is connected to the network and able to directly request a 
 passcode for access.

 Parameters are:

 user = userid to validate credentials for
 passcode = time-bounded, 1 use passcode
 servercode = 12-digit code that represents the server/domain

 This method returns a boolean representing sucessful or unsuccessful authentication

=end

isValid = false
if (action == "check-online")
		passcode = ARGV.shift
    isValid = wc.checkCredentials(username, passcode, servercode)
    if (isValid)
			status = "Success"
    else 
			status = "Authentication Failed"
		end
end

=begin rdoc
 Login Offline

 This function implements the challenge-reponse authentication for offline 
 devices. * Users are given a random challenge and the signed response is 
 returned and validated.

 Parameters are:

 checkCredentials(String user, String challenge, String response, String servercode)

 user = userid to validate credentials for
 challenge = the challeng value provided to the user
 response = the hashed/signed responss from the device
 servercode = 12-digit code that represents the server/domain
=end

# Not currently supported by the Open Source release 

if (action == "check-offline")
    isValid = false
		r_challenge = ARGV.shift
		r_response = ARGV.shift
    isValid = wc.checkCredentials(username, r_challenge, r_response, servercode)
    if (isValid)
        status = "Success"
		else
        status = "Authentication Failed"
		end
end

=begin rdoc
 Add additional device to existing userid

 This method is used to add an additional device to the users account. * It 
 follows the same process as a *  normal registration but requires a passcode 
 from a device already registered to the userid. * This method * will 
 authenticate the user with the passcode provided prior to registering the 
 new device.

 Parameters are:

 registerUsername(String user, String regcode, String servercode, String passcode)

 user = userid with which to associate device
 regcode = the registration code provided to the device
 servercode = the 12-digit code that represents the server/domain
 passcode = time-bounded, 1 use passcode from a device already registered to this user

 This method returns an integer representing the result of the registration.
=end

if (action == "add-device")
		regcode = ARGV.shift
		passcode = ARGV.shift
    res = wc.registerUsername(username, regcode, servercode, passcode)
    if (res == 0)
			status = "Success"
    else 
			status = "Failed (" + res + ")"
    end
end

if (!action.nil? && !status.empty?)
    puts "Status: #{status}"
else

		puts "Usage: sample.rb <action> <username> <option, >*"
		puts ""
		puts " Available actions & options:"
		puts "    register               options:  <regcode>"
		puts "    check-online           options:  <passcode>"
		puts "    check-offline          options:  <challenge> <response>"
		puts "    add-device             options:  <new regcode> <passcode>"
		puts ""

end

