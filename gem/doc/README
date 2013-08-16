Wikid Strong Authentication Module
http://sourceforge.net/projects/wikid-two-factor

Hate passwords? The WiKID Strong Authentication System is a key-based 
two-factor authentication system. We built WiKID to be a flexible, extensible, 
and secure alternative to tokens or passwords. Application support for Java, 
Windows, PHP, SugarCRM, and Ruby.

============================
INSTALLATION
============================
The WiKID Ruby module is packaged in rubygem format.  Download the latest version 
from SourceForge, then run:

# gem install WiKID-x.y.z.gem

If you don't already have rubygems installed, you can get the latest version from
http://rubyforge.org/projects/rubygems/

============================
!!! MOD_RUBY WARNING !!!
============================
Versions of RubyGems up to 0.8.11 (the most recent as of Nov 1, 2005) do not 
function properly when $SAFE = 1, which is the default setting when running 
under mod_ruby.

Until this is corrected in the offical code, there are two work-arounds:

1.  If you're running a safe & secure Apache server (you are, right?), you can
simply turn of the safety checks with:

<IfModule mod_ruby.c>
	RubySafeLevel 0
</IfModule>

2.  Apply the included patch docs/rubygems-0.8.11.security-patch.diff to your 
rubygems installation (assumed to be in /usr/lib/ruby/site_ruby/1.8/rubygems/).
This will add the missing untaint'ings.

Note that FastCGI environments are not affected.

============================
NETWORK CLIENT SETUP
============================

Every WiKID network client needs a certificate from the WiKID server to talk 
via SSL with the WiKID server.  Create a network client on the WiKID server for 
your Ruby network client and download the network client PKCS12 certificate to 
your Ruby server.  

To extract it from the .p12 file for use by Ruby, run:

# openssl pkcs12 -in clientcertkey.p12 -clcerts -out  clientcertkey.pem

You will also need a copy of the server's cert too:

# scp root@yourwikidserver.com:/opt/WiKID/private/WiKIDCA.cer yourlocaldirectory

You need to let the WiKID.rb file know the location and passphrase for the 
WiKID server's certificate.  Find these lines and edit them for your set up:

@@cafile = "/opt/WiKID/private/WiKIDCA.cer";    

Save the file.  

We have provided sample files under docs/example/ for use with the WiKID server.  
Use example.rb for command line or CGI, or example.rhtml for mod_ruby/eruby.  
Edit for your correct variables:

	servercode_default 	= "127000000001"
	server_host      		= "wikid-server.example.com"
	server_port      		= 8388
	ca_cert_file 		 		= "WiKID-ca.pem"
	client_key_file 		= "issued-client-cert-and-key.pem"
	client_key_pass  		= "changeme"

That should be it!  For help, please use the forums and documentation on our 
SourceForge page.

============================
The WiKID Team
http://www.wikidsystems.net

