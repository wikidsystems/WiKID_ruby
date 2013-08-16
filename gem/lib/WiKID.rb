#!/usr/bin/env ruby

# vim: set expandtab tabstop=2 shiftwidth=2 softtabstop=2: :nodoc:

module WiKID

=begin rdoc

    == Title

    WiKID Strong Authentication module for Ruby

    http://sourceforge.net/projects/wikid-twofactor/

    == Synopsis

    This is the core SSL client for WiKID Authentication.  Auth_WiKID manages
    communication between Network Clients (NC) and the WiKID Authentication
    Server (wAuth).

    == License
    Lesser GNU Public License

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

    == Author
    Greg Haygood <ghaygood@wikidsystems.com>

    == Copyright
    Copyright (c) 2001-2005 WiKID Systems, Inc.  All rights reserved.

    == Version
    CVS: Id: WiKID.rb,v 1.0 2005/09/22 05:32:19 ghaygood Exp

=end

## Not necessarily true, but only tested with 1.8.x
raise "Please, use ruby 1.8.0 or later." if RUBY_VERSION < "1.8.0"

require 'socket'
require "rexml/document"
include REXML

SSLEnabled = begin
                 require 'openssl'
                 true
             rescue LoadError
                 false
             end

class Auth

  private

=begin rdoc

     Idle time to allow before closing socket, and time limit on socket
                     * open attempt

=end
    @@timeout = 30

=begin rdoc

     Controls whether debug messages will be printed

=end
    @@DEBUG = false

    @@VERSION = "3.0.4"

    public

=begin rdoc

     This constructor allows the Auth_WiKID module to be initialized from
     either a properties file or via explicit arguments.

     @param string host_or_file   Either the IP address or hostname of
                                   the wAuth server, or the path to a
                                   properties file
     @param int port              The SSL listener port for the wAuth
                                   daemon on the wAuth server
     @param string keyfile        The PKCS12 keystore generated for this
                                   client by the wAuth server
     @param string pass           The passphrase securing the keys in keyfile
     @param string cafile         The certificate authority store for
                                   validating the wAuth server certificate

     The contents of the propertiesfile should contain the following
     key-value pairs:
     <ul>
       <li> host - The IP address or hostname of the wAuth server
       <li> port - The SSL listener port for the wAuth daemon on the
                   wAuth server
       <li> keyfile - The PKCS12 keystore generated for client by
                   the wAuth server
       <li> pass - The passphrase securing the keys in keyfile
       <li> cafile - The PEM-encoded certificate file for validating the wAuth
                      server certificate
     </ul>

=end
    def initialize(host_or_file, port, keyfile, keypass, cafile)

        unless SSLEnabled
            raise RuntimeError.new("Ruby/OpenSSL module is required for WiKID authentication.")
        end

        if (cafile.empty?)
            cafile = File.expand_path(File.join(File.dirname(__FILE__), "..", "share", "data", "WiKID-ca.pem"))
        end

        if (File.exist?(host_or_file))
            # props = parse_ini_file(host_or_file)
            props = Hash.new

            @host = props['host']
            @port = props['port']
            @keyfile = props['keyfile']
            @keypass = props['pass']
            @cafile = props['cafile']
        else
            @host = host_or_file.untaint
            @port = port.untaint
            @keyfile = keyfile.untaint
            @keypass = keypass.untaint
            unless (cafile.nil? || cafile.empty?)
                @cafile = cafile.untaint
            end
        end
        if (!@port.is_a?(Integer))
            @port = 0
        end

        _dprint("WiKID.rb initialized: host=#{@host}, port=#{@port}, keyfile=#{@keyfile}, cafile=#{@cafile}")

        ## simple hack to allow for testing during gem installation (prevents security errors since keys may not yet be available)
        unless port == -1
            checkKeys()
        end

        return true
    end

=begin rdoc

     Class destructor, which just calls close().


=end
    def _WiKID()
        close()
    end

=begin rdoc

     This method simply closes the connection to the wAuth.


=end
    def close()
        _dprint("Closing Auth_WiKID connection ...")
        unless $sslsocket.nil?
            unless $sslsocket.closed?
                $sslsocket.puts("QUIT");
                $sslsocket.flush
                $sslsocket.close
            end
            $sslsocket = nil
            @socket.shutdown
        end
        @isConnected = false
    end

=begin rdoc

     This method checks that the certificates are readable.


=end
    def checkKeys()

        data = nil
        if (@cafile.nil? || @cafile.empty? || !File.exists?(@cafile) || OpenSSL::X509::Certificate.new(File.read(@cafile)).nil?)
            raise SecurityError, "CA Public key NOT OK!"
        else
            _dprint("CA Public Key OK")
        end

        if (@keyfile.nil? || @keyfile.empty? || !File.exists?(@keyfile) || OpenSSL::X509::Certificate.new(File.read(@keyfile)).nil?)
            raise SecurityError, "Public key NOT OK!"
        else
            _dprint("Public Key OK")
        end

        if (!File.exists?(@keyfile) || OpenSSL::PKey::RSA.new(File.read(@keyfile), @keypass).nil?)
            raise SecurityError, "Private key NOT OK!"
        else
            _dprint("Private Key OK")
        end

    end

=begin rdoc

     @param string mesg         The message to send to the server

     @return string response    The response from the server

=end

    require "rexml/document"
    include REXML

    def _request(mesg)
        mesg.gsub!(/\n/, '')
        #puts "send.request is: #{mesg.inspect}"
        #puts "---------------------------------"
        $sslsocket.puts(mesg)
        $sslsocket.flush

        #puts "checking response..."
        response = $sslsocket.gets.chomp!
        #puts "send.response is: #{response.inspect}"
        unless response.nil?
            #puts "creating xml"
            xml = Document.new response
            #puts xml.inspect
        else
            #puts 'No response received.'
            xml = nil
        end
        #puts "returning XML"
        return xml;
    end

=begin rdoc

=end
    def _ping()
        mesg = '<transaction> <type>1</type> <data> <value>TX</value> </data> </transaction>';
        xml = _request(mesg);
    end

=begin rdoc
         This method initiates the connection to the wAuth server.

         @return boolean              Whether the socket is connected
=end
    def _startConnection()
        #puts "startConnection() called."
        valid_tag = "ACCEPT";
        # The client initiates the transaction
        mesg = "CONNECT: WiKID Ruby Client v#{@@VERSION}"
        mesg = "<transaction> <type>1</type> <data> <client-string>wClient Ruby #{@@VERSION}</client-string> <server-string>null</server-string> <result>null</result> </data> </transaction>
        "

        xml = _request(mesg);
        result = XPath.first(xml, '//data/result')
        if result == "ACCEPT"
            #puts "wClient connection ACCEPTED"
            @isConnected = true
        else
            #puts "wClient connection FAILED"
            @isConnected = false
        end
        return @isConnected
    end

=begin rdoc

     This method reconnects to the wAuth server, if the socket handle is dead.

     @return boolean              Whether the socket is connected

=end
    def reconnect()

        #puts "reconnect() called."

        begin

            if ($sslsocket.nil? || $sslsocket.closed?)
                #puts "Socket inactive.  Reconnecting..."

                #puts "Setting up SSL context ..."
                ctx = OpenSSL::SSL::SSLContext.new()

                # Options:
                #    "cert", "key", "client_ca", "ca_file", "ca_path",
                #    "timeout", "verify_mode", "verify_depth",
                #    "verify_callback", "options", "cert_store", "extra_chain_cert"

                ctx.cert         = OpenSSL::X509::Certificate.new(File.read(@keyfile))
                ctx.key          = OpenSSL::PKey::RSA.new(File.read(@keyfile), @keypass)

                ctx.ca_file      = @cafile
                ctx.verify_mode  = OpenSSL::SSL::VERIFY_PEER | OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT
                #ctx.verify_mode = OpenSSL::SSL::VERIFY_PEER
                #ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
                ctx.timeout      = @@timeout

                if ctx.cert.nil?
                    #puts "warning: peer certificate won't be verified this session."
                    ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
                end

                #puts "Opening socket to #{@host}:#{@port}..."
                @socket = TCPSocket.open(@host, @port)
                #puts "socket open"
                #@socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_RCVTIMEO, @@timeout)

                #@socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_SNDTIMEO, @@timeout)

                $sslsocket = OpenSSL::SSL::SSLSocket.new(@socket, ctx)
                #puts "socket created"
                #$sslsocket.sync_close = true

                # $sslsocket should be good now
                #puts "Connecting SSL socket ..."
                $sslsocket.connect

                _startConnection()

            end

            if block_given?
                #puts "Connecting SSL socket in block ..."
                $sslsocket.connect if $sslsocket.closed?
                yield
                #puts "SSL connection block finished."
            else
                #puts "SSL connection wanting to do something else ..."
                # do something non-OO
            end
        rescue Exception => ex
            warn "Error reading from server: #{ex}"
        end

    end

=begin rdoc

     Is the socket connected?

     @return boolean              Status of handle: true indicates connection is active

=end
    def isConnected()
        return @isConnected
    end

=begin rdoc

     Creates an association between the userid and the device registered
     by the user.

     @param string username      Users login ID in this authentication domain
     @param string regcode       Registration code provided to user when
                                   setting up this domain on users device
     @param string domaincode    12 digit code representing this
                                   authentication domain
     @param string passcode      Optional passcode provided by the user, to
                                   link this device to an existing registration
     @return int                  Result code from the registration attempt


=end
    def registerUsername(username, regcode, domaincode, groupname = '', passcode = '')

        _dprint("registerUsername() called ...")
        valid_tag = "REGUSER:SUCESS"

        if (!passcode.nil? && passcode.length > 0)
            _dprint("Adding new device ...")
            command = "ADDREGUSER"
            type = 4;
            passcodeline = "<passcode>#{passcode}</passcode>";
            format = "add";
        else
            _dprint("Registering user ...")
            command = "REGUSER"
            type = 4;
            passcodeline = "<passcode>null</passcode>";
            format = "new";
        end

        if (!groupname.nil? && groupname.length>0)
            groupnameline="<groupName>#{groupname}</groupName>"
        else
            groupnameline="<groupName>null</groupName>"
        end

        #mesg = "#{command}:#{username}\t#{regcode}\t#{domaincode}\t#{passcode}"
        mesg = <<XML
    <transaction>
        <type format="#{format}">#{type}</type>
        <data>
        <user-id>#{username}</user-id>
        <registration-code>#{regcode}</registration-code>
        <domaincode>#{domaincode}</domaincode>
        #{passcodeline}
        #{groupnameline}
        <error-code>null</error-code>
        <result>null</result>
        </data>
    </transaction>
XML

    #puts mesg
                            reconnect {

                                    _dprint("registerUsername() sending '#{mesg}' ...")

                                    xml = _request(mesg)
                    response = XPath.first(xml, '//data/result')
                                    _dprint("response: '#{response}'")
                                    if response =~ /SUCC?ESS/
                                            _dprint("Registered!")
                                            return 0
                                    else
                        err = XPath.first(xml, '//data/error-code')
                                            _dprint("Failed to register!  Error: #{err}")
                                            return err
                                    end
                            }

        end

=begin rdoc

     Verifies credentials generated using the online mechanism.

     @param string username          Users login ID in this authentication domain
     @param string passcode      Passcode provided by the user
     @param string domaincode    12 digit code representing the
                                   authentication domain
     @return boolean              'true' indicates credentials were valid,
                                   'false' if credentials were invalid or
                                   an error occurred

=end
    def checkCredentials(username, passcode, domaincode = '127000000001')

        _dprint("checkCredentials(#{username}, #{passcode}, #{domaincode}) called ...")

        validCredentials = false
        offline_challenge = ''
        offline_response = ''
        chap_password = ''
        chap_challenge = ''
        valid_tag = "VERIFY:VALID"

        _dprint("Checking Credentials...")

        mesg = "VERIFY:" + username + "\t" + passcode + "\t" + domaincode
        mesg = <<XML
    <transaction>
        <type format="base">2</type>
        <data>
            <user-id>#{username}</user-id>
            <passcode>#{passcode}</passcode>
            <domaincode>#{domaincode}</domaincode>
            <offline-challenge encoding="none">#{offline_challenge}</offline-challenge>
            <offline-response encoding="none">#{offline_response}</offline-response>
            <chap-password encoding="none">#{chap_password}</chap-password>
            <chap-challenge encoding="none">#{chap_challenge}</chap-challenge>
            <result>null</result>
        </data>
    </transaction>
XML

        reconnect {

            xml = _request(mesg)
            response = XPath.first(xml, '//data/result')

            if response =~ /VALID/
                validCredentials = true
            else
                validCredentials = false
            end
            _dprint("Read response: verdict = " + validCredentials.to_s)
                                    }

                                    _dprint("Returning Results...")
                                    return validCredentials
    end

=begin rdoc

     Verifies the credentials via challenge-response.

     <b>!!! Not currently supported by the Open Source release of WiKID.</b>

     @ignore
     @return boolean              'true' indicates credentials were valid,
                                   'false' if credentials were invalid or
                                   an error occurred

=end
    def chapVerify(username, domaincode, wikidChallenge = '', chapPassword = '', chapChallenge = '')

        _dprint("chapVerify() called ...")
        reconnect()
        validCredentials = false
        valid_tag = "VERIFY:VALID"
        _dprint("Checking Chap Credentials")

        mesg = "CHAPOFFVERIFY:" + username + "\t" + "nil" + "\t" + domaincode + "\t" + wikidChallenge

        reconnect {

            $sslsocket.puts(chapPassword.length)
            $sslsocket.puts(chapPassword)
            $sslsocket.puts(chapChallenge.length)
            $sslsocket.puts(chapChallenge.length)
            $sslsocket.flush

            _dprint("Reading in...")

            inputLine = $sslsocket.gets.chomp!
            if (inputLine[0, valid_tag.length] == valid_tag)
                validCredentials = true
            end
        }

        return validCredentials
    end

=begin rdoc

     Fetches a list of domains served by the currently connected server code.

     <b>!!! Not currently supported by the Open Source release of WiKID.</b>


     @ignore
     @return boolean              'true' indicates credentials were valid,
                                   'false' if credentials were invalid or
                                   an error occurred

=end
    def getDomains()

        _dprint("getDomains() called ...")

        valid_tag = "DOMAINLIST"
        _dprint("Getting Domains")

        mesg = <<XML
    <transaction>
        <type>3</type>
        <data>
            <domain-list>null</domain-list>
        </data>
    </transaction>
XML
            reconnect {
                xml = _request(mesg)
                domains = XPath.match(xml, '//data/domain-list')
            }
            _dprint("Returning Results...")
            return domains
        end

        def setDebug(newval)
            @@DEBUG = (newval == true) ? true : false
        end

=begin rdoc

   Prints a time-stamped (since the epoch) message if _@@DEBUG is true.

   @param string str           Message to print out

=end
  def _dprint(msg)

    if (@@DEBUG)
        show = Time.now.to_s + ': ' + msg
        show += '<br />' if !ENV['REQUEST_URI'].nil?

        puts show
        #STDERR.puts show
        #STDERR.flush()
    end
    return true
  end

  end

end
