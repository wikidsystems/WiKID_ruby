#!/usr/bin/env ruby

require 'test/unit'
# $:.unshift File.join(File.dirname(__FILE__), "..", "lib")

class TestWiKID < Test::Unit::TestCase

	def test_001_rubygems

		begin
			require 'rubygems'
			loaded = 1
		rescue Exception
			# puts "WARNING: RubyGems not installed"
			loaded = 0
		end
		assert(loaded == 1, "Unable to load RubyGems!")

		require 'rubygems/rubygems_version.rb'
		# puts "Loaded RubyGems #{Gem::RubyGemsVersion} ..."

		if (Gem::RubyGemsVersion <= '0.8.11')
			 # puts "WARNING: RubyGems may need patching for a mod_ruby environment.  Please see doc/README for more details"
		end

	end

	def test_002_load_module

		begin
			require_gem 'WiKID'
			loaded = 1
		rescue
			loaded = 0
		end
		assert(loaded == 1, "Unable to load WiKID module!")

	end

	def test_003_init_module

		server_host     = "127000000001"
		server_port     = -1
		client_key_file = "/path/to/nowhere.pem"
		client_key_pass = "changeme"

		wc = WiKID::Auth.new(server_host, server_port, client_key_file, client_key_pass)
		assert_not_nil(wc, "WiKID module successfully loaded!")

	end

end
