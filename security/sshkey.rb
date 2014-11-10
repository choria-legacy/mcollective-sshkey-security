module MCollective
  module Security
    # Configuration
    #
    # Client:
    #   client.private_key                      : A private key used to sign requests with - defaults to ssh-agent
    #   client.known_hosts                      : The known_hosts file to use - defaults to /home/callerid/.ssh/known_hosts
    #   client.send_key                         : Send the client's public key with the request - doesn not send the key by default.
    #                                             To send a key specify the key file to send.
    #
    # Server:
    #   server.private_key                      : The private key used to sign replies with - Defaults to /etc/ssh/ssh_host_rsa_key * required
    #   server.authorized_keys                  : The authorized_keys file to use - defaults to the caller's authorized_keys file in his home directory
    #   server.send_key                         : Send the server's public key with the request - does not send the key by default.
    #                                             To send a key specify the key file to send.
    #
    # Shared:
    #   (client|server).publickey_dir          : Directory to store received keys - defaults to none
    #   (client|server).learn_public_keys      : Allow writing public keys to publickey_dir - defaults to not sending.
    #   (client|server).overwrite_stored_keys  : Overwrite received keys - defaults to false
    class Sshkey < Base
      gem 'sshkeyauth', '>= 0.0.4'

      require 'ssh/key/signer'
      require 'ssh/key/verifier'
      require 'etc'

      def initialize
        @known_hosts_cache = {}
        @known_hosts_mtime = 0
        super
      end

      def decodemsg(msg)
        body = Marshal.load(msg.payload)

        if validrequest?(body)
          body[:body] = Marshal.load(body[:body])
          return body
        else
          nil
        end
      end

      def encodereply(sender, msg, requestid, requestcallerid=nil)
        serialized_msg = Marshal.dump(msg)
        reply = create_reply(requestid, sender, serialized_msg)
        reply[:serialized_data] = Marshal.dump(create_hash_fields(serialized_msg, reply[:msgtime], requestid))
        reply[:hash] = makehash(reply[:serialized_data])

        if server_key = lookup_config_option('send_key')
          if File.exists?(server_key)
            reply[:public_key] = load_key(server_key)
          else
            raise("Cannot create reply. sshkey.server.send_key set but key '%s' does not exist." % server_key)
          end
        end

        Marshal.dump(reply)
      end

      def encoderequest(sender, msg, requestid, filter, target_agent, target_collective, ttl=60)
        serialized_msg = Marshal.dump(msg)
        req = create_request(requestid, filter, serialized_msg, @initiated_by, target_agent, target_collective, ttl)


        if client_key = lookup_config_option('send_key')
          if File.exists?(client_key)
            req[:public_key] = load_key(client_key)
          else
            raise("Cannot create request. sshkey.client.send_key set but key '%s' does not exist." % client_key)
          end
        end

        req[:serialized_data] = Marshal.dump(create_hash_fields(serialized_msg, req[:msgtime], requestid, ttl, callerid))
        req[:hash] = makehash(req[:serialized_data])

        Marshal.dump(req)
      end

      def validrequest?(req)
        # Check if verification keys are correctly configured
        valid_configuration?
        # Check if key should be written to disk and write it
        write_key_to_disk(req[:public_key], (req[:callerid] || req[:senderid]).split('=')[-1] ) if req[:public_key]

        if @initiated_by == :client
          Log.debug('Validating reply from node %s' % req[:senderid])
          verifier = client_verifier(req[:senderid])
        else
          Log.debug('Validating request from client %s' % req[:callerid])
          verifier = node_verifier(req[:callerid], (req[:agent] == 'registration'), req[:public_key])
        end

        signatures = Marshal.load(req[:hash])

        if verifier.verify?(signatures, req[:serialized_data])
          @stats.validated
          return true
        else
          @stats.unvalidated
          Log.debug('Received an invalid signature in message.')
          raise SecurityValidationFailed
        end
      end

      def callerid
        'sshkey=%s' % (ENV['MCOLLECTIVE_SSH_CALLERID'] ? ENV['MCOLLECTIVE_SSH_CALLERID'] : Etc.getpwuid(Process.uid).name)
      end

      private

      # Checks that publickey_dir and known_hosts|authorized_keys are not set at the same time.
      def valid_configuration?
        if @initiated_by == :client
          if lookup_config_option('publickey_dir') && lookup_config_option('known_hosts')
            raise('Both publickey_dir and known_hosts are defined in client config. Cannot lookup public key')
          end
        elsif @initiated_by == :node
          if lookup_config_option('publickey_dir') && lookup_config_option('authorized_keys')
            raise('Both publickey_dir and authorized_keys are defiend in server config. Cannot lookup public key')
          end
        end
      end

      # Checks if the attached public key needs to be stored locally
      # Overwriting is disabled by default
      # - The publickey_directory config option needs to be set before
      #   the file will be written.
      # - The directory must exist before writing.
      # - The learn_public_keys configuration option must be enabled.
      def write_key_to_disk(key, identity)

        # Writing is disabled. Don't bother checking any other states.
        return unless lookup_config_option('learn_public_keys') =~ /^1|y/

        publickey_dir = lookup_config_option('publickey_dir')

        unless publickey_dir
          Log.info("Public key sent with request but no publickey_dir defined in configuration. Not writing key to disk.")
          return
        end

        if File.directory?(publickey_dir)
          if File.exists?(old_keyfile = File.join(publickey_dir, "#{identity}_pub.pem"))
            old_key = File.read(old_keyfile).chomp

            unless old_key == key
              unless lookup_config_option('overwrite_stored_keys', 'n') =~ /^1|y/
                Log.warn("Public key sent from '%s' does not match the stored key. Not overwriting." % identity)
              else
                Log.warn("Public key sent from '%s' does not match the stored key. Overwriting." % identity)
                File.open(File.join(publickey_dir, "#{identity}_pub.pem"), 'w') { |f| f.puts key }
              end
            end
          else
            Log.debug("Discovered a new public key for '%s'. Writing to '%s'" % [identity, publickey_dir])
            File.open(File.join(publickey_dir, "#{identity}_pub.pem"), 'w') { |f| f.puts key }
          end
        else
          raise("Cannot write public key to '%s'. Directory does not exist." % publickey_dir)
        end
      end

      # Fetches the correct configuration option for a client or a server
      def lookup_config_option(opt, default = nil)
        if @initiated_by == :client
          result = @config.pluginconf.fetch("sshkey.client.#{opt}", default)

          if result && ["authorized_keys", "private_key", "send_key", "publickey_dir", "known_hosts"].include?(opt)
            return File.expand_path(result)
          else
            return result
          end
        elsif @initiated_by == :node
          return @config.pluginconf.fetch("sshkey.server.#{opt}", default)
        end
      end

      # Creates a hash of the fields used to sign a message
      # Response messages use the msg, msgtime and requestid fields.
      # Request messages use the same fields as response, but include
      # ttl and callerid.
      def create_hash_fields(msg, msgtime, requestid, ttl = nil, callerid = nil)
        map = {:msg       => msg,
               :msgtime   => msgtime,
               :requestid => requestid}

        # Check if this is a server hash
        return map if (ttl == nil && callerid == nil)

        map[:ttl] = ttl
        map[:callerid] = callerid

        map
      end

      # Adds a key to a signer object and disables ssh-agent
      def add_key_to_signer(signer, key, passphrase=nil)
        if passphrase != nil
          signer.add_key_file(key, passphrase)
        else
          signer.add_key_file(key)
        end
        signer.use_agent = false
      end

      # Creates a signed hash of fields using the node's private key
      def makehash(data)
        signer = SSH::Key::Signer.new

        # Check if the client is signing its request with a predefined
        # private key. If this is the case, disable ssh-agent.
        if @initiated_by == :client
          if ENV['MCOLLECTIVE_SSH_KEY']
            add_key_to_signer(signer, ENV['MCOLLECTIVE_SSH_KEY'], ENV['MCOLLECTIVE_SSH_KEY_PASSPHRASE'])
          elsif private_key = lookup_config_option('private_key')
            unless File.exists?(private_key)
              raise("Cannot sign request - private key not found: '%s'" % private_key)
            else
              add_key_to_signer(signer, private_key, lookup_config_option('private_key_passphrase'))
            end
          end
        elsif @initiated_by == :node
          if private_key = lookup_config_option('private_key')
            add_key_to_signer(signer, private_key)
          else
            # First try and default to ssh_host_dsa_key
            if File.exists?(private_key = '/etc/ssh/ssh_host_dsa_key')
              add_key_to_signer(signer, private_key)
            # If that fails, try ssh_host_rsa_key
            elsif File.exists?(private_key = '/etc/ssh/ssh_host_rsa_key')
              add_key_to_signer(signer, private_key)
            else
              raise("Cannot sign reply - private key not found: 's'" % private_key)
            end
          end
        end

        # Default to using ssh-agent for key signing
        signatures = signer.sign(data).collect { |s| s.signature }
        Marshal.dump(signatures)
      end

      #Returns the contents of a key file on disk
      def load_key(key)
        if File.exists?(key)
          return File.read(key).strip
        else
          nil
        end
      end

      # Looks for a specific key in  known hosts file
      def find_key_in_known_hosts(hostname, known_hosts)
        parse_known_hosts_file known_hosts
        key = @known_hosts_cache[hostname]

        unless key
          Log.warn("Could not find a key for host '%s' in file '%s'" % [hostname, known_hosts])
          raise SecurityValidationFailed
        end

        key
      end

      # This should be safe, as we parse the known hosts file only in the client...
      def parse_known_hosts_file(known_hosts)
        if File.exists?(known_hosts)
          known_hosts_mtime = File.mtime(known_hosts).to_i
          return if known_hosts_mtime == @known_hosts_mtime
          File.read(known_hosts).each_line do |line|
            next if line =~ /^#/
            fields = line.split
            next if fields.count < 3
            key = fields[-2] << ' ' << fields[-1]
            fields[0].split(',').each do |host|
              @known_hosts_cache[host] = key
            end
          end
          @known_hosts_mtime = known_hosts_mtime
        else
          @known_hosts_mtime = 0
          @known_hosts_cache = {}
        end
      end

      # Create a client verifier object which uses the correct public key
      def client_verifier(senderid)
        verifier = SSH::Key::Verifier.new(senderid)
        verifier.use_authorized_keys = false

        if publickey_dir = lookup_config_option('publickey_dir')
          Log.debug("Using public key directory: '%s'" % publickey_dir)
          verifier.add_public_key_data(find_shared_public_key(publickey_dir, senderid))

        elsif (known_hosts = lookup_config_option('known_hosts'))
          Log.debug("Using custom known_hosts file: '%s'" % known_hosts)
          verifier.add_public_key_data(find_key_in_known_hosts(senderid, known_hosts))

        elsif (authorized_keys = lookup_config_option('authorized_keys'))
          Log.debug("Found custom authorized_keys file: '%s'" % authorized_keys)
          verifier.authorized_keys_file = authorized_keys
          verifier.use_authorized_keys = true

        else
          begin
            user = Etc.getpwuid(Process.uid).name
            known_hosts = File.join(Etc.getpwnam(user).dir, '.ssh', 'known_hosts')
            Log.debug("Using default known_hosts file for user '%s': ''" % [user, known_hosts])
            verifier.add_public_key_data(find_key_in_known_hosts(senderid, "%s" % known_hosts))
          rescue => e
            raise("Cannot find known_hosts file for user '%s': '%s'" % [user, known_hosts])
          end
        end

        verifier.use_agent = false

        verifier
      end

      # Looks for a public key in a shared directory
      def find_shared_public_key(dir, id)
        unless File.directory?(dir)
          raise("Cannot read shared public key directory: '%s'" % dir)
        end

        if File.exists?(key_file = File.join(dir, "#{id}_pub.pem"))
          return File.read(key_file)
        else
          Log.warn("Cannot find public key for id '%s': '%s'" % [id, File.join(dir, "#{id}_pub.pem")])
          raise SecurityValidationFailed
        end
      end

      # Create a node verifier object which uses the correct public key
      def node_verifier(callerid, registration = false, pubkey = nil)
        user = callerid.split('=')[-1]
        verifier = SSH::Key::Verifier.new(user)
        verifier.use_agent = false

        # Here we deal with the special case where a registration message
        # is being validated. send_key has to be defined in the configuration.
        # TODO : This is a stop gap measure we should remove when we fix
        #        registration
        if registration && pubkey
          Log.debug("Found registration message. Using sender's public key")
          verifier.add_public_key_data(pubkey)
          verifier.use_authorized_keys = false

        elsif registration && !pubkey
          Log.warn("Cannot verify registration request. Server did not send its public key")
          raise SecurityValidationFailed

        elsif publickey_dir = lookup_config_option('publickey_dir')
          if File.directory?(publickey_dir)
            Log.debug("Found shared public key directory: '%s'" % publickey_dir)
            verifier.add_public_key_data(find_shared_public_key(publickey_dir, user))
            verifier.use_authorized_keys = false
          else
            raise("Public key directory '%s' does not exist" % publickey_dir)
          end

        elsif (authorized_keys = lookup_config_option('authorized_keys'))
          authorized_keys = authorized_keys.sub('%u') { |c| user }
          Log.debug("Found custom authorized_keys file: '%s'" % authorized_keys)
          verifier.authorized_keys_file = authorized_keys

        else
          begin
            authorized_keys = File.join(Etc.getpwnam(user).dir, '.ssh', 'authorized_keys')
            Log.debug("No authorized_keys file or publickey_dir specified. Using '%s'" % authorized_keys)
            verifier.authorized_keys_file = authorized_keys
          rescue => e
            raise("Cannot find authorized_keys file for user '%s': '%s'" % [user, authorized_keys])
          end
        end

        verifier
      end
    end
  end
end
