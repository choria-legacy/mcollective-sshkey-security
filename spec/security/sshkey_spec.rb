#!/usr/bin/env rspec

require 'spec_helper'

module MCollective
  module Security

    # Fixes requirement on sshkeyauth gem during testing
    class Sshkey < Base ;end

    class SSH
      class Key
        class Signer;end
        class Verifier; end
      end
    end

    MCollective::Security::Sshkey.stubs(:gem)
    MCollective::Security::Sshkey.stubs(:require
                                       )
    require File.join(File.dirname(__FILE__), '../../', 'security', 'sshkey.rb')

    describe Sshkey do
      before do
        ENV['MCOLLECTIVE_SSH_CALLERID'] = nil # Make sure to blank these before tests
        ENV['MCOLLECTIVE_SSH_KEY'] = nil
        ENV['MCOLLECTIVE_SSH_KEY_PASSPHRASE'] = nil

        @config = mock("config")
        @config.stubs(:identity).returns("test")
        @config.stubs(:configured).returns(true)
        @config.stubs(:pluginconf).returns({})

        @stats = mock("stats")

        @time = Time.now.to_i
        ::Time.stubs(:now).returns(@time)

        MCollective::Log.stubs(:debug).returns(true)
        MCollective::Log.stubs(:warn).returns(true)

        MCollective::PluginManager << {:type => "global_stats", :class => @stats}
        MCollective::Config.stubs("instance").returns(@config)
        MCollective::Util.stubs("empty_filter?").returns(false)

        @plugin = Sshkey.new
      end

      describe '#decodemsg' do
        let(:msg) { mock }

        before do
          msg.stubs(:payload).returns({:body => 'hello world'})
          Marshal.stubs(:load).with({:body => 'hello world'}).returns({:body => 'hello world'})
        end

        it 'should return the message body if the message is valid' do
          @plugin.stubs(:validrequest?).returns(true)
          Marshal.stubs(:load).with('hello world').returns('hello world')
          @plugin.decodemsg(msg).should == {:body => 'hello world'}
        end

        it 'should return nil if the message is invalid' do
          @plugin.stubs(:validrequest?).returns(false)
          @plugin.decodemsg(msg).should == nil
        end
      end

      describe '#encodereply' do
        let(:hash_fields) do
          {:msg => 'helloworld',
           :msgtime => 123,
           :requestid => 'id123'}
        end

        before do
          Marshal.stubs(:dump).with('hello world').returns('helloworld')
          @plugin.stubs(:create_reply).returns({:hash => nil, :msgtime => 123})
          @plugin.stubs(:create_hash_fields).with('helloworld', 123, 'id123').returns(hash_fields)
          Marshal.stubs(:dump).with(hash_fields).returns(hash_fields)
          @plugin.stubs(:makehash).with(hash_fields).returns('hash')
        end

        it 'should encode a reply' do
          Marshal.expects(:dump).with({:hash => 'hash',
                                       :msgtime => 123,
                                       :serialized_data => hash_fields})
          @plugin.encodereply('rspec', 'hello world', 'id123')
        end

        it 'should add the public key to the reply if configured' do
          @plugin.stubs(:lookup_config_option).with('send_key').returns('id_rsa.pub')
          @plugin.stubs(:load_key).with('id_rsa.pub').returns('ssh-rsa 123')
          File.stubs(:exists?).with('id_rsa.pub').returns(true)
          Marshal.expects(:dump).with({:hash => 'hash',
                                       :serialized_data => hash_fields,
                                       :msgtime => 123,
                                       :public_key => 'ssh-rsa 123'})

          @plugin.encodereply('rspec', 'hello world', 'id123')
        end

        it 'should fail if the public key does not exist' do
          @plugin.stubs(:lookup_config_option).with('send_key').returns('id_rsa.pub')
          @plugin.stubs(:load_key).with('id_rsa.pub').returns('ssh-rsa 123')
          File.stubs(:exists?).with('id_rsa.pub').returns(false)

          expect{
            @plugin.encodereply('rspec', 'hello world', 'id123')
          }.to raise_error
        end
      end

      describe '#encoderequest' do
        let(:hash_fields) do
          {:msg => 'helloworld',
           :msgtime => 123,
           :requestid => 'id123',
           :ttl => 10,
           :callerid => 'caller=rspec'}
        end

        before do
          Marshal.stubs(:dump).with('hello world').returns('helloworld')
          @plugin.stubs(:create_request).returns({:hash => nil, :msgtime => 123})
          @plugin.stubs(:callerid).returns('caller=rspec')
          @plugin.stubs(:create_hash_fields).with('helloworld', 123, 'id123', 10, 'caller=rspec').returns(hash_fields)
          Marshal.stubs(:dump).with(hash_fields).returns(hash_fields)
          @plugin.stubs(:makehash).with(hash_fields).returns('hash')
        end

        it 'should encode a request' do
          Marshal.expects(:dump).with({:hash => 'hash', :msgtime => 123, :serialized_data => hash_fields})
          @plugin.encoderequest('rspec', 'hello world', 'id123', [], 'rspec_agent', 'rspec/collective', 10)

        end

        it 'should add the public key to the request if configued' do
          @plugin.stubs(:lookup_config_option).with('send_key').returns('id_rsa.pub')
          @plugin.stubs(:load_key).with('id_rsa.pub').returns('ssh-rsa 123')
          File.stubs(:exists?).with('id_rsa.pub').returns(true)
          Marshal.expects(:dump).with({:hash => 'hash',
                                       :serialized_data => hash_fields,
                                       :msgtime => 123,
                                       :public_key => 'ssh-rsa 123'})
          @plugin.encoderequest('rspec', 'hello world', 'id123', [], 'rspec_agent', 'rspec/collective', 10)
        end

        it 'should fail if the public key does not exist' do
          @plugin.stubs(:lookup_config_option).with('send_key').returns('id_rsa.pub')
          @plugin.stubs(:load_key).with('id_rsa.pub').returns('ssh-rsa 123')
          File.stubs(:exists?).with('id_rsa.pub').returns(false)

          expect{
            @plugin.encoderequest('rspec', 'hello world', 'id123', [], 'rspec_agent', 'rspec/collective', 10)
          }.to raise_error
        end
      end

      describe '#validrequest?' do
        let(:verifier) { mock }

        before do
          @plugin.stubs(:valid_configuration?)
          @plugin.stubs(:write_key_to_disk)
          @plugin.stubs(:create_hash_fields).returns({})
          Marshal.stubs(:load).with('hash').returns('signatures')
        end

        it 'should validate node replies' do
          @plugin.instance_variable_set(:@initiated_by, :client)
          @plugin.stubs(:client_verifier).with('host1.your.com').returns(verifier)
          verifier.stubs(:verify?).with('signatures', 'data').returns(true)
          @stats.expects(:validated)

          @plugin.validrequest?({:senderid => 'host1.your.com', :hash => 'hash', :serialized_data => 'data'}).should be_true
        end

        it 'should validate client requests' do
          @plugin.instance_variable_set(:@initiated_by, :node)
          @plugin.stubs(:node_verifier).with('caller=rspec', false, nil).returns(verifier)
          verifier.stubs(:verify?).with('signatures', 'data').returns(true)
          @stats.expects(:validated)

          @plugin.validrequest?({:callerid => 'caller=rspec', :hash => 'hash', :serialized_data => 'data'}).should be_true
        end

        it 'should validate registration requests' do
          @plugin.instance_variable_set(:@initiated_by, :node)
          @plugin.expects(:node_verifier).with('caller=rspec', true, 'ssh-rsa 123').returns(verifier)
          verifier.stubs(:verify?).with('signatures', 'data').returns(true)
          @stats.expects(:validated)
          @plugin.validrequest?({:callerid => 'caller=rspec',
                                :hash => 'hash',
                                :serialized_data => 'data',
                                :agent => 'registration',
                                :public_key => 'ssh-rsa 123'}).should be_true

        end

        it 'should fail on unverified messages' do
          @plugin.instance_variable_set(:@initiated_by, :node)
          @plugin.stubs(:node_verifier).with('caller=rspec', false, nil).returns(verifier)
          verifier.stubs(:verify?).with('signatures', 'data').returns(false)
          @stats.expects(:unvalidated)

          expect{
            @plugin.validrequest?({:callerid => 'caller=rspec', :hash => 'hash', :serialized_data => 'data'}).should be_true
          }.to raise_error SecurityValidationFailed
        end
      end

      describe '#callerid' do
        context 'no environment variable' do
          it 'should return the callerid in the correct format' do
            passwd = mock('passwd')
            passwd.stubs(:name).returns('rspec')
            Etc.stubs(:getpwuid).returns(passwd)
            @plugin.callerid.should == 'sshkey=rspec'
          end
        end
        context 'with environment variable' do
          it 'should return the callerid in the correct format' do
            ENV['MCOLLECTIVE_SSH_CALLERID'] = 'rspec2'
            @plugin.callerid.should == 'sshkey=rspec2'
          end
        end
      end

      describe '#valid_configuration?' do
        it 'should not raise an exception if the client has a valid configuration' do
          @plugin.instance_variable_set(:@initiated_by, :client)
          @plugin.stubs(:lookup_config_option).with('publickey_dir').returns(true)
          @plugin.stubs(:lookup_config_option).with('known_hosts').returns(false)
          @plugin.send(:valid_configuration?)
        end

        it 'should not raise an exception if the server has a valid configuration' do
          @plugin.instance_variable_set(:@initiated_by, :node)
          @plugin.stubs(:lookup_config_option).with('publickey_dir').returns(false)
          @plugin.stubs(:lookup_config_option).with('authorized_keys').returns(true)
          @plugin.send(:valid_configuration?)
        end

        it 'should raise an exception if the client configuration is invalid' do
          @plugin.instance_variable_set(:@initiated_by, :client)
          @plugin.stubs(:lookup_config_option).with('publickey_dir').returns(true)
          @plugin.stubs(:lookup_config_option).with('known_hosts').returns(true)

          expect{
            @plugin.send(:valid_configuration?)
          }.to raise_error
        end

        it 'should raise an exception if the server configuration is invalid' do
          @plugin.instance_variable_set(:@initiated_by, :node)
          @plugin.stubs(:lookup_config_option).with('publickey_dir').returns(true)
          @plugin.stubs(:lookup_config_option).with('authorized_keys').returns(true)

          expect{
            @plugin.send(:valid_configuration?)
          }.to raise_error
        end
      end

      describe '#write_key_to_disk' do
        it 'should return if storing public keys is not enabled' do
          @plugin.stubs(:lookup_config_option).with('learn_public_keys').returns(nil)
          File.expects(:dictory?).never
          @plugin.send(:write_key_to_disk, '', '')
        end

        it 'should fail if publicikey_dir does not exist' do
          @plugin.stubs(:lookup_config_option).with('learn_public_keys').returns('1')
          @plugin.stubs(:lookup_config_option).with('publickey_dir').returns('ssh/pkd')
          File.stubs(:directory?).with('ssh/pkd').returns(false)

          expect{
            @plugin.send(:write_key_to_disk, '', '')
          }.to raise_error
        end

        it 'should fail if identity would result in directory traversal' do
          @plugin.stubs(:lookup_config_option).with('learn_public_keys').returns('1')
          @plugin.stubs(:lookup_config_option).with('publickey_dir').returns('ssh/pkd')
          File.stubs(:directory?).with('ssh/pkd').returns(true)
          Log.expects(:warn)
          File.expects(:open).never
          @plugin.send(:write_key_to_disk, 'ssh-rsa abcd', '../test')
        end

        it 'should write the public key to disk if its the first time its been seen' do
          @plugin.stubs(:lookup_config_option).with('learn_public_keys').returns('1')
          @plugin.stubs(:lookup_config_option).with('publickey_dir').returns('ssh/pkd')
          File.stubs(:directory?).with('ssh/pkd').returns(true)
          full_path = File.join(File.expand_path('ssh/pkd'), 'rspec_pub.pem')
          File.stubs(:exists?).with(full_path).returns(false)
          file = mock
          File.expects(:open).with(full_path, 'w').yields(file)
          file.expects(:puts).with('ssh-rsa abcd')
          @plugin.send(:write_key_to_disk, 'ssh-rsa abcd', 'rspec')
        end

        it 'should not overwrite an existing file if overwrite_stored_key is not set' do
          @plugin.stubs(:lookup_config_option).with('learn_public_keys').returns('1')
          @plugin.stubs(:lookup_config_option).with('publickey_dir').returns('ssh/pkd')
          @plugin.stubs(:lookup_config_option).with('overwrite_stored_keys', 'n').returns('n')
          File.stubs(:directory?).with('ssh/pkd').returns(true)
          full_path = File.join(File.expand_path('ssh/pkd'), 'rspec_pub.pem')
          File.stubs(:exists?).with(full_path).returns(true)
          File.stubs(:read).with(full_path).returns('ssh-rsa dcba')
          Log.expects(:warn)
          File.expects(:open).never
          @plugin.send(:write_key_to_disk, 'ssh-rsa abcd', 'rspec')
        end

        it 'should overwrite the existing public key if overwrite_stored_key is set' do
          @plugin.stubs(:lookup_config_option).with('learn_public_keys').returns('1')
          @plugin.stubs(:lookup_config_option).with('publickey_dir').returns('ssh/pkd')
          @plugin.stubs(:lookup_config_option).with('overwrite_stored_keys', 'n').returns('1')
          File.stubs(:directory?).with('ssh/pkd').returns(true)
          full_path = File.join(File.expand_path('ssh/pkd'), 'rspec_pub.pem')
          File.stubs(:exists?).with(full_path).returns(true)
          File.stubs(:read).with(full_path).returns('ssh-rsa dcba')
          file = mock
          File.expects(:open).with(full_path, 'w').yields(file)
          file.expects(:puts).with('ssh-rsa abcd')
          Log.expects(:warn)
          @plugin.send(:write_key_to_disk, 'ssh-rsa abcd', 'rspec')
        end
      end

      describe "lookup_config_option" do
        it 'should lookup a client config option' do
          @plugin.instance_variable_set(:@initiated_by, :client)
          @config.stubs(:pluginconf).returns({'sshkey.client.rspec' => '1'})
          @plugin.send(:lookup_config_option, 'rspec').should == '1'
        end

        it 'lookup a server config option' do
          @plugin.instance_variable_set(:@initiated_by, :node)
          @config.stubs(:pluginconf).returns({'sshkey.server.rspec' => '1'})
          @plugin.send(:lookup_config_option, 'rspec').should == '1'
        end

        it 'should return the default if the config option is not set' do
          @plugin.instance_variable_set(:@initiated_by, :client)
          @plugin.send(:lookup_config_option, 'rspec').should be_nil
        end

        it 'should return the supplied default if the config option is not set' do
          @plugin.instance_variable_set(:@initiated_by, :client)
          @plugin.send(:lookup_config_option, 'rspec' , '2').should == '2'
        end

        it 'should expand tildas in paths for client options' do
          @plugin.instance_variable_set(:@initiated_by, :client)
          File.expects(:expand_path).with('~/publickey_dir').returns('/home/rspec/publickey_dir')
          @config.stubs(:pluginconf).returns({'sshkey.client.publickey_dir' => '~/publickey_dir'})
          @plugin.send(:lookup_config_option, 'publickey_dir' , '2').should == '/home/rspec/publickey_dir'
        end

      end

      describe '#create_hash_fields' do
        it 'should return the correct map for a request hash' do
          result = @plugin.send(:create_hash_fields, 'hello', 123, 'id', 60, 'rspec')
          result.should == {:msg => 'hello',
                            :msgtime => 123,
                            :requestid => 'id',
                            :ttl => 60,
                            :callerid => 'rspec'}

        end

        it 'should return the correct map for a reply hash' do
          result = @plugin.send(:create_hash_fields, 'hello', 321, 'id')
          result.should == {:msg => 'hello',
                            :msgtime => 321,
                            :requestid => 'id'}
        end

      end

      describe '#add_key_to_signer' do
        let(:signer) { mock }
        context 'no pass phrase' do
          it 'should add a key file to a signer' do
            signer.expects(:add_key_file).with('ssh/key')
            signer.expects(:use_agent=).with(false)

            @plugin.send(:add_key_to_signer, signer, 'ssh/key')
          end
          it 'should add a key to a signer when passphrase is nil' do
            signer.expects(:add_key_file).with('ssh/key')
            signer.expects(:use_agent=).with(false)

            @plugin.send(:add_key_to_signer, signer, 'ssh/key', nil)
          end
        end
        context 'with pass phrase' do
          it 'should add a key file to a signer' do
            signer.expects(:add_key_file).with('ssh/key', 'mypassphrase')
            signer.expects(:use_agent=).with(false)

            @plugin.send(:add_key_to_signer, signer, 'ssh/key', 'mypassphrase')
          end
        end
      end

      describe '#makehash' do
        let(:signer) { mock }
        let(:signature) { mock }

        before do
          SSH::Key::Signer.stubs(:new).returns(signer)
          signer.stubs(:sign).returns([signature])
          signature.stubs(:signature).returns('123')
          Marshal.stubs(:dump).with(['123']).returns('hash')
        end


        it 'should create the correct client hash using ssh-agent' do
          @plugin.stubs(:initiated_by).returns(:client)
          @plugin.send(:makehash, {}).should == 'hash'
        end

        context 'client hash' do
          before do
            @plugin.instance_variable_set(:@initiated_by, :client)
            @plugin.stubs(:lookup_config_option).with('private_key').returns('id_rsa')
            File.stubs(:exists?).with('id_rsa').returns(true)
          end

          it 'should create the correct client hash using a specified private key' do
            @plugin.stubs(:lookup_config_option).with('private_key_passphrase').returns(nil)
            @plugin.expects(:add_key_to_signer).with(signer, 'id_rsa', nil)

            @plugin.send(:makehash, {}).should == 'hash'
          end

          it 'should create the correct client hash using a specified private key and passphrase' do
            @plugin.stubs(:lookup_config_option).with('private_key_passphrase').returns('mypassphrase')
            @plugin.expects(:add_key_to_signer).with(signer, 'id_rsa', 'mypassphrase')

            @plugin.send(:makehash, {}).should == 'hash'
          end
        end


        it 'should create the correct client hash using private key from environment' do
          @plugin.instance_variable_set(:@initiated_by, :client)
          @plugin.expects(:add_key_to_signer).with(signer, 'id_rsa', nil)
          ENV['MCOLLECTIVE_SSH_KEY'] = 'id_rsa'

          @plugin.send(:makehash, {}).should == 'hash'
        end

        it 'should create the correct client hash using private key and pass phrase from environment' do
          @plugin.instance_variable_set(:@initiated_by, :client)
          @plugin.expects(:add_key_to_signer).with(signer, 'id_rsa', 'mypassphrase')
          ENV['MCOLLECTIVE_SSH_KEY'] = 'id_rsa'
          ENV['MCOLLECTIVE_SSH_KEY_PASSPHRASE'] = 'mypassphrase'

          @plugin.send(:makehash, {}).should == 'hash'
        end

        it 'should create the correct server hash using a specified private key' do
          @plugin.instance_variable_set(:@initiated_by, :node)
          @plugin.stubs(:lookup_config_option).with('private_key').returns('id_rsa')
          File.stubs(:exists?).with('id_rsa').returns(true)
          @plugin.expects(:add_key_to_signer).with(signer, 'id_rsa')

          @plugin.send(:makehash, {}).should == 'hash'
        end

        it 'should create the correct server hash using the default private key' do
          @plugin.instance_variable_set(:@initiated_by, :node)
          File.stubs(:exists?).with('/etc/ssh/ssh_host_dsa_key').returns(true)
          signer.expects(:add_key_file).with('/etc/ssh/ssh_host_dsa_key')
          signer.expects(:use_agent=).with(false)

          @plugin.send(:makehash, {}).should == 'hash'
        end

        it 'should create the correct server hash using the fallback default private key' do
          @plugin.instance_variable_set(:@initiated_by, :node)
          File.stubs(:exists?).with('/etc/ssh/ssh_host_dsa_key').returns(false)
          File.stubs(:exists?).with('/etc/ssh/ssh_host_rsa_key').returns(true)
          signer.expects(:add_key_file).with('/etc/ssh/ssh_host_rsa_key')
          signer.expects(:use_agent=).with(false)

          @plugin.send(:makehash, {}).should == 'hash'
        end

        it 'should fail if the client private key cannot be found' do
          @plugin.instance_variable_set(:@initiated_by, :client)
          @plugin.stubs(:lookup_config_option).with('private_key').returns('id_rsa')
          File.stubs(:exists?).with('id_rsa').returns(false)

          expect{
            @plugin.send(:makehash, {}).should == 'hash'
          }.to raise_error
        end

        it 'should fail if the server private key cannot be found' do
          @plugin.instance_variable_set(:@initiated_by, :node)
          @plugin.stubs(:lookup_config_option).with('private_key').returns(nil)
          File.stubs(:exists?).with('/etc/ssh/ssh_host_dsa_key').returns(false)
          File.stubs(:exists?).with('/etc/ssh/ssh_host_rsa_key').returns(false)

          expect{
            @plugin.send(:makehash, {}).should == 'hash'
          }.to raise_error
        end
      end

      describe '#loadkey' do
        it 'should return the content of a key file if it exists' do
          File.stubs(:exists?).with('ssh/rspec.pub').returns(true)
          File.stubs(:read).with('ssh/rspec.pub').returns('ssh-rsa 123')
          result = @plugin.send(:load_key, 'ssh/rspec.pub')
          result.should == 'ssh-rsa 123'
        end

        it 'should return nil if the file cannot be found' do
          File.stubs(:exists?).with('ssh/rspec.pub').returns(false)
          @plugin.send(:load_key, 'ssh/rspec.pub').should be_nil
        end
      end

      describe '#find_key_in_known_hosts' do
        it 'should return the key if it was found in the known_hosts file' do
          File.stubs(:exists?).with('known_hosts').returns(true)
          File.stubs(:mtime).with('known_hosts').returns(1)
          File.stubs(:read).with('known_hosts').returns('rspec.com,192.167.1.1 ssh-rsa 123')

          result = @plugin.send(:find_key_in_known_hosts, 'rspec.com', 'known_hosts')
          result.should == 'ssh-rsa 123'

          File.stubs(:read) do
            raise_error(Spec::Expectations::ExpectationNotMetError, 'Should not try to re-read known_hosts file')
          end

          result = @plugin.send(:find_key_in_known_hosts, '192.167.1.1', 'known_hosts')
          result.should == 'ssh-rsa 123'

          File.stubs(:mtime).with('known_hosts').returns(2)
          File.stubs(:read).with('known_hosts').returns('rspec.com,192.167.1.1 ssh-rsa 456')
          result = @plugin.send(:find_key_in_known_hosts, '192.167.1.1', 'known_hosts')
          result.should == 'ssh-rsa 456'
        end

        it 'should fail if the key cannot be found' do
          File.stubs(:exists?).with('known_hosts').returns(false)

          expect{
            @plugin.send(:find_key_in_known_hosts, 'rspec.com', 'known_hosts')
          }.to raise_error
        end

        it 'should not fail if the ssh_known_hosts file contains garbage' do
          File.stubs(:exists?).with('known_hosts').returns(true)
          File.stubs(:mtime).with('known_hosts').returns(1)
          File.stubs(:read).with('known_hosts').returns("other_example_host.dev############################################################\nrspec.com,192.167.1.1 ssh-rsa 123")

          result = @plugin.send(:find_key_in_known_hosts, 'rspec.com', 'known_hosts')
          result.should == 'ssh-rsa 123'
        end
      end


      describe '#client_verifier' do
        let(:client_verifier) { mock }

        before do
          SSH::Key::Verifier.stubs(:new).with('host1.your.com').returns(client_verifier)
          passwd = mock('passwd')
          passwd.stubs(:name).returns('rspec')
          Etc.stubs(:getpwuid).returns(passwd)
          client_verifier.stubs(:use_agent=).with(false)
          client_verifier.stubs(:use_authorized_keys=).with(false)
        end

        it 'should return a verifier that uses the default known_hosts' do
          @plugin.stubs(:lookup_config_option).with('publickey_dir').returns(false)
          @plugin.stubs(:lookup_config_option).with('known_hosts').returns(false)
          @plugin.stubs(:lookup_config_option).with('authorized_keys').returns(false)
          client_verifier.expects(:add_public_key_data).with('ssh-rsa 123')
          pw = mock
          pw.stubs(:dir).returns('/home/rspec')
          Etc.stubs(:getpwnam).returns(pw)
          @plugin.expects(:find_key_in_known_hosts).with('host1.your.com', '/home/rspec/.ssh/known_hosts').returns('ssh-rsa 123')
          @plugin.send(:client_verifier, 'host1.your.com').should == client_verifier
        end

        it 'should return a verifier uses a specified known_hosts file' do
          @plugin.stubs(:lookup_config_option).with('publickey_dir').returns(false)
          @plugin.stubs(:lookup_config_option).with('known_hosts').returns('ssh/known_hosts')
          client_verifier.expects(:add_public_key_data).with('ssh-rsa 123')
          @plugin.stubs(:find_key_in_known_hosts).with('host1.your.com', 'ssh/known_hosts').returns('ssh-rsa 123')
          @plugin.send(:client_verifier, 'host1.your.com').should == client_verifier
        end

        it 'should return a verifier that uses an authorized_keys file' do
          @plugin.stubs(:lookup_config_option).with('publickey_dir').returns(false)
          @plugin.stubs(:lookup_config_option).with('known_hosts').returns(false)
          @plugin.stubs(:lookup_config_option).with('authorized_keys').returns('ssh/authorized_keys')
          client_verifier.expects(:use_authorized_keys=).with(true)
          client_verifier.expects(:authorized_keys_file=).with('ssh/authorized_keys')
          @plugin.send(:client_verifier, 'host1.your.com').should == client_verifier
        end

        it 'should return a verifier that loads a public key from disk' do
          @plugin.stubs(:lookup_config_option).with('publickey_dir').returns('ssh/known_hosts')
          @plugin.stubs(:find_shared_public_key).with('ssh/known_hosts', 'host1.your.com').returns('ssh-rsa 123')
          client_verifier.expects(:add_public_key_data).with('ssh-rsa 123')
          @plugin.send(:client_verifier, 'host1.your.com').should == client_verifier
        end

      end

      describe '#find_shared_public_key' do
        it 'should fail if the publickey_directory does not exist' do
          File.stubs(:directory?).with('ssh/pkd').returns(false)

          expect{
            @plugin.send(:find_shared_public_key, 'ssh/pkd', 'rspec')
          }.to raise_error
        end

        it 'should fail if the file in the publickey_directory does not exist' do
          File.stubs(:directory?).with('ssh/pkd').returns(false)
          File.stubs(:exists?).with('ssh/pkd/rspec.ssh').returns(false)

          expect{
            @plugin.send(:find_shared_public_key, 'ssh/pkd', 'rspec')
          }.to raise_error
        end

        it 'should return the contents of the public key' do
          File.stubs(:directory?).with('ssh/pkd').returns(true)
          File.stubs(:exists?).with('ssh/pkd/rspec_pub.pem').returns(true)
          File.stubs(:read).with('ssh/pkd/rspec_pub.pem').returns('ssh-rsa 123')

          result = @plugin.send(:find_shared_public_key, 'ssh/pkd', 'rspec')
          result.should == 'ssh-rsa 123'
        end
      end

      describe '#node_verifier' do
        let(:node_verifier) { mock }

        before do
          SSH::Key::Verifier.stubs(:new).with('rspec').returns(node_verifier)
        end

        it 'should return a verifier using the default authorized_keys file' do
          @plugin.stubs(:lookup_config_option).with('publickey_dir').returns(false)
          @plugin.stubs(:lookup_config_option).with('authorized_keys').returns(false)
          pw = mock
          Etc.stubs(:getpwnam).with('rspec').returns(pw)
          pw.stubs(:dir).returns('/home/rspec')
          node_verifier.expects(:authorized_keys_file=).with('/home/rspec/.ssh/authorized_keys')
          node_verifier.expects(:use_agent=).with(false)
          @plugin.send(:node_verifier, 'caller=rspec', nil, nil).should == node_verifier
        end

        it 'should return a verifier using the specified authorized_keys file' do
          @plugin.stubs(:lookup_config_option).with('publickey_dir').returns(false)
          @plugin.stubs(:lookup_config_option).with('authorized_keys').returns('ssh/authorized_keys')
          node_verifier.expects(:authorized_keys_file=).with('ssh/authorized_keys')
          node_verifier.expects(:use_agent=).with(false)
          @plugin.send(:node_verifier, 'caller=rspec', nil, nil).should == node_verifier
        end

        it 'should return a verifier having interpolcated %u into authorized_keys file path' do
          @plugin.stubs(:lookup_config_option).with('publickey_dir').returns(false)
          @plugin.stubs(:lookup_config_option).with('authorized_keys').returns('ssh/%u/authorized_keys')
          node_verifier.expects(:authorized_keys_file=).with('ssh/rspec/authorized_keys')
          node_verifier.expects(:use_agent=).with(false)
          @plugin.send(:node_verifier, 'caller=rspec', nil, nil).should == node_verifier
        end

        it 'should return a verifier with a public key loaded directly from disk' do
          @plugin.stubs(:lookup_config_option).with('publickey_dir').returns('ssh/authorized_keys')
          File.expects(:directory?).with('ssh/authorized_keys').returns(true)
          @plugin.stubs(:find_shared_public_key).with('ssh/authorized_keys', 'rspec').returns('ssh-rsa 123')
          node_verifier.expects(:add_public_key_data).with('ssh-rsa 123')
          node_verifier.expects(:use_authorized_keys=).with(false)
          node_verifier.expects(:use_agent=).with(false)
          @plugin.send(:node_verifier, 'caller=rspec', nil, nil).should == node_verifier
        end

        it 'should fail if the default authorized_keys file does not exist' do
          @plugin.stubs(:lookup_config_option).with('publickey_dir').returns(false)
          @plugin.stubs(:lookup_config_option).with('authorized_keys').returns(false)
          Etc.stubs(:getpwnam).raises('error')

          expect{
            @plugin.send(:node_verifier, 'caller=rspec', nil, nil)
          }.to raise_error
        end

        it 'should fail for registration messages that do not pass a key' do
          expect{
            @plugin.send(:node_verifier, 'caller=rspec', true, nil)
          }.to raise_error
        end

        it 'should return a verfier for a registration request' do
          node_verifier.expects(:use_agent=).with(false)
          node_verifier.expects(:add_public_key_data).with('ssh-rsa 123')
          node_verifier.expects(:use_authorized_keys=).with(false)
          @plugin.send(:node_verifier, 'caller=rspec', true, 'ssh-rsa 123').should == node_verifier
        end
      end
    end
  end
end
