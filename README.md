# MCollective SSH Key Security Plugin

A security plugin that uses ssh keys to sign and validate messages.

## Installation

 * Follow the [basic plugin install guide](http://projects.puppetlabs.com/projects/mcollective-plugins/wiki/InstalingPlugins).
 * You need to have the [sshkeyauth](https://rubygems.org/gems/sshkeyauth) Gem installed.

## Configuration

The sshkey security plugin can be enabled by setting the 'securityprovider' field in both the client and server
configuration files.

    securityprovider = sshkey

## Server configuration

By default a server using the sshkey security plugin will look for a public key in the caller's __authorized_keys__ file and use it
to verify a request. It will respond by signing the reply with its private key. There are, however, a list of options that
can be configured that will change this default behavior.

###private_key

This will change the private key used by the server to sign its replies.

    plugin.sshkey.server.private_key = /etc/ssh/mysupersecretkey

If not set, the private key will first default to '/etc/ssh/ssh_host_dsa_key'. If this file doens't exist, it will try
'/etc/ssh/ssh_host_rsa_key'


###authorized_keys

This will set the authorized_keys file that the server will use to find the client's public key. The
authorized_keys file used will default to /home/bob/.ssh/authorized_keys, where bob is the caller's id.

    plugin.sshkey.server.authorized_keys = /etc/mcollective/my_other_authorized_keys

As in sshd_config(5)'s AuthorizedKeysFile property, the %u sequence will be replaced with the user ID of
the user calling the agent, e.g.

    plugin.sshkey.server.authorized_keys = /etc/admin_authorized_keys/%u

###send_key

This will send the specified public key as part of the reply to the client. This is useful when you do not want to manage
public key distribution by hand (see __learn_private_keys__ option).

    plugin.sshkey.server.send_key = /etc/ssh/ssh_host_rsa_key.pub

If not set, send_key will default to false.

###publickey_dir

Setting this option will cause the server to no longer look for a key in its authorized_keys file and instead look for user
specific public keys inside this directory. These keys will be stored in the format __alice_pub.pem__. When publickey_dir is used in
conjunction with __learn_public_keys__, the server will store newly received public keys in this directory.

    plugin.sshkey.server.publickey_dir = /etc/mcollective/shared_keys

###learn_public_keys

Used in conjunction with __publickey_dir__. This will allow the server to store newly received public keys in
the shared public key directory.

    plugin.sshkey.server.learn_public_keys = 1

If not set, learn_public_keys will default to false.

###overwrite_stored_key

Used in conjunction with __learn_public_keys__ and __publickey_dir__. If set to true, new public keys received from client requests
that do not match the currently stored key will be overwritten, and the new key used.

    plugin.sshkey.server.overwrite_stored_key = true

If not set, overwrite_stored_key will default to false and will __not__ overwrite stored keys.

__Note:__ The publickey_directory and known_hosts configuration options are mutually exclusive and will cause validation to fail
if both are enabled.

## Client configuration

By default clients using the sshkey security plugin will use ssh-agent to sign a request with its private key and validate replies
using the sender's public key found in its __known_hosts__ file. However just like servers, clients can be configured to change this default
behavior.

Clients will by default use the username of the unix user which is logged in, but this can be overridden using the MCOLLECTIVE_SSH_CALLERID environment
variable.

###private_key

Setting this option will cause the client to no longer use ssh-agent and directly look up the private key to sign the request with.
Note that this will not work if the private key has a passphrase set.

    plugin.sshkey.client.private_key = /home/bob/.ssh/id_rsa

If not set, the client will default to using ssh-agent.

###known_hosts

Setting this option will change the known_hosts file that the client will use to identify the server's public key when verifying the reply.

    plugin.sshkey.client.known_hosts = /home/alice/.ssh/my_other_known_hosts

If not set, the client known_hosts file will default to /home/alice/.ssh/known_hosts


###authorized_keys

In cases where the host verificiation step is not required, the client can use a authorized_keys file which will be used to verify the reply.

    plugin.sshkey.client.authorized_keys = /home/bob/.ssh/authorized_keys

###send_key

This will send the specified public key as part of the request to the server. This is useful when you do not want to manage
public key distribution by hand (see __learn_public_keys__)

    plugin.sshkey.client.send_key = /home/bob/.ssh/id_rsa.pub

If not set, send_key will default to false.

###publickey_dir

Setting this option will cause the client to no longer look for a key in its known_hosts file and instead look for host
specific public keys inside this directory. File will be stored in the format __host1.your.com_pub.pem__. When publickey_dir is used in
conjunction with __learn_public_keys__, replies from new hosts that contain their public key which will be written to this
directory. Note that your publickey_dir must be created before using it.

    plugin.sshkey.client.publickey_dir = /home/alice/ssh/shared_keys

###learn_public_keys

Used in conjunction with __publickey_dir__. This will allow the client to store newly received public keys in
the shared public key directory.

    plugin.sshkey.server.learn_public_keys = 1

If not set, learn_public_keys will default to false.

###overwrite_stored_key

Used in conjunction with __send_key__ and __publickey_dir__. If set to true, new public keys received from host replies
that do not match the currently stored key will be overwritten, and the new key used.

    plugin.sshkey.client.overwrite_stored_key = true

If not set, overwrite_stored_key will default to false.

__Note:__ The publickey_directory and known_hosts configuration options are mutually exclusive and will cause validation to fail
if both are enabled.

## Deployment Scenariors

### Default

The default deployment scenario requires nothing to be configured in either the client or server configuration
files, other than setting the security provider. ssh-agent must be running on the client. On the node the sshkey
security plugin will use the authorized_keys file in the calling user's home directory (/home/bob/.ssh/authorized_keys)
for a public key to validate the request with. The node will then check for a DSA key (/etc/ssh/ssh_host_dsa_key)
to sign the reply with, and if no dsa key can be found it will look for an RSA key (/etc/ssh/ssh_host_rsa_key).
The client will then use the caller's known_hosts file (/home/bob/.ssh/known_hosts) to validate the reply.

```
#client
securityprovider = sshkey
```
```
#server
securityprovider = sshkey
```

### Custom private keys

In cases where ssh-agent my not be running on the client or when signing with the default keys on the server might
not be suitable, it is possible to configure a custom private key to do the signing with. You can optionally
supply the passphrase for the key if it has one.

```
#client
securityprovider = sshkey
plugin.sshkey.client.private_key = /home/bob/.ssh/my_other_private_key
plugin.sshkey.client.private_key_passphrase = mypassphrase
```

Alternatively, you can supply the private key file (and optionally passphrase) to the client through an
environment variable.

```
MCOLLECTIVE_SSH_KEY=/home/bob/.ssh/my_other_private_key MCOLLECTIVE_SSH_KEY_PASSPHRASE="examplepass" mco find
```

```
#server
securityprovider = sshkey
plugin.sshkey.server.private_key = /etc/ssh/ssh_host_rsa_key
```

#### Custom known_hosts and authorized_keys files

In cases where using the default files for validation is not suitable, the known_hosts and authorized_keys files
can be configured.

```
#server
securityprovider = sshkey
plugin.sshkey.server.authorized_keys = /etc/ssh/authorized_keys
```

```
#client
securityprovider = sshkey
plugin.sshkey.client.known_hosts = /etc/ssh/known_hosts
```

### Using sshkey with MCollective registration

Using the sshkey security plugin with MCollective registration is non trivial due to that registration requests
are created on the server, which are signed with the server's private key which normally would not be in the
authorized_keys file of the node running the registration agent. However, registration can be used with the
sshkey security plugin by enabling send_key on the server.

This will cause registration messages to be verified with the server's public key. Keys sent during registration
will however __never__ be stored on the node.

```
#server
sercurityprovider = sshkey

# server will sign with its default key, /etc/ssh/ssh_host_dsa_key
plugin.sshkey.server.send_key = /etc/ssh/ssh_host_dsa_key.pub
```

### Manual public key distribution

In cases where using authorized_keys and known_hosts files for validation is not suitable, a shared public key
directory can be used to store keys on the client (alice_pub.pem) or server (host1.your.com_pub.pem).

```
#client
securityprovider = sshkey
plugin.sshkey.client.publickey_dir = /home/alice/.ssh/host_keys
```

```
#server
securityprovider = sshkey
plugin.sshkey.server.publickey_dir = /etc/ssh/user_keys
```

### Automatic public key distribution

In cases where you do not wish to distribute public keys by hand, the sshkey security plugin can be used to do
basic key distribution. In the following configuration snippet the client will sign the key using the default
method, but also send its public key to the server.

The server is then configured to use a shared public key directory and will store new public keys in it.

```
#client
securityprovider = sshkey
plugin.sshkey.client.send_key = /home/alice/.ssh/id_rsa
```

```
#server
securityprovider = sshkey
plugin.sshkey.server.publickey_dir = /etc/ssh/user_keys
plugin.sshkey.server.learn_public_keys = 1
```

This will however only write a key to disk once. If a new key is received, it will not overwrite the stored key.
The following server configuration snippet will allow the server to overwrite stored keys with new ones.

```
#server
securityprovider = sshkey
plugin.sshkey.server.publickey_dir = /etc/ssh/user_keys
plugin.sshkey.server.learn_public_keys = 1
plugin.sshkey.server.overwrite_stored_keys = 1
```

Note that by default the ability to learn and overwrite keys is disabled. Enabling these settings reduces the
security of the sshkey security plugin.
