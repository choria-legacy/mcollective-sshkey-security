# 0.5.1

* Prevent public key overwriting attack via identity (MCOP-600). This was registered as CVE-2017-2298.

# 0.5.0

* Use Etc.getpwuid instead of Etc.getlogin (PR#6)
* Cache the known\_hosts file (PR#8)
* Allow client configuration to be specified by environment variables (PR#7)
* Added pl-packaging (MCOP-370)


# 0.4

Released 2013-08-16

* Allow custom per-identity authorized keys file (#22172)


# 0.3

Release 2013-07-29

* Support ssh keys with multiple aliases (PR#1)


# 0.2

Released 2013-06-25

* Add `authorized_keys` option to client (#21434)
