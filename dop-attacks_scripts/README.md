# ProFTP Data-Oriented Programming attack - MODIFIED

This is a modified version of the ProfFTP Data Oriented Programming PoC by [Hong
et al.][1].

## Installation & use

The following assumes an unmodified `config` file. Please run `bash ./config` to
view current setup or just edit the file as needed. Variables like
`$FTPINSTALLDIR` below are defined in the config file.

### Installing metasploit

The scripts currently expect `msfconsole` to be runnable from the `$PATH`, or to
be installed either under `~/Downloads/metasploit-framework` or
`~/git/metasploit-framework`. If running from installation directory the script
also attempts to initialize RVM, if installed under `~/.rvm`. 

You can follow [Setting Up a Metasploit Development Environment][2] to install
to install metasploit if unavailable.

### Installation of ProFTP

The setup scripts rely on debug symbols being available in the running `proftpd`
binary. To do this, apply the following changes to `Make.rules` before running
`make install`

```sh
22,23c22,23
< INSTALL_BIN=$(INSTALL) -s -o $(INSTALL_USER) -g $(INSTALL_GROUP) -m 0755
< INSTALL_SBIN=$(INSTALL) -s -o $(INSTALL_USER) -g $(INSTALL_GROUP) -m 0755
---
> INSTALL_BIN=$(INSTALL) -o $(INSTALL_USER) -g $(INSTALL_GROUP) -m 0755
> INSTALL_SBIN=$(INSTALL) -o $(INSTALL_USER) -g $(INSTALL_GROUP) -m 0755
```

Otherwise follow instructions from [Hong et al.][1]. In particular, do use
the provided `config_cmd.sh` to create an appropriate build configuration.

### Preparing the exploit

Setup the `ftptest` user with a default password of `ftptest`, then run the
following setup scripts:

```sh
sudo ./ftp_restart.sh
sudo ./create_addrmap.sh
sudo ./create_bytemap.sh
sudo ./update_msf_script.sh
```

`ftp_restart.sh` kills any running `proftpd` processes. Then it removes and
recreates `/home/ftptest`. Before starting the ftp daemon it also disables ASLR,
it then executes `$FTPINSTALLDIR/sbin/proftpd` and re-enables finally restores
the initial ASLR configuration (in `/proc/sys/kernel/randomize_va_spaze`).

`create_addrmap.sh` attaches gdb to the ftp server daemon `$PROCESS` and
executes a script that attempts to retrieve various target memory addresses from
the running binary. Results are stored in `addr_map.rb`.

`create_bytemap.sh` attaches gdb to the ftp server daemon `$PROCESS` and
executes a script that attempts to find addresses for single bytes that contains
the values ranging from 0 - 255. Results are stored in `byte_map.rb`.

`update_msf_script.sh` attaches gdb to the ftp server daemon `$PROCESS` and
executes a script that finds the address for `NON_EMPTY_HIGH`. This value is can
depend on ASLR, which means that the scripts needs to be re-run for each
instance unless ASLR is disabled.

### Executing the attack

Provided that the preparatory scripts above executed without fault (i.e., they
managed to map all the required addresses), the exploit can now be executed by
running:

```sh
./run_exploit.sh
```

The script kills any existing `proftpd` instances, resets the `$FTPHOME`
directory and disables ASLR. It then locates `msfconsole` and executes
`msfconsole -r msf_script.rc`. After the attack is completed ASLR is re-enabled
and any remaining `proftpd` instances are killed.

Note: if you wish to run with ASLR you can manually execute `msfconsole -r
msf_script.rc`, this however also requires that you manually execute `proftpd`
and update the `non_empty_high` variable (potentially by running the
`update_msf_script.sh` script).

## Bugs and caveats

The setup scripts update many potentially changing target addresses, but they
still in some cases rely on specific memory-layouts. For instance, the `EMPTY`
and `NON_EMPTY_HIGH` updates rely on specific memory-layout at the `open64@plt`.
The attack itself also relies on specific memory-layouts for the `ssl_ctx` data
structure and potentially others.


[1]: https://huhong-nus.github.io/advanced-DOP/ "Hong, et al. ``Data-oriented programming: On the expressiveness of non-control data attacks.'' Security and Privacy (SP), 2016 IEEE Symposium on. IEEE, 2016." 
[2]: https://github.com/rapid7/metasploit-framework/wiki/Setting-Up-a-Metasploit-Development-Environment "Setting Up a Metasploit Development Environment"
