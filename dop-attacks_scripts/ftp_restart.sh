#!/bin/bash


source config

proftpd=${FTPINSTALLDIR}/sbin/proftpd

[[ "$EUID" -ne 0 ]] && fail "Please run as root"

# Make sure we actually have a FTPHOME... :|
# and do this without fancy stuff to make sure it works...
if [[ -z "${FTPHOME}" ]]; then
	echo "no FTPHOME defined"
	exit
fi

say "killing any existing proftpd processes"
killall proftpd
killall -9 proftpd 2> /dev/null

say "resetting ${FTPHOME}"
rm -rf $FTPHOME
mkdir $FTPHOME
mkdir $FTPHOME/etc
echo "other password required /pam_bla.so" > ${FTPHOME}/etc/pam.conf
chown ftptest:ftptest $FTPHOME
chown -R ftptest:ftptest ${FTPHOME}/*

RANDOMIZE_VA_SPACE=$(cat /proc/sys/kernel/randomize_va_space)
say "diabling /proc/sys/kernel/randomize_va_space (was ${RANDOMIZE_VA_SPACE})"
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

say "starting ${proftpd}"
${proftpd}

say "setting /proc/sys/kernel/randomize_va_space back to ${RANDOMIZE_VA_SPACE}), press to continue"
read
echo ${RANDOMIZE_VA_SPACE} | sudo tee /proc/sys/kernel/randomize_va_space
