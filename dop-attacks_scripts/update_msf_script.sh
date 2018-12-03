#!/bin/bash


source config

GDB_SCRIPT=$(mktemp)
TMPFILE=$(mktemp)
SCRIPTFILE="msf_script.rc"

[[ "$EUID" -ne 0 ]] && fail "Please run as root"
[[ -z "${PROCESS}" ]] && fail "Cannot find proftpd, is it running?"

cat <<EOF | tee ${GDB_SCRIPT} > /dev/null
set logging file ${TMPFILE}
set pagination off
set logging on
set logging redirect on
i proc m
quit
EOF

say "executing: gdb -p ${PROCESS} -x ${GDB_SCRIPT}"
gdb -p ${PROCESS} -x ${GDB_SCRIPT} > /dev/null

addr=$(grep 0x700.*libcrypto.so.1.0.0 ${TMPFILE} | awk '{print $1}' | \
	perl -ne "printf(q|0x%x|, hex(\$_) + 1)")
say "updating non_empty_high to ${addr} (in ${SCRIPTFILE})"

cp -f "${SCRIPTFILE}" "${SCRIPTFILE}.bak" 2> /dev/null

cp -f "${SCRIPTFILE}.orig" "${SCRIPTFILE}"
sed -r -i "s/^set non_empty_high\s+.*/set non_empty_high ${addr}/" ${SCRIPTFILE}

diff "${SCRIPTFILE}" "${SCRIPTFILE}.bak"
