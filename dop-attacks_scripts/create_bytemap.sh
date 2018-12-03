#!/bin/bash


source config

GDB_SCRIPT=$(mktemp)
# SEARCH_START="&main"
SEARCH_START="0x80538ca"
TMPFILE=$(mktemp)
DUMP_SIZE=100000
MAPFILE="byte_map.rb"

[[ "$EUID" -ne 0 ]] && fail "Please run as root"
[[ -z "${PROCESS}" ]] && fail "Cannot find proftpd, is it running?"

[[ -n "${VERBOSE}" ]] && set -x

TMPFILE="raw_${MAPFILE}"
rm -f ${TMPFILE}

say "creating byte_map script in ${GDB_SCRIPT}"

cat <<EOF | tee ${GDB_SCRIPT} > /dev/null
set logging file ${TMPFILE}
set pagination off
set logging on
set logging redirect on
x/${DUMP_SIZE}bx ${SEARCH_START}
quit
EOF

if [[ -z "${PROCESS}" ]]; then
	echo "Cannot find proftpd, is it running?";
	exit
fi

say "executing: gdb -p ${PROCESS} -x ${GDB_SCRIPT}"
gdb -p ${PROCESS} -x ${GDB_SCRIPT} > /dev/null

if [[ ! -e ${TMPFILE} ]]; then
	say "no output from gdb!?!"
	exit;
fi

say "parsing log at ${TMPFILE}, storing bytemap to ${MAPFILE}"
cp -f "${MAPFILE}" "${MAPFILE}.bak" 2> /dev/null
echo "BYTE_MAP = {" > ${MAPFILE}
cat ${TMPFILE} | perl -n  -e "\
	\$d = 0; \
	%found = ();
	while (<>) { \
		m/^0x/ or next; \
		s/^(.*):\s*//; \
		\$a = hex \$1; \
		for my \$h (split /\s+/) { \
			\$found{\$h} or \$found{\$h} = \$a; \
			\$a++; \
		} \
	} \
	for (sort keys %found) { \
		printf qq|\"%x\" => \"%x\",\n|, hex(\$_), \$found{\$_}; \
	} \
	\$count = scalar(keys%found); \
	\$count == 256 or die qq|couldn't populate byte map, found only \$count|;" \
	>> ${MAPFILE}
echo "}" >> ${MAPFILE}

diff "${MAPFILE}" "${MAPFILE}.bak"

say "cleaning up"
rm ${GDB_SCRIPT}
