start
$1 = (SSL_CTX **) 0x80de0c8 <ssl_ctx>
$2 = (off_t *) 0x80e0c3c <session+8700>
$3 = (module *) 0x80d3420 <auth_unix_module>
0x80d3420 <auth_unix_module>:	0x080d3020
0x80d3430 <auth_unix_module+16>:	0x080d3450
$4 = (server_rec **) 0x80d6e14 <main_server>
$5 = (<data variable, no debug info> *) 0x80cf4e0
$6 = (char (*)[5120]) 0x80d9020 <resp_buf>
process 6881
Mapped address spaces:

	Start Addr   End Addr       Size     Offset objfile
	 0x8048000  0x80ce000    0x86000        0x0 /usr/local/proftpd-1.3.0/sbin/proftpd
	 0x80ce000  0x80cf000     0x1000    0x85000 /usr/local/proftpd-1.3.0/sbin/proftpd
	 0x80cf000  0x80d5000     0x6000    0x86000 /usr/local/proftpd-1.3.0/sbin/proftpd
	 0x80d5000  0x80e1000     0xc000        0x0 
	 0x9559000  0x959c000    0x43000        0x0 [heap]
	 0x959c000  0x959d000     0x1000        0x0 [heap]
	 0x959d000  0x95bc000    0x1f000        0x0 [heap]
	0xb7233000 0xb723e000     0xb000        0x0 /lib/i386-linux-gnu/libnss_files-2.23.so
	0xb723e000 0xb723f000     0x1000     0xa000 /lib/i386-linux-gnu/libnss_files-2.23.so
	0xb723f000 0xb7240000     0x1000     0xb000 /lib/i386-linux-gnu/libnss_files-2.23.so
	0xb7240000 0xb7247000     0x7000        0x0 
	0xb7247000 0xb7263000    0x1c000        0x0 /lib/i386-linux-gnu/libaudit.so.1.0.0
	0xb7263000 0xb7264000     0x1000    0x1b000 /lib/i386-linux-gnu/libaudit.so.1.0.0
	0xb7264000 0xb7265000     0x1000    0x1c000 /lib/i386-linux-gnu/libaudit.so.1.0.0
	0xb7265000 0xb726f000     0xa000        0x0 
	0xb726f000 0xb7272000     0x3000        0x0 /lib/i386-linux-gnu/libdl-2.23.so
	0xb7272000 0xb7273000     0x1000     0x2000 /lib/i386-linux-gnu/libdl-2.23.so
	0xb7273000 0xb7274000     0x1000     0x3000 /lib/i386-linux-gnu/libdl-2.23.so
	0xb7274000 0xb7275000     0x1000        0x0 
	0xb7275000 0xb7425000   0x1b0000        0x0 /lib/i386-linux-gnu/libc-2.23.so
	0xb7425000 0xb7427000     0x2000   0x1af000 /lib/i386-linux-gnu/libc-2.23.so
	0xb7427000 0xb7428000     0x1000   0x1b1000 /lib/i386-linux-gnu/libc-2.23.so
	0xb7428000 0xb742b000     0x3000        0x0 
	0xb742b000 0xb7439000     0xe000        0x0 /lib/i386-linux-gnu/libpam.so.0.83.1
	0xb7439000 0xb743a000     0x1000     0xd000 /lib/i386-linux-gnu/libpam.so.0.83.1
	0xb743a000 0xb743b000     0x1000     0xe000 /lib/i386-linux-gnu/libpam.so.0.83.1
	0xb743b000 0xb760d000   0x1d2000        0x0 /lib/i386-linux-gnu/libcrypto.so.1.0.0
	0xb760d000 0xb761d000    0x10000   0x1d1000 /lib/i386-linux-gnu/libcrypto.so.1.0.0
	0xb761d000 0xb7624000     0x7000   0x1e1000 /lib/i386-linux-gnu/libcrypto.so.1.0.0
	0xb7624000 0xb7627000     0x3000        0x0 
	0xb7627000 0xb768a000    0x63000        0x0 /lib/i386-linux-gnu/libssl.so.1.0.0
	0xb768a000 0xb768d000     0x3000    0x62000 /lib/i386-linux-gnu/libssl.so.1.0.0
	0xb768d000 0xb7691000     0x4000    0x65000 /lib/i386-linux-gnu/libssl.so.1.0.0
	0xb7691000 0xb769a000     0x9000        0x0 /lib/i386-linux-gnu/libcrypt-2.23.so
	0xb769a000 0xb769b000     0x1000     0x8000 /lib/i386-linux-gnu/libcrypt-2.23.so
	0xb769b000 0xb769c000     0x1000     0x9000 /lib/i386-linux-gnu/libcrypt-2.23.so
	0xb769c000 0xb76c3000    0x27000        0x0 
	0xb76e0000 0xb76e1000     0x1000        0x0 
	0xb76e1000 0xb76e3000     0x2000        0x0 [vvar]
	0xb76e3000 0xb76e5000     0x2000        0x0 [vdso]
	0xb76e5000 0xb7708000    0x23000        0x0 /lib/i386-linux-gnu/ld-2.23.so
	0xb7708000 0xb7709000     0x1000    0x22000 /lib/i386-linux-gnu/ld-2.23.so
	0xb7709000 0xb770a000     0x1000    0x23000 /lib/i386-linux-gnu/ld-2.23.so
	0xbf856000 0xbf877000    0x21000        0x0 [stack]
Symbol "mons.8644" is at 0x80cf6e0 in a file compiled without debugging.
Symbol "open64@plt" is at 0x804b640 in a file compiled without debugging.
A debugging session is active.

	Inferior 1 [process 6881] will be detached.

Quit anyway? (y or n) [answered Y; input not from terminal]
