#
# Regular cron jobs for the bc-crypto-base package.
#
0 4	* * *	root	[ -x /usr/bin/bc-crypto-base_maintenance ] && /usr/bin/bc-crypto-base_maintenance
