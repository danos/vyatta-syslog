SUBDIRS = . tests

share_perl5dir = $(datarootdir)/perl5/Vyatta
etcdir = /etc
modprobedir = /etc/modprobe.d
tmplscriptdir = $(datadir)/tmplscripts
yangdir = /usr/share/configd/yang
vyatta_configdir = /opt/vyatta/etc/config
vyatta_securitydir = /opt/vyatta/etc/security/
rsyslogdir = /opt/vyatta/share/rsyslog-configs

rsyslog_DATA = usr/share/rsyslog-configs/vyatta-action.template

bin_PROGRAMS =
bin_SCRIPTS =
sysconf_DATA =

sbin_SCRIPTS = scripts/system/vyatta_update_syslog.pl
sbin_SCRIPTS += scripts/system/vyatta_syslog_gencerts
sbin_SCRIPTS += scripts/system/vyatta_update_logrotate.pl

share_perl5_DATA = lib/Vyatta/Syslog.pm

cronhourlydir = /etc/cron.hourly
cronhourly_SCRIPTS = sysconf/vyatta-logrotate-hourly

vyatta_config_scriptsdir = /opt/vyatta/etc/config/scripts

cpiop = find  . ! -regex '\(.*~\|.*\.bak\|.*\.swp\|.*\#.*\#\)' -print0 | \
  cpio -0pd

install-exec-hook:
	cd tmplscripts && $(cpiop) $(DESTDIR)$(tmplscriptdir)
	mkdir -p $(DESTDIR)$(yangdir)
	cd yang && $(cpiop) $(DESTDIR)$(yangdir)
