Linux iptables firewall
========

A firewall using iptables, allowing rule matches based on DNS names. It includes a daemon which keeps ipsets in sync
with changes to DNS entries.

For example, you could add this rule in /etc/iptables.rules:
```
-A OUTPUT -m owner --uid-owner unifi -o enp6s0 -m set --match-set trace.svc.ui.com dst -j REJECT
```

The daemon will automatically create an ipset with the name `trace.svc.ui.com` and add/remove IPs from it based on
updates to the DNS A record(s) (or CNAME record which eventually resolves to A record(s)).

Before installing, please make sure that any other firewalls (e.g. ufw) are deactivated and ideally uninstalled.

To install, run `make install`. At the moment, it is expected that the OS is debian/ubuntu.
