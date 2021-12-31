SHELL = /bin/bash
.SHELLFLAGS := -euo pipefail -c

help: ## Display help
	@awk '{if (sub(/\\$$/,"")) printf "%s", $$0; else print $$0}' $(MAKEFILE_LIST) | awk -F ':|##' \
		'/^[^\t].+?:.*?##/ {printf "\033[31m%-30s\033[0m %s\n", $$1, $$NF}' | LC_ALL=C sort

install: ## Install files
	sudo apt-get install -y python3-dnspython ipset iptables
	sudo install -D -m 755 iptables-ipsets.py /usr/local/bin/iptables-ipsets.py
	sudo install -D -m 644 iptables.service /etc/systemd/system/iptables.service
	if [ ! -e /etc/default/iptables ]; then sudo install -D -m 644 default-iptables /etc/default/iptables; fi
	if [ ! -e /etc/ip6tables.rules ]; then sudo install -D -m 644 ip6tables.rules /etc/ip6tables.rules; fi
	if [ ! -e /etc/iptables.rules ]; then sudo install -D -m 644 iptables.rules /etc/iptables.rules; fi
	sudo systemctl daemon-reload
	sudo systemctl enable iptables
	sudo systemctl restart iptables
