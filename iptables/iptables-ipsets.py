#!/usr/bin/env python3

import argparse
import datetime
import logging
import re
import subprocess
import sys
import time

from dns import exception
import dns.resolver
from dns.resolver import NoAnswer, NXDOMAIN

LOG = logging.getLogger()


class TemporaryFailure(Exception):
    pass


class Query:
    def __init__(self, resolv_conf_file, dns_servers=None):
        self.resolver = dns.resolver.Resolver(configure=False)
        if dns_servers:
            self.resolver.nameservers = dns_servers
        else:
            self.resolver.read_resolv_conf(resolv_conf_file)

    def get_ips(self, name, timeout=3):
        try:
            ans = self.resolver.query(name, lifetime=timeout)
        except (NXDOMAIN, NoAnswer):
            return []
        except exception.Timeout:
            LOG.error('Timeout resolving: %s', name)
            raise TemporaryFailure(f'Timeout resolving: {name}') from None

        return {x.to_text() for x in ans}


def loop():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--debug', '-d', default=False, action='store_true', help='Enable debug output.')
    parser.add_argument('--dns', action='append', help='Use these dns servers instead of resolv.conf.')
    parser.add_argument('--init', default=False, action='store_true', help='Create ipsets but do not do DNS lookups.')
    parser.add_argument('--iptables-rules', default='/etc/iptables.rules', help='Location of iptables rules file.')
    parser.add_argument('--loop-sleep', default=3, type=int, help='Sleep this many seconds between loops.')
    parser.add_argument('--once', '-1', default=False, action='store_true', help='Run only once.')
    parser.add_argument(
        '--purge-timeout', default=1800, type=int, help='Time after which old IP entries will be removed.'
    )
    parser.add_argument('--query-timeout', default=10, type=int, help='DNS query timeout in seconds.')
    parser.add_argument('--resolv-conf', default='/etc/resolv.conf', help='Location of resolv.conf file.')
    args = parser.parse_args()

    if args.debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO

    formatter = logging.Formatter(fmt='%(asctime)s %(levelname)s %(message)s', datefmt='%H:%M:%S')
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setFormatter(formatter)
    stderr_handler.setLevel(log_level)
    LOG.addHandler(stderr_handler)
    LOG.setLevel(log_level)

    match_set_re = re.compile(' --match-set ([^ ]+) ')
    query = Query(args.resolv_conf, dns_servers=args.dns)

    ipsets = {}
    # This script is intended to be ran via systemd with a pre script doing the iptables load, so we should never need
    # to reload the contents of this file in our loop. When this file is changed, the user will need to restart the
    # iptables service anyway.
    with open(args.iptables_rules, 'r') as ipf:
        for line in ipf.readlines():
            if line.startswith('-'):
                match = match_set_re.search(line)
                if match:
                    ipsets[match.group(1)] = {}

    while True:
        # If we are using the contents of resolv.conf, make sure to update our copy. It's possible the contents of this
        # file will change.
        if not args.dns:
            query = Query(args.resolv_conf, dns_servers=args.dns)

        if not args.init:
            now = datetime.datetime.utcnow()
            for domain in ipsets:
                try:
                    LOG.debug('Looking up A records for %s.', domain)
                    ips = query.get_ips(domain, timeout=args.query_timeout)
                except TemporaryFailure:
                    # For temporary failures, we want the previous set to continue functioning.
                    continue
                for ip in ips:
                    ipsets[domain][ip] = now

            purge_before = now - datetime.timedelta(seconds=args.purge_timeout)
            for domain, ipmap in ipsets.items():
                new_ipmap = {}
                for ip, last_seen in ipmap.items():
                    if last_seen < purge_before:
                        delta = now - last_seen
                        min_ago = (delta.days * 86400 + delta.seconds) / 60
                        LOG.info('Removing %s from ipset %s, it was last seen %.2f minutes ago.', ip, domain, min_ago)
                    else:
                        new_ipmap[ip] = last_seen
                ipsets[domain] = new_ipmap

        for domain, ipmap in ipsets.items():
            new_ips = set(ipmap.keys())
            LOG.debug('Ensuring ipset %s exists.', domain)
            subprocess.run(['ipset', 'create', '-!', domain, 'hash:ip'], check=True)

            old_ips = set()
            for line in (
                subprocess.run(
                    ['ipset', 'list', domain, '-output', 'save'],
                    stdout=subprocess.PIPE,
                    check=True,
                    universal_newlines=True,
                )
                .stdout.strip()
                .split('\n')
            ):
                if line.startswith('add '):
                    old_ips.add(line.split(' ')[2])

            for ip in new_ips - old_ips:
                LOG.info('Adding %s to ipset %s.', ip, domain)
                subprocess.run(['ipset', 'add', domain, ip], check=True)

            for ip in old_ips - new_ips:
                LOG.debug('Removing %s from ipset %s.', ip, domain)
                subprocess.run(['ipset', 'del', domain, ip], check=True)

        if args.init or args.once:
            break

        time.sleep(args.loop_sleep)


if __name__ == '__main__':
    loop()
