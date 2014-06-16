import json
import os
import re
from whois_client import NICClient
from parser import WhoisEntry, PywhoisError


class WhoisException(BaseException):
    pass


class Whois:

    def __init__(self, domain):
        self._whois_text = None
        self.domain = domain
        # clean domain to expose netloc
        self.sub_domain, self.tlds = self.extract_domain(domain)

        script_dir = os.path.dirname(os.path.realpath(__file__))

        with open(os.path.join(script_dir, 'whois_servers.json')) as f:
            servers_json = ''
            while True:
                line = f.readline()
                if not line:
                    break
                servers_json += line
            servers = json.loads(servers_json)

        if self.tlds in servers:
            self.whois_server = servers[self.tlds]
        else:
            raise WhoisException('tld % not find')

        self.nic_client = NICClient(self.whois_server[0])

    @property
    def whois_text(self):
        if self._whois_text is None:
            self._whois_text = self.nic_client.whois_lookup(self.domain)
        return self._whois_text

    def info(self):
        try:
            return WhoisEntry.load(self.domain, self.whois_text)
        except PywhoisError:
            raise WhoisException

    def is_available(self):
        try:
            not_found_string = self.whois_server[1]
        except KeyError:
            not_found_string = ''

        m = re.search(not_found_string, self.whois_text)

        if not m is None:
            return True
        else:
            return False

    @staticmethod
    def extract_domain(search_url):
        """Extract the domain from the given URL
        """
        m = re.match(r'^([a-zA-Z\d\-]+).([a-zA-Z\.\-\d]+)$', search_url)
        if m:
            sub_domain = m.group(1)
            tlds = m.group(2)
            return sub_domain, tlds
        else:
            raise WhoisException('Invalid domain')
