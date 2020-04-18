import logging

import zope.interface

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common

import requests

logger = logging.getLogger(__name__)


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Vultr

    This Authenticator uses the Vultr API to fulfill a dns-01 challenge.
    """

    description = "Obtain certs using a DNS TXT record (if you are using Vultr for DNS)."

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None
        self.vultr = None

    @classmethod
    def add_parser_arguments(cls, add):
        super(Authenticator, cls).add_parser_arguments(add)
        add("credentials", help="Vultr credentials INI file.")

    def more_info(self):
        return "This plugin configures a DNS TXT record to respond to a dns-01 challenge using theVultr API."

    def _setup_credentials(self):
        self.credentials = self._configure_credentials("credentials", "Vultr credentials INI file", {
            "key": "API key for Vultr account"
        })

    def _perform(self, domain, validation_name, validation):
        self._get_vultr_client().add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain, validation_name, validation):
        self._get_vultr_client().del_txt_record(domain, validation_name, validation)

    def _get_vultr_client(self):
        if self.vultr is None:
            self.vultr = VultrClient(self.credentials.conf("key"))

        return self.vultr


class VultrClient:
    def __init__(self, key):
        self.api_key = key
        self.domains_cache = None
        self.added_records = set()

    def add_txt_record(self, domain_name, record_name, record_data):
        try:
            base_domain_name = self.get_base_domain_name(domain_name)
            relative_record_name = self.get_relative_record_name(base_domain_name, record_name)

            self.request("POST", "/dns/create_record", {
                "domain": base_domain_name,
                "type": "TXT",
                "name": relative_record_name,
                "data": quote(record_data),
            })

            self.added_records.add((record_name, record_data))
            logger.debug(f'Successfully added TXT record for "{domain_name}"')
        except (VultrPluginError, requests.HTTPError) as err:
            error_message = err.message if isinstance(err, VultrPluginError) else response_error_message(err)
            raise errors.PluginError(f'Failed to add TXT record for "{domain_name}": {error_message}')

    def del_txt_record(self, domain_name, record_name, record_data):
        if (record_name, record_data) not in self.added_records:
            logger.debug(f'Skipping deletion of TXT record for "{domain_name}" since it was not successfully added')
            return

        try:
            base_domain_name = self.get_base_domain_name(domain_name)
            relative_record_name = self.get_relative_record_name(base_domain_name, record_name)
            record_id = self.get_record_id(base_domain_name, relative_record_name, record_data)

            self.request("POST", "/dns/delete_record", {"domain": base_domain_name, "RECORDID": record_id})

            logger.debug(f'Successfully deleted TXT record for "{domain_name}"')
        except (VultrPluginError, requests.HTTPError) as err:
            error_message = err.message if isinstance(err, VultrPluginError) else http_error_message(err)
            logger.warning(f'Failed to delete TXT record for "{domain_name}": {error_message}')

    def get_base_domain_name(self, full_domain_name):
        if self.domains_cache is not None:
            domains = self.domains_cache
        else:
            try:
                domains = self.domains_cache = self.request("GET", "/dns/list")
            except requests.HTTPError as err:
                raise VultrPluginError("Error fetching DNS domains list: " + http_error_message(err))

        guess_list = dns_common.base_domain_name_guesses(full_domain_name)
        for guess in guess_list:
            for base_domain in domains:
                if base_domain["domain"] == guess:
                    logger.debug(f'Using base domain "{guess}" for "{full_domain_name}"')
                    return guess

        raise VultrPluginError(f'Could not find the (base) domain for "{full_domain_name}" (Is the domain set in your DNS?)')

    def get_relative_record_name(self, base_domain_name, absolute_record_name):
        return absolute_record_name[:-len("." + base_domain_name)]

    def get_record_id(self, base_domain_name, relative_record_name, record_data):
        try:
            dns_records = self.request("GET", "/dns/records?domain=" + base_domain_name)
        except requests.HTTPError as err:
            raise VultrPluginError(f'Error fetching DNS records for "{base_domain_name}": {http_error_message(err)}')

        for r in dns_records:
            if r.get("type") == "TXT" and r.get("name") == relative_record_name and r.get("data") == quote(record_data):
                return r["RECORDID"]

        raise VultrPluginError("TXT record not found")

    def request(self, method, path, data=None):
        url = "https://api.vultr.com/v1" + path

        response = requests.request(method, url, data=data, headers={"API-Key": self.api_key})
        response.raise_for_status()

        if response.headers["Content-Type"] == "application/json":
            return response.json()
        else:
            return response.text


class VultrPluginError(Exception):
    def __init__(self, message):
        self.message = message


def http_error_message(http_error):
    response = http_error.response
    return f"{response.status_code} - {response.text}"

def quote(text):
    return f'"{text}"'
