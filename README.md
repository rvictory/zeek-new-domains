# Zeek New Domain Monitoring
This package monitors DNS queries and seeks to alert on new second level domains observed. It does this by using the `DomainTLD` module to extract "effective" second level domain names. This means that for domains such as `www.google.co.uk` we will consider `google.co.uk` to be the second level domain, not `co.uk`. 

The package keeps state in an SQLite database and considers a domain "new" if it hasn't been observed in the past 24 hours. When a new domain is observed, the effective second level domain name and the original query (the FQDN) are added to a notice in `notice.log`. The SQLite database enables us to keep the state across Zeek restarts.

## Installing
This package is intended to be installed using `zkg`. To install it, execute `zkg install https://github.com/rvictory/zeek-new-domains`. If you need to install it in a standalone fashion, the Domain TLD package (https://github.com/sethhall/domain-tld) must be installed and loaded (via local.zeek or similar) BEFORE this package is loaded.

## Caveats
This package is not cluster ready (although I will likely update it in the future to make it cluster ready). This means that if you have more than one worker it won't work as intended (each worker will build its own database based on traffic it has seen and you'll get duplicate alerts).

Because it uses an SQLite database, it's not suitable for extremely high volume monitoring. Future versions will include the ability to run in memory only to help mitigate this shortcoming.
