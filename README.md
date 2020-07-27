# Zeek New Domain Monitoring
This package monitors DNS queries and seeks to alert on new second level domains observed. It does this by using the `DomainTLD` module to extract "effective" second level domain names. This means that for domains such as `www.google.co.uk` we will consider `google.co.uk` to be the second level domain, not `co.uk`. 

The package keeps state in an SQLite database (or optionally in memory) and considers a domain "new" if it hasn't been observed in the past 24 hours (this can be configured, see the Configuration section below). When a new domain is observed, the effective second level domain name and the original query (the FQDN) are added to a notice in `notice.log`. The SQLite database enables us to keep the state across Zeek restarts.

## Example Alert:
```
#fields ts      uid     id.orig_h       id.orig_p       id.resp_h       id.resp_p       fuid    file_mime_type  file_desc       proto   note    msg     sub     src     dst     p       n       peer_descr      actions suppress_for    remote_location.country_code    remote_location.region  remote_location.city     remote_location.latitude        remote_location.longitude
#types  time    string  addr    port    addr    port    string  string  string  enum    enum    string  string  addr    addr    port    count   string  set[enum]       interval        string  string  string  double  double
1595603197.132760       CFUCQDnZe2SnHdRrg       192.168.2.183   39772   192.168.2.1     53      -       -       -       udp     DNSMonitor::DNS_New_Domain      New domain observed: google-analytics.com from query www.google-analytics.com   -       192.168.2.183   192.168.2.1     53      -       -       Notice::ACTION_LOG       0.001000        -       -       -       -       -
```

## Installing
This package is intended to be installed using `zkg`. To install it, execute `zkg install https://github.com/rvictory/zeek-new-domains`. If you need to install it in a standalone fashion, the Domain TLD package (https://github.com/sethhall/domain-tld) must be installed and loaded (via local.zeek or similar) BEFORE this package is loaded.

## Configuration
This package exposes two configuration options:
* `DNSMonitor::history_expiration_interval`: This is an interval that controls how long a name will be considered "not new." The default is 24 hours. The timer is reset for a name every time it is queried, so as long as a name is queried once every `history_expiration_interval` time interval, it won't be alerted on. Larger values will create a larger database (on disk or in memory) but will lower the number of notices you get.
*  `DNSMonitor::enable_persistence`: This boolean option turns on or off the persistence of the history datastore. The default is `T` which saves history in an SQLite database on disk. Turn it off if you are willing to lose history on Zeek restarts but gain the performance of not using SQLite.

To change a configuration option, put something like the following in your `site/local.zeek` file:

```zeek
redef DNSMonitor::history_expiration_interval = 12hrs;
redef DNSMonitor::enable_persistence = F;
```

## Caveats
This package is ~~not cluster ready (although I will likely update it in the future to make it cluster ready)~~ cluster aware through the use of a persistent Clusterized Broker data store! This means that if you have more than one worker it ~~won't~~ will work as intended.

Because it uses an SQLite database, it's not suitable for extremely high volume monitoring. If you want to use it in an enviroment with higher traffic volumes, set the `DNSMonitor::enable_persistence` configuration option to `F` in order to store the data in memory only. If Zeek restarts, your history will be lost. This is useful, however, if you know that you have long-running Zeek processes and are willing to accept the loss of history.
