# This script will monitor for new domains being queried on your network
# It uses an SQLite backed database to persist across Zeek restarts. This also means that it won't really scale well
# This only alerts on new second level domains. By using Domain TLD, we can expand that concept much further.
# For example, www.example.co.uk would be considered example.co.uk, and not co.uk in the naiive sense
# Names are considered "not new" if they have been queried at least once in the past 24 hours
# Alerts end up in the `notice.log` log
module DNSMonitor;

export {
    redef enum Notice::Type += {
        DNS_New_Domain
    };

    option history_expiration_interval = 24hrs;
    option enable_persistence = T;
}

global store: Cluster::StoreInfo;

event dns_query_reply(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
        local effective_domain = DomainTLD::effective_domain(query);
        when (local exists = Broker::exists(store$store, effective_domain)) {
                local bool_exists = (exists$result as bool);
                if (!bool_exists) {
                        NOTICE([$note=DNS_New_Domain,
                                $conn=c,
                                $suppress_for=1msec,
                                $msg="New domain observed: " + effective_domain + " from query " + query]);
                }
                when (local put_result = Broker::put(store$store, effective_domain, T, DNSMonitor::history_expiration_interval)) {
                } timeout 5sec { Cluster::log("Timeout when writing domain to store"); }
        } timeout 5sec { Cluster::log("Timeout when trying to see if a domain exists"); }
}

event zeek_init() {
    store = Cluster::create_store("dns_monitoring", DNSMonitor::enable_persistence);
}