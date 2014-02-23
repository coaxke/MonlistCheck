#NTP Monlist (MON_GETLIST) check:

This application will connect to an NTP server specified by the user, test for valid response and then check if it will return Monlist information.

I understand that writing this app in .NET is targeting the wrong crowd of people who generally maintain/administer NTP servers, I hope to also write this in Python when I have a chance.


##About NTP Monlist:

The ntpd program is an operating system daemon that sets and maintains the system time in synchronization with Internet standard time servers. As described in CVE-2013-5211, a denial of service condition can be caused by the use of the "monlist" feature, which is enabled by default on most NTP servers. NTP runs over UDP port 123, and since it’s on a UDP port, the source address can be spoofed easily.

It’s a relatively cheap and easy attack to launch using spoofed UDP based packets from a handful of hosts all the way to highly distributed botnets targeting NTP servers across the world which together can magnify the payload data request by up to 700x, forwarding the NTP response to the target network.

When the UDP service is queried remotely or the monlist command is run locally (ntpdc-c monlist), the service outputs the list of the last 600 queries that were made from different IP addresses. If the attacker spoofs the source address to be the victim's address, then all the responses are sent back to the victim's address. And because the response data is large, the victim's machine may not be able to handle the response, which can cause a denial of service 