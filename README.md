Proxy for send data from MQTT to Zabbix.
Based on Zabbix sender 3.0.4 and libmosquitto.

To compile need to set path to source of Zabbix in file "compile".
Zabbix source need to be configured with options --with-agent and compiled.
Need to be installed libmosquitto-dev(Ubuntu)

How its work:

zbx_mqtt subscribe to $SYS/#, /host/#, /service/# this options is hardcoded, may be chnged in source.

For $SYS/# subscribtion:
Template: $SYS/{item}
Host must be set in conf file, else use broker address as host.

For /host/# and /service/# subscription:
Template: /host/{host}/{item}, /service/{host}/{item}
Example topic:
/host/testhost/some/data
testhost - host in Zabbix
some/data - transformed to some.data, key of item must be some.data
