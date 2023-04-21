# etcd-cdc
Decentralised NVMe discovery using the etcd key-value store

## Overview
etcd-cdc implements a distributed NVMe discovery system, where each storage
node is part of an etcd cluster. It consists of two parts:

1) nvmet_etcd
Monitors the nvmet configfs via inotify(3) and generates discovery information
which is stored as keys in etcd.

2) etcd_discovery
Watches for discovery key changes in etcd, and connects to added NVMe
subsystems or disconnects from deleted NVMe subsystems based on the
information from the discovery keys.

3) etcd_tool
Utility to exercise the interactions with etcd

## Discovery keys
The keys have this format:

~~~
<prefix>/<hostnqn>/<subsysnqn>/<portid>
~~~

The value of each key is:

~~~
trtrype=<trtype>,traddr=<traddr>,trsvcid=<trsvcid>
~~~

This makes is particularly easy to generate discovery information, as each
host just has to fetch all keys with the prefix

~~~
<prefix>/<hostnqn>
~~~

The default `<prefix>` is `nvmet`, it can be changed with the `--etcd-prefix`
option to `nvmet_etcd`.

## Lifetime of generated keys
etcd-cdc will request a lease on startup, and all keys are stored in etcd
with this lease attached. This avoids the discovery information getting stale
as etcd will remove these keys once the lease expires.
etcd-cdc will refresh the lease in regular intervals during runtime.
On shutdown etcd-cdc will issue a 'revoke' request on that lease, which will
remove all keys generated by this particular instance.

## NVMe connection management
etcd_discovery will maintain NVMe controller connections based on the
discovery keys in etcd. As etcd contains all discovery information no
discovery connection is required, and etcd_discovery will connect to
the subsystems directly without having to discover the subsystems.
