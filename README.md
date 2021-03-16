# etcd-cdc
Decentralised NVMe discovery using the etcd key-value store

# Overview
etcd-cdc implements a distributed NVMe discovery system, where each storage
node is part of an etcd cluster. It consists of two parts:

1) etcd-cdc
Monitors the nvmet configfs via inotify(3) and generates discovery information
which is stored as keys in etcd.

2) etcd-discovery
Watches for key changes in etcd and generates discovery information usable for
nvme-cli to connect to the remote systems (TBD).

# Discovery keys
The keys have this format:

nvmet/<hostnqn>/<subsysnqn>/<portid>/{traddr,trtype,trsvcid}

This makes is particularly easy to generate discovery information, as each
host just has to fetch all keys with the prefix

nvmet/<hostnqn>

The keys will be stored in etcd with a lease attached, and the etcd-cdc will
need to refresh the lease. This avoids the discovery information getting
stale, and etcd will remove these keys once the lease expires (TBD).
On shutdown etcd-cdc will issue a 'revoke' request, which will remove all keys
maintained by this particular instance (TBD).
