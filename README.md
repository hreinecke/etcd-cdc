# etcd-cdc
Decentralised NVMe target configuration using the etcd key-value store

## Overview
etcd-cdc implements a distributed NVMe target configuration, where each storage
node is part of an etcd cluster. It consists of two parts:

1) nvmetd
Monitors the nvmet configfs via inotify(3) and pushes the configfs values
as keys into etcd.

2) nvmetd-fuse
Provides a fuse filesystem with the same layout as the nvmet configfs
settings, and modifies the etcd keys based on the changes in the fuse
filesystem.

## nvmet configfs considerations
Each subsystem will be extended across all nodes in the cluster.

In the absense of a distributed storage system each namespace will
be local to the node providing that namespace. To handle this a new
namespace attribute 'device_node' is presented, which specifies on
whih node in the cluster the namespace resides.
Only when the 'device_node' attribute is set modifications to
the 'device_path' attribute wiil be allowed.

'ports' are handled in a similar manner; a new attribute 'addr_node'
is presented which needs to be set to the node for which the 'addr_traddr'
is a valid address. Only if the 'addr_node' attribute is set modificaitons
to the 'addr_traddr' attribute are allowed.
