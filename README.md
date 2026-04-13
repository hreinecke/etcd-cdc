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

Configfs requires the port ID to be unique per node, and the discovery
log page requires the port ID to be unique for the log page.
So to avoid port renumbering the (local) port ID is restricted to
255, and the top byte of the port ID is set to the cluster id when
storing in etcd. With that we avoid port renumbering, and the port id
also indicates on which node the port attributes should be stored.
