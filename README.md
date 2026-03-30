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

3) etcd_tool
Utility to exercise the interactions with etcd

## nvmet configfs considerations
Each subsystem will be extended across all nodes in the cluster.
Due to limitations in the linux kernel that implies that the ANA
group IDs are global throughout the cluster, too.
In the absense of a distributed storage system each namespace will
be local to the node providing that namespace. This implies that
the ANA state for the namespace on every other node is 'INACCESSIBLE',
requiring two ANA groups ('optimized' and 'inaccessible') for each
subsystem.
