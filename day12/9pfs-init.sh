#!/bin/sh
set -eu

PATH=/bin
export PATH

( cd /bin && ln -sf busybox sh )
for util in mount insmod poweroff cat; do
    [ -x "/bin/$util" ] || ln -sf busybox "/bin/$util"
done

echo "[init] loading 9p modules"
for mod in /lib/modules/*/kernel/fs/netfs/netfs.ko \
           /lib/modules/*/kernel/net/9p/9pnet.ko \
           /lib/modules/*/kernel/net/9p/9pnet_virtio.ko \
           /lib/modules/*/kernel/fs/9p/9p.ko; do
    [ -f "$mod" ] || continue
    echo "  insmod $mod"
    insmod "$mod" 2>/dev/null || true
done

echo "[init] mounting 9p list..."
mkdir -p /list
if ! mount -t 9p -o trans=virtio,version=9p2000.L list /list 2>&1; then
    echo "mount failed"
    exit 1
fi

echo "[init] running checks"
if /challenge/check-list; then
    echo "NICE"
else
    echo "NAUGHTY"
fi

/bin/busybox poweroff -f