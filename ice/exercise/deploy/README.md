# ICE read-only web view (llinker.com/ICE)

`python -m ice.exercise.webstatus` serves a read-only page on 127.0.0.1:8139:
batch status, the live episode + recorder log tail (pulled from the box over ssh),
and every finished bundle with its reward broken out by axis and its agent trajectory.

Deploy on the intake host (this machine):
1. `cp ice/exercise/deploy/ice-web.service /etc/systemd/system/ && systemctl enable --now ice-web`
2. paste `ice/exercise/deploy/nginx-ICE.conf` into the llinker.com :443 server block, `nginx -t && systemctl reload nginx`

Env (set in the unit): ICE_WEB_PORT=8139, ICE_WEB_DATASET=/home/ICE-Agent/dataset,
ICE_BOX=root@220.86.159.73, ICE_BOX_PORT=21530. The service runs as root and reaches the
box with root's ssh key; it only ever reads (no endpoint mutates anything).
