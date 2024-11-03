systemctl stop matt-daemon
rm -rf /etc/systemd/system/matt-daemon.service
rm -rf /etc/init.d/matt-daemon
rm -rf /usr/bin/matt-daemon
systemctl daemon-reload