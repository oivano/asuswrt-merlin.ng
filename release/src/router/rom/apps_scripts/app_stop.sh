#!/bin/sh
# ASUS app stop script


nvram set apps_state_stop=0 # INITIALIZING
nvram set apps_state_error=0

nvram set apps_state_stop=1 # STOPPING
# stop all APPs by order.
/usr/sbin/app_init_run.sh allpkg stop


nvram set apps_state_stop=2


nvram set apps_state_stop=3 # FINISHED
