#!/bin/sh

release_url="https://github.com/oivano/asuswrt-merlin.ng/releases"

logger -t firmware_upgrade "Live flashing is disabled; download supported firmware from $release_url and upload it manually"
nvram set webs_state_error=3
nvram set webs_state_dl_error=3
nvram set webs_state_flag=0
nvram set webs_state_upgrade=1
nvram set auto_upgrade=0
nvram set webs_state_dl=0
exit 1