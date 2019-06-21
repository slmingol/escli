#!/bin/bash

#------------------------------------------------
# Detect how we were called [l|p]
#------------------------------------------------
calledCmd="$(basename $0)"
[[ $calledCmd == "esl" ]] && env="lab1"
[[ $calledCmd == "esp" ]] && env="rdu1"
[[ $calledCmd == "esc" ]] && env="aws1"

#------------------------------------------------
# source zencli.conf variables
#------------------------------------------------
# g* tools via brew install coreutils
[ $(uname) == "Darwin" ] && readlink=greadlink || readlink=readlink

# source default escli.conf
. $(dirname $($readlink -f $0))/zencli.conf

uid="/zport/dmd/Devices/Server/Linux/devices/${1}/os/filesystems/mnt_data/FileSystem"
DATA=$(cat <<-EOM
   {
        "action" : "TemplateRouter",
        "method" : "getThresholds",
        "data"   : [ {
           "uid" : "${uid}"
           }
        ],
        "tid"    : 1
    }
	EOM
)
curl -skK \
    <(cat <<<"user = \"$( ${usernameCmd} ):$( ${passwordCmd} )\"") \
    -X POST ${zenBaseUrl} \
   -H "${contType}" \
   -H "Host: ${hostname}" \
   -d "${DATA}"
