#!/bin/bash

#------------------------------------------------
# Detect how we were called [l|p]
#------------------------------------------------
calledCmd="$(basename $0)"
[[ $calledCmd == "esl" ]] && env="lab1"
[[ $calledCmd == "esp" ]] && env="rdu1"
[[ $calledCmd == "esc" ]] && env="aws1"

#------------------------------------------------
# source escli.conf variables
#------------------------------------------------
# g* tools via brew install coreutils
[ $(uname) == "Darwin" ] && readlink=greadlink || readlink=readlink

# source default escli.conf
. $(dirname $($readlink -f $0))/escli.conf
# source secondary escli_c.conf if called w/ esc
[ "$env" == "aws1" ] && . $(dirname $($readlink -f $0))/escli_c.conf


usage () {
    cat <<-EOF

    USAGE: $0 [HEAD|GET|PUT|POST] '...ES REST CALL...'

    EXAMPLES:

        $0 GET  '_cat/shards?pretty'
        $0 GET  '_cat/indices?pretty&v&human'
        $0 GET  '_cat'
        $0 GET  ''
        $0 PUT  '_all/_settings'   -d "\$DATA"
        $0 POST '_cluster/reroute' -d "\$DATA"


	EOF
    exit 1
}

[ "$1" == "" ] && usage


#------------------------------------------------
# retrieves user/pass, replace them....
#   - XXXXXXXX (username)
#   - YYYYYYYY (password)
#------------------------------------------------
[ "$4" != "" ] && tmpArg4="$4"
arg4=$(echo "$tmpArg4" | sed -e "s/XXXXXXXX/$(${usernameCmd})/" -e "s/YYYYYYYY/$(${passwordCmd})/")

#------------------------------------------------
# ...ways to call curl.....
#------------------------------------------------
if [ "${1}" == "HEAD" ]; then
    curl -I -skK \
        <(cat <<<"user = \"$( ${usernameCmd} ):$( ${passwordCmd} )\"") \
        "${esBaseUrl}/$2"
elif [ "${1}" == "PUT" ]; then
    curl -skK \
        <(cat <<<"user = \"$( ${usernameCmd} ):$( ${passwordCmd} )\"") \
        -X$1 -H "${contType}" "${esBaseUrl}/$2" "$3" "$4"
elif [ "${1}" == "POST" ]; then
    curl -skK \
        <(cat <<<"user = \"$( ${usernameCmd} ):$( ${passwordCmd} )\"") \
        -X$1 -H "${contType}" "${esBaseUrl}/$2" "$3" "$arg4"
#elif [ "${1}" == "KIBANA" ]; then
#    curl -skK \
#        <(cat <<<"user = \"$( ${usernameCmd} ):$( ${passwordCmd} )\"") \
#        -XPOST -H "${contType}" -H "kbn-xsrf: reporting" "$2"
else
    curl -skK \
        <(cat <<<"user = \"$( ${usernameCmd} ):$( ${passwordCmd} )\"") \
        -X$1 -H "${contType}" "${esBaseUrl}/$2" "$3" "$4" "$5"
fi


