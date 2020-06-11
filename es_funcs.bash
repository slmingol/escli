### es wrapper cmd inventory
declare -A escmd
escmd[l]="./esl"
escmd[p]="./esp"
escmd[c]="./esc"

### es data node naming conventions
nodeBaseName="rdu-es-data-0"
declare -A esnode
esnode[l]="lab-${nodeBaseName}"
esnode[p]="${nodeBaseName}"
esnode[c]="instance-0000000"

### zenoss wrapper cmd inventory
declare -A zencmd
zencmd[l]="./zsl"
zencmd[p]="./zsp"

filename="es_funcs.bash"

#################################################
### Tips
#################################################
# watch -x bash -c ". es_funcs.bash; show_recovery p"

#################################################
### References
#################################################
# - https://dzone.com/articles/23-useful-elasticsearch-example-queries

#################################################
### Globals
#################################################
uname="$(uname)"
# sed
[ "$uname" == 'Darwin' ] && sedCmd=gsed     || sedCmd=sed
# gpaste
[ "$uname" == 'Darwin' ] && pasteCmd=gpaste || pasteCmd=paste
# gdate
[ "$uname" == 'Darwin' ] && dateCmd=gdate   || dateCmd=date

#################################################
### Functions 
#################################################

#0-----------------------------------------------
# helper funcs
##-----------------------------------------------
gen_README () {
    # generate contents of README.md
    cat \
         <($sedCmd -n '0,/^$ escli_ls$/p' README.md) \
         <(escli_ls) \
         <($sedCmd -n '/^show_template$/,/^You can also get that list/p' README.md | grep -v '^show_template$') \
         <(grep -B1 '^$ escli_lsl$' README.md) \
         <(escli_lsl) \
         <($sedCmd -n '/^show_template[  ]\+#/,$p' README.md | $sedCmd -n '4,$p')
}

cmp_README () {
    # sdiff new README.md vs. existing README.md
    sdiff <(gen_README) README.md | less
}

mk_README () {
    # save new README.md over existing README.md
    gen_README | tee README.md.new
    cp -f README.md.new README.md
    rm -f README.md.new
}

gen_EXAMPLES () {
    # generate content of EXAMPLES.md
    ./gen_EXAMPLES.bash
}

cmp_EXAMPLES () {
    # sdiff new EXAMPLES.md vs. existing EXAMPLES.md
    sdiff <(gen_EXAMPLES) EXAMPLES.md | less
}

mk_EXAMPLES () {
    # save new EXAMPLES.md over existing EXAMPLES.md
    gen_EXAMPLES | tee EXAMPLES.md.new
    cp -f EXAMPLES.md.new EXAMPLES.md
    rm -f EXAMPLES.md.new
}



#1-----------------------------------------------
# date & math funcs
##-----------------------------------------------
calc_date () {
    # print UTC date X "days | days ago"
    local english_days="$1"

    [[ -z ${FUNCNAME[1]} ]] && caller=${FUNCNAME[0]} || caller=${FUNCNAME[1]}

    [[ $english_days != *days* ]] \
        && printf "\nUSAGE: ${caller} [ 'X days ago' | 'X days' ]\n\n" \
        && return 1

    ${dateCmd} -u --date="$english_days" +%Y.%m.%d
}

calc_hour () {
    # print UTC date X "hours | hours ago"
    local english_hours="$1"

    [[ -z ${FUNCNAME[1]} ]] && caller=${FUNCNAME[0]} || caller=${FUNCNAME[1]}

    [[ $english_hours != *hours* ]] \
        && printf "\nUSAGE: ${caller} [ 'X hours ago' | 'X hours' ]\n\n" \
        && return 1

    ${dateCmd} --utc --iso-8601=sec --date="$english_hours"
}

calc_date_1daybefore () {
    # print UTC date 1 day before given date (YYYY-mm-dd)
    local date="$1"

    [[ -z ${FUNCNAME[1]} ]] && caller=${FUNCNAME[0]} || caller=${FUNCNAME[1]}

    [[ ! $date =~ [0-9]{4}-[0-9]{2}-[0-9]{2} ]] \
        && printf "\nUSAGE: ${caller} [YYYY-mm-dd]\n\n" \
        && return 1

    ${dateCmd} -u --date="$date -1 days" +%Y.%m.%d
}

calc_date_1dayafter () {
    # print UTC date 1 day after given date (YYYY-mm-dd)
    local date="$1"

    [[ -z ${FUNCNAME[1]} ]] && caller=${FUNCNAME[0]} || caller=${FUNCNAME[1]}

    [[ ! $date =~ [0-9]{4}-[0-9]{2}-[0-9]{2} ]] \
        && printf "\nUSAGE: ${caller} [YYYY-mm-dd]\n\n" \
        && return 1

    ${dateCmd} -u --date="$date +1 days" +%Y.%m.%d
}

julian_day () {
    # calculate julian day based on a YYYYmmdd

    [[ -z ${FUNCNAME[1]} ]] && caller=${FUNCNAME[0]} || caller=${FUNCNAME[1]}

    [[ ! $1 =~ [0-9]{8} ]] \
        && printf "\nUSAGE: ${caller} YYYYmmdd\n\n" \
        && return 1

    local year="${1:0:4}"
    local month="${1:4:2}"
    local day="$(printf "%g" "${1:6:2}")"

    #DEBUG# echo "$year - $month - $day"
    local julianday=$((day - 32075 + 1461 * (year + 4800 - (14 - month) / 12) / 4 + 367 * \
            (month - 2 + ((14 - month) / 12) * 12) / 12 - 3 * \
            ((year + 4900 - (14 - month) / 12) / 100) / 4))

    echo "$julianday"

    # REFS:
    #  - https://stackoverflow.com/questions/43317428/bash-how-to-get-current-julian-day-number
    #  - https://en.wikipedia.org/wiki/Julian_day
}

ceiling_divide () {
    # ceiling divide 2 numbers

    [[ -z ${FUNCNAME[1]} ]] && caller=${FUNCNAME[0]} || caller=${FUNCNAME[1]}

    [[ ! $1 =~ [0-9]{1,} ]] && [[ ! $2 =~ [0-9]{1,} ]] \
        && printf "\nUSAGE: ${caller} <numerator> <denominator>\n\n" \
        && return 1

    ceiling_result=$(echo "($1 + $2 - 1)/$2" | bc)
    echo "$ceiling_result"
}



#2-----------------------------------------------
# usage funcs
##-----------------------------------------------
escli_ls () {
    # list function names
    awk '/\(\)/ {print $1}' ${filename} | grep -vE "usage_chk|grep"
}

escli_lsl () {
    # list function names + desc.
    while read line; do
        if [[ $line =~ ^#[0-9]+-- ]]; then
            printf "\n"
            grep --color=never -A2 "^${line}" "${filename}"
        else
            grep --color=never -A1 "^${line} () {" "${filename}" | sed 's/ ().*//' | \
                paste - - | pr -t -e43
        fi
    done < <(awk '/^[0-9a-zA-Z_-]+ \(\) {|^#[0-9]+--/ {print $1}' "${filename}" | grep -v usage_chk)
    printf "\n\n"
}

usage_chk1 () {
    # usage msg for cmds w/ 1 arg
    local env="$1"

    [[ $env =~ [lpc] ]] && return 0 || \
        printf "\nUSAGE: ${FUNCNAME[1]} [l|p|c]\n\n" && return 1
}

usage_chk2 () {
    # usage msg for cmds w/ 2 arg (where 2nd arg. is a node suffix)
    local env="$1"
    local node="$2"

    [[ $env =~ [lpc] && $node =~ 1[a-z] ]] && return 0 || \
        printf "\nUSAGE: ${FUNCNAME[1]} [l|p|c] <node suffix--[1a|1b|1c|1d...]>\n\n" \
        && return 1
}

usage_chk3 () {
    # usage msg for cmds w/ 2 arg (where 2nd arg. is a index pattern)
    local env="$1"
    local idxArg="$2"

    [[ $env =~ [lpc] && $idxArg != '' ]] && return 0 || \
        printf "\nUSAGE: ${FUNCNAME[1]} [l|p|c] <idx pattern>\n\n" \
        && return 1
}

usage_chk4 () {
    # usage msg for cmds w/ 4 arg (<shard name> <shard num> <from/to node suf.>)
    local env="$1"
    local shardName="$2"
    local shardNum="$3"
    local nodeCode="$4"

    [[ $env =~ [lpc] && $shardName != '' \
        && $shardNum != '' \
        && $nodeCode =~ 1[a-z] || $nodeCode =~ [0-9]{3} ]] && return 0 || \
        printf "\nUSAGE: ${FUNCNAME[1]} [l|p|c] <shard name> <shard num> <from/to node>\n\n" \
        && return 1
}

usage_chk5 () {
    # usage msg for cmds w/ 5 arg (<shard name> <shard num> <from node suf.> <to node suf.>)
    local env="$1"
    local shardName="$2"
    local shardNum="$3"
    local fromCode="$4"
    local toCode="$5"

    [[ $env =~ [lpc] && $shardName != '' \
        && $shardNum != '' \
        && $fromCode =~ 1[a-z] \
        && $toCode =~ 1[a-z] ]] && return 0 || \
        printf "\nUSAGE: ${FUNCNAME[1]} [l|p|c] <shard name> <shard num> <from node> <to node>\n\n" \
        && return 1
}

usage_chk6 () {
    # usage msg for cmds w/ 4 arg (<k8s namespace> <start time> <end time>)
    local env="$1"
    local idxArg="$2"
    local namespace="$3"
    local sTime="$4"
    local eTime="$5"

	MSG1=$(cat <<-EOM

	    ------------------------------------------------------------------------------------------------------

	    Example
	    =======
	    $ del_docs_k8s_ns_range l filebeat-* big-dipper-perf 2019-07-11T11:57:20.968Z 2019-07-12T04:26:38.757Z
	    {"task":"vudQxvnfSQuxMtdkq8ZTUQ:844209600"}

	    ------------------------------------------------------------------------------------------------------

	        Source: https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-delete-by-query.html
	EOM
    )

    [[ $env =~ [lpc] && $idxArg != '' \
            && $namespace != '' \
            && $sTime != '' \
            && $sTime =~ [0-9]{4}-[0-9]{2}-[0-9]{2}T && $sTime =~ [0-9]{2}:[0-9]{2}:[0-9]{2}.[0-9]{3}Z \
            && $eTime != '' \
            && $eTime =~ [0-9]{4}-[0-9]{2}-[0-9]{2}T && $eTime =~ [0-9]{2}:[0-9]{2}:[0-9]{2}.[0-9]{3}Z ]] \
        && return 0 || \
            printf "\nUSAGE: ${FUNCNAME[1]} [l|p|c] <idx pattern> <k8s namespace> <start time> <end time>\n\n\n" \
                && printf "  * TIME FORMAT: 2019-07-10T00:00:00.000Z\n\n" \
                && printf "  * INDX FORMAT:\n      -- %s\n      -- %s\n      -- %s\n\n%s\n\n\n" \
                    "filebeat-*" \
                    "-or- filebeat-6.5.1-2019.07.04,filebeat-6.5.1-2019.07.05,...." \
                    "-or- filebeat-*-2019.07*" \
                    "$MSG1" \
        && return 1
}

usage_chk7 () {
    # usage msg for cmds w/ 3 arg (where 2nd arg. is a index pattern, and 3rd is a integer)
    local env="$1"
    local idxArg="$2"
    local repNum="$3"

    [[ $env =~ [lpc] && $idxArg != '' && ( $repNum =~ ^[0-9]{1,2}$ ) ]] && return 0 || \
        printf "\nUSAGE: ${FUNCNAME[1]} [l|p|c] <idx pattern> <shard replica count>\n\n" \
        && return 1
}

usage_chk8 () {
    # usage msg for cmds w/ 3 arg (where 2nd arg. is a index pattern, and 3rd is a integer)
    local env="$1"
    local idxArg="$2"
    local retNum="$3"

    [[ $env =~ [lpc] && $idxArg != '' && ( $retNum =~ ^[0-9]{1,2}$ ) ]] && return 0 || \
        printf "\nUSAGE: ${FUNCNAME[1]} [l|p|c] <idx base type> <days to retain>\n\n" \
        && printf "  * idx base type:  [filebeat|metricbeat|packetbeat|etc.]\n" \
        && printf "  * days to retain: [30|60|90|etc.]\n\n\n" \
        && return 1
}

usage_chk9 () {
    # usage msg for cmds w/ 2 arg (where 2nd arg. is a integer)
    local env="$1"
    local size="$2"

    [[ $env =~ [lpc] && ( $size =~ ^[0-9]{2,4}$ && $size -gt 39 && $size -lt 2001 ) ]] && return 0 || \
        printf "\nUSAGE: ${FUNCNAME[1]} [l|p|c] <size in megabytes>\n\n" \
        && printf "  * size in megabytes: [40|100|250|500|2000|etc.]\n\n" \
        && printf "  NOTE: ...minimum is 40, the max. 2000!...\n\n\n" \
        && return 1
}

usage_chk10 () {
    # usage msg for cmds w/ 2 arg (where 2nd arg. is a integer (days))
    local env="$1"
    local days="$2"

    [[ $env =~ [lpc] && ( $days =~ ^[0-9]{1,2}$ && $days -gt 0 && $days -lt 91 ) ]] && return 0 || \
        printf "\nUSAGE: ${FUNCNAME[1]} [l|p|c] <days>\n\n" \
        && printf "  * days: [1|5|30|45|90]\n\n" \
        && printf "  NOTE: ...minimum is 1, the max. 90!...\n\n\n" \
        && return 1
}

usage_chk11 () {
    # usage msg for cmds w/ 3 arg (where 2nd arg. is a index pattern, and 3rd is a integer or `-1`)
    local env="$1"
    local idxArg="$2"
    local numShards="$3"

    [[ $env =~ [lpc] && $idxArg != '' && ( $numShards =~ ^[-]*[0-9]{1,2}$ ) ]] && return 0 || \
        printf "\nUSAGE: ${FUNCNAME[1]} [l|p|c] <idx pattern> <num shards>\n\n" \
        && return 1
}

usage_chk12 () {
    # usage msg for cmds w/ 3 arg (where 2nd arg. is a index pattern, and 3rd is a field name)
    local env="$1"
    local idxArg="$2"
    local field="$3"

    # NOTE: Be careful where you put the `-` in the `$field` test. Should be at end, anywhere else
    #       and bash may interpret characters in a range
    [[ $env =~ [lpc] && $idxArg != '' && ( $field =~ ^[a-zA-Z0-9_@.-]+ ) ]] && return 0 || \
        printf "\nUSAGE: ${FUNCNAME[1]} [l|p|c] <idx pattern> <field name>\n\n" \
        && return 1
}



#3-----------------------------------------------
# help funcs
##-----------------------------------------------
help_cat () {
    # print help for _cat API call
    local env="$1"
    usage_chk1 "$env" || return 1
    ${escmd[$env]} GET '_cat'
}

help_indices () {
    # print help for _cat/indices API call
    local env="$1"
    usage_chk1 "$env" || return 1
    ${escmd[$env]} GET '_cat/indices?pretty&v&help' | less
}



#4-----------------------------------------------
# node funcs
##-----------------------------------------------
list_nodes () {
    # list ES nodes along w/ a list of data node suffixes for use by other cmds.
    local env="$1"
    usage_chk1 "$env" || return 1
    #output=$(${escmd[$env]} GET '_cat/nodes?v&pretty')
    output=$(${escmd[$env]} GET '_cat/nodes?v&h=ip,heap.percent,ram.percent,cpu,load_1m,load_5m,load_15m,node.role,master,name,disk.total,disk.used,disk.avail,disk.used_percent&s=name:asc')
    dnodes=$(echo "${output}" | awk '/data|di.*instance/ { print $10 }' | sed 's/.*-00*//' | sort | paste -s -d"," -)

    printf "\n%s\n\n"                         "${output}"
    printf "valid data node suffixes: %s\n\n" "${dnodes}"
}

list_nodes_storage () {
    # list ES nodes HDD usage
    local env="$1"
    usage_chk1 "$env" || return 1
    output=$(${escmd[$env]} GET '_cat/nodes?v&h=ip,node.role,master,name,disk.total,disk.used,disk.avail,disk.used_percent&s=disk.used_percent:desc')
    dnodes=$(echo "${output}" | awk '/data|di.*instance/ { print $4 }' | sed 's/.*-00*//' | sort | paste -s -d"," -)

    printf "\n%s\n\n"                         "${output}"
    printf "valid data node suffixes: %s\n"   "${dnodes}"
    printf "total data nodes: %s\n\n"         "$(echo "$dnodes" | awk -F, '{print NF}')"
}

list_nodes_zenoss_alarms () {
    # list ES node HDD usage alarms in Zenoss
    local env="$1"
    usage_chk1 "$env" || return 1
    ips=$(${escmd[$env]} GET '_cat/nodes?h=ip,node.role,name' | awk '$2~/d/ {print $1" "$3}')
    printf "\n"
    printf "%-20s%-32s%-32s\n" "server" "zenoss alarm #1" "zenoss alarm #2"
    printf "%-20s%-32s%-32s\n" "======" "===============" "==============="
    set -- $ips
    (
        while [ ! -z "$1" ]; do
            printf "%-20s%-s\n" \
                "${2}" \
                "$(${zencmd[$env]} $1 | jq ".result.data[].maxval" | paste - -)"
            shift 2
        done
    ) | sort -k1,1
    printf "\n\n"
}

show_nodes_fs_details () {
    # list ES nodes filesystem details
    local env="$1"
    usage_chk1 "$env" || return 1
    ${escmd[$env]} GET '_nodes/stats/fs?human&pretty' | jq -C . | less -r
}

show_nodes_circuit-breaker_summary () {
    # list ES nodes circuit breaker tripped summaries
    local env="$1"
    usage_chk1 "$env" || return 1
    printf "\nnode circuit breakers tripped counts"
    printf "\n---------------------------------------------------\n"
    ${escmd[$env]} GET '_nodes/stats/breaker?pretty&human' \
        | jq -s 'map({ (.nodes[].name): .nodes[].breakers }) | add'  \
        | grep -E "lab-|: {|tripped" \
        | paste - - - - - - - - - - - \
        | $sedCmd -e 's/{[ \t]\+/ /g' -e 's/"tripped"://g' -e 's/"//g' \
        | column -t \
        | sort
    printf "\n--------- end of check ----------------------------\n\n"
    cat <<-EOM

    Circuit Breakers
    ----------------
    Elasticsearch contains multiple circuit breakers used to prevent operations from causing an OutOfMemoryError. 
    Each breaker specifies a limit for how much memory it can use. Additionally, there is a parent-level breaker 
    that specifies the total amount of memory that can be used across all breakers.
    -------------------------------------------------------------------------------------------------------------
      * request
                request circuit breaker allows Elasticsearch to prevent per-request data structures 
                (for example, memory used for calculating aggregations during a request) from exceeding 
                a certain amount of memory.
    -------------------------------------------------------------------------------------------------------------
      * fileddata
                field data circuit breaker allows Elasticsearch to estimate the amount of memory a field 
                will require to be loaded into memory.
    -------------------------------------------------------------------------------------------------------------
      * in_flight_requests 
                in flight requests circuit breaker allows Elasticsearch to limit the memory usage of all 
                currently active incoming requests on transport or HTTP level from exceeding a certain 
                amount of memory on a node. The memory usage is based on the content length of the request 
                itself. This circuit breaker also considers that memory is not only needed for 
                representing the raw request but also as a structured object which is reflected by default 
                overhead.
    -------------------------------------------------------------------------------------------------------------
      * accounting
                accounting circuit breaker allows Elasticsearch to limit the memory usage of things held 
                in memory that are not released when a request is completed. This includes things like 
                the Lucene segment memory.
    -------------------------------------------------------------------------------------------------------------
      * parent
                there is a parent-level breaker that specifies the total amount of memory that can be used 
                across all breakers
    -------------------------------------------------------------------------------------------------------------

    Source: https://www.elastic.co/guide/en/elasticsearch/reference/current/circuit-breaker.html


	EOM
}

show_nodes_circuit-breaker_details () {
    # list ES nodes circuit breaker details
    local env="$1"
    usage_chk1 "$env" || return 1
    ${escmd[$env]} GET '_nodes/stats/breaker?pretty&human' | jq . -C | less -r
}

show_nodes_threadpools () {
    # list ES nodes thread pool counts (_cat/thread_pool) ... any all zeros filtered out
    local env="$1"
    usage_chk1 "$env" || return 1
    ${escmd[$env]} GET '_cat/thread_pool?v&h=node_name,name,active,rejected,completed&s=node_name' \
		| grep -v '0[ ]\+0[ ]\+0'
}



#5-----------------------------------------------
# shard mgmt funcs
##-----------------------------------------------
show_shards () {
    # list all the index shards sorted by size (big->small)
    local env="$1"
    usage_chk1 "$env" || return 1
    ${escmd[$env]} GET '_cat/shards?v&human&pretty&s=store:desc,index,shard'
}

show_big_shards () {
    # list top 20 shards for a given node's suffix (1a, 1b, etc.)
    local env="$1"
    local node="$2"
    usage_chk2 "$env" "$node" || return 1
    show_shards "$env" | grep -E "index|${node}" | head -40
}

show_small_shards () {
    # list smallest 20 shards for a given node's suffix (1a, 1b, etc.)
    local env="$1"
    local node="$2"
    usage_chk2 "$env" "$node" || return 1
    show_shards "$env" | grep -E "index|${node}" | tail -40
}

show_hot_shards () {
    # list today's shards for a given node's suffix (1a, 1b, etc.)
    local env="$1"
    local node="$2"
    usage_chk2 "$env" "$node" || return 1

    todayDate=$(calc_date '0 days')
    todayDay=$(echo "$todayDate" | cut -d'.' -f2-3)

    show_shards "$env" | grep -E "^index|${todayDay}" | grep -E "^index|${node}"
}

show_shard_usage_by_node () {
    # list all the index shards sorted by size (big->small)
    local env="$1"
    usage_chk1 "$env" || return 1
    cat <<-EOM


	A good rule-of-thumb is to ensure you keep the number of shards per node below 20 per GB heap it 
	has configured. A node with a 30GB heap should therefore have a maximum of 600 shards, but the 
	further below this limit you can keep it the better. This will generally help the cluster 
	stay in good health.
	
	Source: https://www.elastic.co/blog/how-many-shards-should-i-have-in-my-elasticsearch-cluster


	EOM
    (
    echo "node #shards"
    echo "---- -------"
    show_shards "$env" | awk '{print $8}' | grep -v node | sort | uniq -c | awk '{print $2, $1}'
    ) | column -t 
    echo ""
}

relo_shard () {
    # move an indices' shard from node suffix X to node suffix Y
    local env="$1"
    local shardName="$2"
    local shardNum="$3"
    local fromCode="$4"
    local toCode="$5"
    usage_chk5 "$env" "$shardName" "$shardNum" "$fromCode" "$toCode" || return 1
    MOVE=$(cat <<-EOM
        {
            "commands" : [ {
                "move" :
                    {
                      "index" : "${shardName}",  "shard" : ${shardNum},
                      "from_node" : "${esnode[$env]}${fromCode}", "to_node" : "${esnode[$env]}${toCode}"
                    }
                }
            ]
        }
	EOM
    )
    cmdOutput=$(${escmd[$env]} POST '_cluster/reroute' -d "$MOVE")
    echo "${cmdOutput}" | grep -q '"acknowledged":true' && printf '{"acknowledged":true}\n' || echo "${cmdOutput}"
}

cancel_relo_shard () {
    # cancel move of an index shard from node suffix X
    local env="$1"
    local shardName="$2"
    local shardNum="$3"
    local fromCode="$4"
    usage_chk4 "$env" "$shardName" "$shardNum" "$fromCode" || return 1
    CANCEL=$(cat <<-EOM
        {
            "commands" : [ {
                "cancel" :
                    {
                      "index" : "${shardName}", "shard": ${shardNum},
                      "node": "${esnode[$env]}${fromCode}",
                      "allow_primary": true
                    }
                }
            ]
        }
	EOM
    )
    cmdOutput=$(${escmd[$env]} POST '_cluster/reroute?explain&pretty' -d "$CANCEL")
    echo "${cmdOutput}" | grep -q '"acknowledged":true' && printf '{"acknowledged":true}\n' || echo "${cmdOutput}"
}

cancel_relo_shards_all () {
    # cancel all shard RELOCATIONS in recovery queue
    local env="$1"
    usage_chk1 "$env" || return 1
    while read line; do
        local shardName="$(echo $line | awk '{print $1}')"
        local shardNum="$(echo $line  | awk '{print $2}')"
        local fromCode="$(echo $line  | rev | cut -d'-' -f1 | rev | sed 's/0//')"
        cancel_relo_shard "$env" "$shardName" "$shardNum" "$fromCode" 
    done < <(show_shards p | grep RELO | awk '{print $1,$2,$8}')
    
}

retry_unassigned_shards () {
    # reallocate all unassignable shards (elapsed past 5 retries)
    local env="$1"
    usage_chk1 "$env" || return 1
    cmdOutput=$(${escmd[$env]} POST '_cluster/reroute?retry_failed&explain&pretty')
    echo "${cmdOutput}" | less
}



#6-----------------------------------------------
# shard size analysis funcs
##-----------------------------------------------
show_shard_distribution_by_node_last3days () {
    # show distribution of day X's shards across nodes
    local env="$1"
    usage_chk1 "$env" || return 1

    cat <<-EOM

	429's (es_rejected_execution_exception)
	---------------------------------------
	Below shows the distribution of a given date's shards by node. If too many of a given days shards
	end up on the same node, you may enounter 429s, for e.g.:
	-------------------------------------------------------------------------------------------------------------

	    [2020-05-28T21:33:45,574][INFO ][logstash.outputs.elasticsearch][filebeat] retrying failed action with
	    response code: 429 ({"type"=>"es_rejected_execution_exception", "reason"=>"rejected execution of processing
	    of [2372784339][indices:data/write/bulk[s][p]]: request: BulkShardRequest [[filebeat-6.5.1-2020.05.28][13]]
	    containing [7] requests, target allocation id: basnD3RDQeurw3HJ-Ss0CQ, primary term: 1 on
	    EsThreadPoolExecutor[name = rdu-es-data-01j/write, queue capacity = 200,

	    org.elasticsearch.common.util.concurrent.EsThreadPoolExecutor@7b8b41e3[Running, pool size = 40, active
	    threads = 40, queued tasks = 200, completed tasks = 1321763404]]"})

	-------------------------------------------------------------------------------------------------------------

	Sources:
       - https://www.elastic.co/blog/performance-considerations-elasticsearch-indexing
       - https://www.elastic.co/guide/en/elasticsearch/reference/current/modules-threadpool.html


	EOM

    for day in {0..3}; do
        local YYmmdd="$(calc_date "${day} days ago")"
        printf "\n"
        printf "[DATE: %s]\n\n" "$YYmmdd"
        (
            printf "node #shards\n"
            printf -- "---- -------\n"
            show_shards "$env" | grep "$YYmmdd" | awk '{print $8}' | sort | uniq -c | awk '{print $2, $1}'
        ) | column -t
        printf "\n==============================================\n"
    done
    printf "\n\n"
}

show_hot_idxs_shard_distribution_by_node () {
    # show distribution of today's hot index shards across nodes
    local env="$1"
    usage_chk1 "$env" || return 1

    todayDate=$(calc_date '0 days')
    todayDay=$(echo "$todayDate" | cut -d'.' -f2-3)

    shardDetails=$(
        (
            printf "node indexType #shards\n"
            printf -- "---- --------- -------\n"
            show_shards "$env" | \
                grep "$todayDay" \
                | grep -vE '^\.|f5|heart|default' \
                | awk '{print $8, $1}' \
                | sed "s/-${todayDate}//g" \
                | sort -k1,2 \
                | uniq -c \
                | awk '{print $2, $3, $1}'
        ) | column -t
    )

    nodes="$(echo "$shardDetails" | grep -vE '^$|node|--' | awk '{print $1}' | sort -u)"

    colWidth="$(echo "$shardDetails" | grep '^node' | wc -c | awk '{print $1}')"
    # adjust to remove NEWLINE
    (( colWidth-- ))
    dividingLine="$(printf -- '-%.0s' $(seq $colWidth))"

    printf "\n\n[DATE: %s]\n\n" "$todayDate"

    colHeader="$(echo "$shardDetails" | grep -E '^node|^--')"
    printf "\n\n%s\n" "$colHeader"

    for node in $nodes; do
        echo "$shardDetails" | grep "$node"
        echo "$shardDetails" | awk -v node="${node}" '$1 == node {total += $3} END {printf("* * %0.0f\n"), total}'
    done \
        | column -t \
        | $sedCmd "s/\(^\* .*\)/${dividingLine} \n\1\n/g" \
        | sed 's/\*/ /g'

    printf "\n\n"
}



calc_hot_idxs_shard_sweet_spot () {
    # calculate optimal number of hot index shards per node
    local env="$1"
    usage_chk1 "$env" || return 1

    todayDate=$(calc_date '0 days')
    todayDay=$(echo "$todayDate" | cut -d'.' -f2-3)

    numDailyHotShards=$(show_shards "$env" |grep "$todayDay" | grep -vE '^\.|f5|heart|syslog' | wc -l)
    numNodes=$(list_nodes_storage "$env" | grep es-data | wc -l)
    printf "\n\n"
    printf "Optimal hot indexes' shards per node: %s\n\n\n" "$(ceiling_divide "$numDailyHotShards" "$numNodes")"
}

show_shards_biggerthan50gb () {
    # show shards which are > 50GB (too big)
    local env="$1"
    usage_chk1 "$env" || return 1

    shards=$(show_shards "$env")

    cat <<-EOM

	Shards > 50GB
	$(printf "%s\n\n\n" "$(printf '=%.0s' {1..100})")

	EOM

    {
        echo "$shards" | head -1
        echo "$shards" | grep 'gb ' | sed 's/gb / /' \
            | awk '$6 > 50 && sub("$", "gb", $6) || NR==1' \
            | sort -k6,6gr
    } | column -t
    printf "%s\n\n\n" "$(printf '=%.0s' {1..100})"
}

show_idx_with_oversized_shards_summary () {
    # show summary of indexes w/ shards > 50GB (too big)
    local env="$1"
    usage_chk1 "$env" || return 1

    printf "\n\n"
    printf "Daily Indicies w/ > 50GB shards"
    printf "\n\n"

    {
     printf "days IdxType\n"
     printf -- "---- -------\n"
    show_shards_biggerthan50gb "$env"  \
        | grep -vE  '===|^$|index|Shards' \
        | awk '{print $1}' \
        | sort -u \
        | sed 's/-[0-9]\{4\}.*//' \
        | uniq -c
    } | column -t

    printf "\n\n"
}

show_idx_with_oversized_shards_details () {
    # show detailed view of indexes w/ shards > 50GB (too big)
    local env="$1"
    usage_chk1 "$env" || return 1

    printf "\n\n"
    printf "Daily Indicies w/ shards (primaries) > 50GB"
    printf "\n\n"

    {
     printf "Idx Shard# ShardType ShardSize\n"
     printf -- "--- ------- -------- ---------\n"
     show_shards_biggerthan50gb "$env" \
         | grep -vE 'Shards|===|index' \
         | awk '$3 ~ /p/ {print $1, $2, $3, $6}' \
         | sort -k1,1; 
     } | column -t

    printf "\n\n"
}




#7-----------------------------------------------
# increase/decrease relo/recovery throttles
##-----------------------------------------------
show_balance_throttle () {
    # show routing allocations for balancing & recoveries (current)
    local env="$1"
    usage_chk1 "$env" || return 1
    showcfg_cluster "$env" | jq '.' | grep -E "allocation.(node|cluster|type)|recovery.max_bytes_per_sec"
}

#D increase_balance_throttle () {
#D     # increase routing allocations for balancing & recoveries (throttle open)
#D     local env="$1"
#D     usage_chk1 "$env" || return 1
#D     THROTTLEINC=$(cat <<-EOM
#D         {
#D             "persistent": {
#D                 "cluster.routing.allocation.cluster_concurrent_rebalance" : "10",
#D                 "cluster.routing.allocation.node_concurrent_incoming_recoveries" : "5",
#D                 "cluster.routing.allocation.node_concurrent_outgoing_recoveries" : "5",
#D                 "cluster.routing.allocation.node_concurrent_recoveries" : "20",
#D                 "cluster.routing.allocation.node_initial_primaries_recoveries" : "10",
#D                 "indices.recovery.max_bytes_per_sec" : "2000mb"
#D             }
#D         }
#D 	EOM
#D     )
#D     cmdOutput=$(${escmd[$env]} PUT '_cluster/settings' -d "$THROTTLEINC")
#D     showcfg_cluster "$env" | jq .persistent
#D }

increase_balance_throttle_XXXmb () {
    # increase bytes_per_sec routing allocations for balancing & recoveries (throttle, just b/w)
    local env="$1"
    local size="$2"
    usage_chk9 "$env" "$size" || return 1
    printf "\n\n"
    printf "NOTE: The default 'indices.recovery.max_bytes_per_sec' == 40mb, to reset to defaults use 'reset_balance_throttle'\n\n"
    THROTTLEINC=$(cat <<-EOM
        {
            "persistent": {
                "indices.recovery.max_bytes_per_sec" : "${size}mb"
            }
        }
	EOM
    )
    cmdOutput=$(${escmd[$env]} PUT '_cluster/settings' -d "$THROTTLEINC")
    showcfg_cluster "$env" | jq .persistent
}

reset_balance_throttle () {
    # reset routing allocations for balancing & recoveries (throttle default)
    local env="$1"
    usage_chk1 "$env" || return 1
    THROTTLERES=$(cat <<-EOM
        {
            "persistent": {
                "cluster.routing.allocation.cluster_concurrent_rebalance" : null,
                "cluster.routing.allocation.node_concurrent_*" : null,
                "cluster.routing.allocation.node_initial_primaries_recoveries" : null,
                "indices.recovery.max_bytes_per_sec" : null
            }
        }
	EOM
    )
    cmdOutput=$(${escmd[$env]} PUT '_cluster/settings' -d "$THROTTLERES")
    show_balance_throttle "$env"
    # REF: https://www.elastic.co/guide/en/elasticsearch/reference/current/cluster-get-settings.html
}

change_allocation_threshold () {
    # override the allocation threshold (cluster.routing.allocation.balance.threshold)
    local env="$1"
    usage_chk1 "$env" || return 1
    ALLOC=$(cat <<-EOM
        {
            "persistent": {
                "cluster.routing.allocation.balance.threshold"  :   3.0
            }
        }
	EOM
    )
    cmdOutput=$(${escmd[$env]} PUT '_cluster/settings' -d "$ALLOC")
    #showcfg_cluster "$env" | jq .persistent
    showcfg_shard_allocations "$env"
}



#8-----------------------------------------------
# recovery funcs
##-----------------------------------------------
show_recovery () {
    # show a summary of recovery queue
    local env="$1"
    usage_chk1 "$env" || return 1
    ${escmd[$env]} GET '_cat/recovery?bytes=gb&v&h=index,shard,time,type,stage,source_node,target_node,files,files_recovered,files_percent,bytes_total,bytes_percent,translog_ops_recovered,translog_ops,translog_ops_percent' \
        | grep -v done | head -40 | sed 's/[^ ]*es-data-//g' | column -t
}

show_recovery_full () {
    # show full details of recovery queue
    local env="$1"
    usage_chk1 "$env" || return 1
    ${escmd[$env]} GET '_cat/recovery?v' \
        | grep -v done | head -40
}


enable_readonly_idx_pattern () {
    # set index read_only flag for pattern of indices
    local env="$1"
    local idxArg="$2"
    usage_chk3 "$env" "$idxArg" || return 1
    DISALLOWDEL=$(cat <<-EOM
        {
         "index": {
           "blocks": {
             "read_only": "true"
            }
          }
        }
	EOM
    )
    ${escmd[$env]} PUT "${idxArg}/_settings" -d "$DISALLOWDEL"
}

disable_readonly_idx_pattern () {
    # clear index read_only flag for pattern of indices
    local env="$1"
    local idxArg="$2"
    usage_chk3 "$env" "$idxArg" || return 1
    ALLOWDEL=$(cat <<-EOM
        {
         "index": {
           "blocks": {
             "read_only": null
            }
          }
        }
	EOM
    )
    ${escmd[$env]} PUT "${idxArg}/_settings" -d "$ALLOWDEL"
}

enable_readonly_idxs () {
    # set index read_only flag
    local env="$1"
    usage_chk1 "$env" || return 1
    DISALLOWDEL=$(cat <<-EOM
        {
         "index": {
           "blocks": {
             "read_only": "true"
            }
          }
        }
	EOM
    )
    ${escmd[$env]} PUT '_all/_settings' -d "$DISALLOWDEL"
}

disable_readonly_idxs () {
    # clear index read_only flag
    local env="$1"
    usage_chk1 "$env" || return 1
    ALLOWDEL=$(cat <<-EOM
        {
         "index": {
           "blocks": {
             "read_only": null
            }
          }
        }
	EOM
    )
    ${escmd[$env]} PUT '_all/_settings' -d "$ALLOWDEL"
}

show_readonly_idxs () {
    # show indexes' read_only setting which are enabled (true)
    local env="$1"
    usage_chk1 "$env" || return 1
    printf "\nindices with read_only flag set (true)"
    printf "\n---------------------------------------------------\n"
    show_readonly_idxs_full "$env" | grep -v false
    printf "\n--------- end of check ----------------------------\n\n"
}

show_readonly_idxs_full () {
    # show indexes' read_only setting for all indices
    local env="$1"
    usage_chk1 "$env" || return 1
    ${escmd[$env]} GET '_all/_settings?pretty&include_defaults&filter_path=*.*.*.*.read_only' \
        | grep -Ev '^{|^}' \
        | paste - - - - - - - - - \
        | $sedCmd -e 's/: {[ \t]\+/:{ /g' -e 's/[ \t]\+}/ }/g' \
        | column -t \
        | sort
}

clear_readonlyallowdel_idxs () {
    # clear read_only_allow_delete flag
    local env="$1"
    usage_chk1 "$env" || return 1
    ALLOWDEL=$(cat <<-EOM
        {
         "index": {
           "blocks": {
             "read_only_allow_delete": null
            }
          }
        }
	EOM
    )
    ${escmd[$env]} PUT '_all/_settings' -d "$ALLOWDEL"
}

set_idx_default_field () {
    # set index.query.default_field => [ "*" ]
    local env="$1"
    local idxArg="$2"
    usage_chk3 "$env" "$idxArg" || return 1
    DEFFIELD=$(cat <<-EOM
        {
         "index": {
           "query": {
             "default_field": [ "*" ]
            }
          }
        }
	EOM
    )
    ${escmd[$env]} PUT "${idxArg}/_settings" -d "$DEFFIELD"
}

set_tmplate_default_field () {
    # set template index.query.default_field => [ "*" ]
    local env="$1"
    local idxArg="$2"
    usage_chk3 "$env" "$idxArg" || return 1
    DEFFIELD=$(cat <<-EOM
        {
         "index": {
           "query": {
             "default_field": [ "*" ]
            }
          }
        }
	EOM
    )
    ${escmd[$env]} PUT "${idxArg}/_settings" -d "$DEFFIELD"
}

set_idx_shards_per_node () {
    # set index.routing.allocation.total_shards_per_node = X
    local env="$1"
    local idxArg="$2"
    local numShards="$3"
    usage_chk11 "$env" "$idxArg" "$numShards" || return 1
    SHARDSNODEFIELD=$(cat <<-EOM
        {
         "index": {
           "routing": {
             "allocation": {
               "total_shards_per_node": "$numShards"
             }
            }
          }
        }
	EOM
    )
    ${escmd[$env]} PUT "${idxArg}/_settings" -d "$SHARDSNODEFIELD"

    # REF:
    #   - https://www.elastic.co/guide/en/elasticsearch/reference/current/allocation-total-shards.html
    #   - https://www.elastic.co/guide/en/elasticsearch/reference/current/shard-allocation-filtering.html
}

set_idx_num_replicas_to_X () {
    # set an index's number_of_replicas to X
    local env="$1"
    local idxArg="$2"
    local numReps="$3"
    usage_chk7 "$env" "$idxArg" "$numReps" || return 1
    NUMREP=$(cat <<-EOM
        {
         "index": {
           "number_of_replicas": ${numReps}

          }
        }
	EOM
    )
    ${escmd[$env]} PUT "${idxArg}/_settings?pretty" -d "$NUMREP"
           #"auto_expand_replicas": "0-1",
           #"auto_expand_replicas": false,
}



#9-----------------------------------------------
# health/stat funcs
##-----------------------------------------------
estop () {
    # mimics `top` command, watching ES nodes CPU/MEM usage
    local env="$1"
    usage_chk1 "$env" || return 1
    watch "${escmd[$env]} GET '_cat/nodes?v&h=ip,heap.percent,ram.percent,cpu,load_1m,load_5m,load_15m,node.role,master,name,nodeId,diskAvail'"
}

estop_recovery () {
    # watches the ES recovery queue
    local env="$1"
    usage_chk1 "$env" || return 1
    watch "${escmd["$env"]} GET '_cat/recovery?bytes=gb&v&h=index,shard,time,type,stage,source_node,target_node,files,files_recovered,files_percent,bytes_total,bytes_percent,translog_ops_recovered,translog_ops,translog_ops_percent&s=target_node,source_node,index' | grep -v done | head -40 | sed 's/[^ ]*es-data-//g' | column -t"
}

estop_relo () {
    # watches ES relocations
    local env="$1"
    usage_chk1 "$env" || return 1
    watch "${escmd["$env"]} GET '_cat/shards?v&h=index,shard,prirep,state,docs,store,node&s=index:desc' | grep -v STARTED | head -40"
}

estop_tasks () {
    # watches ES tasks
    local env="$1"
    usage_chk1 "$env" || return 1
    watch "${escmd["$env"]} GET '_cat/tasks?pretty&v&h=action,type,running_time,node' | head -40"
}

estop_rejected_writes () {
    # watches ES write thread pools for rejected writes (EsRejectedExecutionException)
    local env="$1"
    usage_chk1 "$env" || return 1
    watch -d "${escmd["$env"]} GET '_cat/thread_pool?v&h=node_name,name,active,rejected,completed'  \
        | grep -E 'write|completed' \
        | awk 'NR == 1; NR > 1 {print \$0 | \"sort -k4,4gr\"}' \
        | head -40"
}

estop_active_threads () {
    # watches ES thread pools for active/rejected activities
    local env="$1"
    usage_chk1 "$env" || return 1
    watch "${escmd[$env]} GET '_cat/thread_pool?v&h=node_name,name,active,rejected,completed&s=node_name' \
		| grep -v '0[ ]\+0[ ]\+[0-9]' \
        | grep -v master- \
        | head -40"
}

show_health () {
    # cluster's health stats
    local env="$1"
    usage_chk1 "$env" || return 1
    ${escmd[$env]} GET '_cluster/health?pretty'
}

show_watermarks () {
    # show watermarks when storage marks readonly
    local env="$1"
    usage_chk1 "$env" || return 1
    ${escmd[$env]} GET '_cluster/settings?pretty&flat_settings=true&include_defaults=true' | grep watermark

    cat <<-EOM


    Disk-based shard allocation settings
    ------------------------------------
    Elasticsearch considers the available disk space on a node before deciding whether to allocate new shards to 
    that node or to actively relocate shards away from that node.
    -------------------------------------------------------------------------------------------------------------
      * cluster.routing.allocation.disk.watermark.low
                Controls the low watermark for disk usage. It defaults to 85%, meaning that Elasticsearch 
                will not allocate shards to nodes that have more than 85% disk used. It can also be set to 
                an absolute byte value (like 500mb) to prevent Elasticsearch from allocating shards if 
                less than the specified amount of space is available. This setting has no effect on the 
                primary shards of newly-created indices but will prevent their replicas from being allocated.
    -------------------------------------------------------------------------------------------------------------
      * cluster.routing.allocation.disk.watermark.high
                Controls the high watermark. It defaults to 90%, meaning that Elasticsearch will attempt to 
                relocate shards away from a node whose disk usage is above 90%. It can also be set to an 
                absolute byte value (similarly to the low watermark) to relocate shards away from a node if 
                it has less than the specified amount of free space. This setting affects the allocation of 
                all shards, whether previously allocated or not.
    -------------------------------------------------------------------------------------------------------------
      * cluster.routing.allocation.disk.watermark.flood_stage
                Controls the flood stage watermark, which defaults to 95%. Elasticsearch enforces a read-only 
                index block (index.blocks.read_only_allow_delete) on every index that has one or more 
                shards allocated on the node, and that has at least one disk exceeding the flood stage. 
                This setting is a last resort to prevent nodes from running out of disk space. The index 
                block is automatically released when the disk utilization falls below the high watermark.
    -------------------------------------------------------------------------------------------------------------
      *NOTE*
                You cannot mix the usage of percentage values and byte values within these settings. Either 
                all values are set to percentage values, or all are set to byte values. This enforcement is so 
                that Elasticsearch can validate that the settings are internally consistent, ensuring that the 
                low disk threshold is less than the high disk threshold, and the high disk threshold is less 
                than the flood stage threshold.
    -------------------------------------------------------------------------------------------------------------

    Source: https://www.elastic.co/guide/en/elasticsearch/reference/current/modules-cluster.html#disk-based-shard-allocation


	EOM
}

show_state () {
    # shows the state of the indicies' shards (RELO, Translog, etc.)
    local env="$1"
    usage_chk1 "$env" || return 1
    ${escmd[$env]} GET '_cat/shards?bytes=gb&v&human' | grep -v STARTED
}

showcfg_cluster () {
    # show all '_cluster/settings' configs
    local env="$1"
    usage_chk1 "$env" || return 1
    ${escmd[$env]} GET '_cluster/settings?pretty&flat_settings=true&include_defaults=true'
}

showrecov_stats () {
    # show recovery stats (_recovery)
    local env="$1"
    usage_chk1 "$env" || return 1
    ${escmd[$env]} GET '/_recovery?pretty' | jq -C . | less -r
}

shorecov_hot_threads () {
    # show hot thread details
    local env="$1"
    usage_chk1 "$env" || return 1
    ${escmd[$env]} GET '_nodes/_local/hot_threads'
}

shorecov_idx_shard_stats () {
    # show an index's shard stats
    local env="$1"
    local idxArg="$2"
    usage_chk3 "$env" "$idxArg" || return 1
    ${escmd[$env]} GET ${idxArg}'/_stats?level=shards&pretty' | jq -C . | less -r
}

show_stats_cluster () {
    # shows the _stats for entire cluster
    local env="$1"
    usage_chk1 "$env" || return 1
    ${escmd[$env]} GET '_stats?human&pretty' | jq -C . | less -r
}

show_tasks_stats () {
    # shows the tasks queue
    local env="$1"
    usage_chk1 "$env" || return 1
    ${escmd[$env]} GET '_cat/tasks?human&pretty&detailed&v'
}

verify_idx_retentions () {
    # shows the distribution of index retentions (days per index type & version)
    local env="$1"
    usage_chk1 "$env" || return 1

    printf "\nNOTE: Shows how many days worth of logs per index. Some indices have multiple versions per index type.\n"

    for idx in filebeat packetbeat metricbeat heartbeat messaging test; do
        printf "\n$idx\n==========\n"
        idxDetails=$(show_idx_sizes "$env")
        now=$(date -u +%Y%m%d)
        futureIdxCnt=$(echo "$idxDetails" | grep ^$idx \
            | cut -d" " -f1 | cut -d- -f3 | sed 's/\.//g' \
            | awk -v DATE="$now" '$1 > DATE' | wc -l | awk '{print $1}')
        echo "$idxDetails" | grep ^$idx | cut -d"-" -f2 | sort | uniq -c
        echo ''
        [[ $futureIdxCnt = 0 ]] || echo "Indexes dated in future: $futureIdxCnt"
        echo ''
    done
    idx=syslog; printf "\n$idx\n==========\n%s\n\n\n" "$(show_idx_sizes "$env" | grep "$idx" | wc -l)"
    idx=f5;     printf "\n$idx\n==========\n%s\n\n\n" "$(show_idx_sizes "$env" | grep "$idx" | cut -d"-" -f2 | wc -l)"

    printf 'NOTE: To see more detailed view, use show_idx_sizes <l|p|c> | grep "<filebeat|metricbeat|...>"\n\n\n\n'
}

show_idx_retention_violations () {
    # shows the indexes which fall outside a given retention window (days)
    local env="$1"
    local idxArg="$2"
    local daysToRetain="$3"
    usage_chk8 "$env" "$idxArg" "$daysToRetain" || return 1

    indexes=$(show_idx_sizes "$env" | grep ^"$idxArg" | sort)

    olderThanDate=$(calc_date "${daysToRetain} days ago")
    newerThanDate=$(calc_date "0 days")

    for idxSubType in $(echo "$indexes" | awk '{print $1}' | cut -d"-" -f2 | sort -u); do
        printf "\n\n"
        printf "Indices outside %s day(s) retention window\n" "$daysToRetain"
        printf "==========================================\n"
        printf "Index Sub-Type: [%s]\n" "${idxSubType}"
        printf "==========================================\n\n"
        for idx in $(echo "$indexes" | grep -oE "${idxArg}-${idxSubType}-\d+.\d+.\d+"); do 
            [[ "${idx}" < "${idxArg}-${idxSubType}-${olderThanDate}" ]] && echo "${idx}"
            [[ "${idx}" > "${idxArg}-${idxSubType}-${newerThanDate}" ]] && echo "${idx}"
        done
    done
}

show_idx_doc_sources_1st_10k () {
    # show the hostnames that sent documents to an index
    local env="$1"
    local idxArg="$2"
    usage_chk3 "$env" "$idxArg" || return 1

    totalCnt=$(${escmd[$env]} GET ${idxArg}'/_count' | jq '.count')

    printf "\n\n"
    printf "Document sources (1st 10)\n"
    printf "=========================\n"
    printf "Total Docs: [%s]\n" "$totalCnt"
    printf "=========================\n\n"

    ${escmd[$env]} GET ${idxArg}'/_search?size=10' \
        | jq '. | .hits.hits[] | [._index, ._source.beat.hostname, ._source."@timestamp"]' \
        | paste - - - - -  \
        | column -t
    printf "\n\n"
}

#show_idx_doc_sources_all_cnts l filebeat-6.5.1-2020.05.22 | grep -vE "ocp|es-da" | head -30
#show_idx_doc_sources_all_cnts l filebeat-6.5.1-2020.05.22 | grep -E "ocp" | head -30

show_idx_doc_sources_all_cnts () {
    # show the total num. docs each hostname sent to an index
    local env="$1"
    local idxArg="$2"
    usage_chk3 "$env" "$idxArg" || return 1

    printf "\n\n"
    printf "Document sources (counts)\n"
    printf "===================================\n"
    printf "Idx: [%s]\n" "$idxArg"
    printf "===================================\n\n"

    #TODO - improve query below 
    #  - https://www.elastic.co/guide/en/elasticsearch/reference/current/search-aggregations-bucket-terms-aggregation.html
    ${escmd[$env]} GET ${idxArg}'/_search?pretty' -d \
        '{
          "size": 0,
          "aggs": {
            "hosts": {
                "terms" : { "field": "beat.hostname",  "size": 100000000 }
            }
          }
        }' | jq '.aggregations.hosts.buckets | .[]' | paste - - - -  | sed -e 's/[",]//g' | column -t
    printf "\n\n"
}

show_idx_doc_sources_all_k8sns_cnts () {
    # show the total num. docs each namespace sent to an index
    local env="$1"
    local idxArg="$2"
    usage_chk3 "$env" "$idxArg" || return 1

    timestamp=$(echo "${idxArg}" | sed -e 's/.*-//' -e 's/\./-/g')

    printf "\n\n"
    printf "k8s document sources (counts)\n"
    printf "=============================\n\n"

#    ${escmd[$env]} GET ${idxArg}'/_search?pretty' -d \
#        '{
#          "size": 0,
#          "aggs": {
#            "k8sns": {
#                "terms" : { "field": "kubernetes.namespace",  "size": 500 }
#            }
#          }
#        }' | jq '.aggregations.k8sns.buckets | .[]' | paste - - - -  | column -t

#    ${escmd[$env]} GET ${idxArg}'/_search?pretty' -d \
#        '{
#          "size": 0,
#          "aggs" : {
#            "sales_over_time" : {
#                "date_histogram" : {
#                    "field" : "kubernetes.namespace",
#                    "calendar_interval" : "1d"
#                }
#            }
#          } 
#        }' #| jq '.aggregations.k8sns.buckets | .[]' #| paste - - - -  | column -t
    SEARCHQUERY=$(cat <<-EOM
		{
		  "size": 0,
		  "query" : {
		    "range": {
		      "@timestamp": {
                "gte": "$(echo "$timestamp" | sed 's/\./-/g')",
                "lte": "$(echo "$timestamp" | sed 's/\./-/g')"
		      }
		    }
		  },
		  "aggs": {
		    "k8sns": {
		        "terms" : { "field": "kubernetes.namespace",  "size": 100 },
		        "aggs": {
		          "daily_buckets": {
		            "date_histogram": {
		              "field": "@timestamp",
		              "calendar_interval": "1d"
		            }
		          }
		        }
		    }
		  }
        }
	EOM
    )
    cmdOutput=$(${escmd[$env]} GET ${idxArg}'/_search?pretty' -d "$SEARCHQUERY")
    echo "$cmdOutput" \
        | jq '.aggregations.k8sns.buckets[] | .key, .daily_buckets.buckets[].key_as_string, .daily_buckets.buckets[].doc_count' \
        | paste - - -  \
        | column -t
    printf "\n\n"
}

show_idx_doc_sources_all_k8sns_cnts_hourly () {
    # show the total num. docs each namespace sent to an index
    local env="$1"
    local idxArg="$2"
    usage_chk3 "$env" "$idxArg" || return 1

    printf "\n\n"
    printf "k8s document sources (counts - hourly)\n"
    printf "======================================\n\n"

    SEARCHQUERY=$(cat <<-EOM
		{
		  "size": 0,
		  "query" : {
		    "range": {
		      "@timestamp": {
                "gte": "$(calc_hour '3 hours ago')",
                "lte": "$(calc_hour '0 hours ago')"
		      }
		    }
		  },
		  "aggs": {
		    "k8sns": {
		        "terms" : { "field": "kubernetes.namespace",  "size": 10 },
		        "aggs": {
		          "hourly_buckets": {
		            "date_histogram": {
		              "field": "@timestamp",
		              "calendar_interval": "1h"
		            }
		          }
		        }
		    }
		  }
        }
	EOM
    )
    cmdOutput=$(${escmd[$env]} GET ${idxArg}'/_search?pretty' -d "$SEARCHQUERY")
    echo "$cmdOutput" \
        | jq '.aggregations.k8sns.buckets[] | .key, .hourly_buckets.buckets[] | .' \
        | grep -v '"key"' \
        | paste - - - - - - - - - - - - - - - - \
        | $sedCmd 's/[ \t]\+[{}]\+[ \t]\+/ /g' \
        | $sedCmd 's/[ \t]\+[}{]\+[ \t]\+/ /g' #\
        #| column -t
    #    | jq '.aggregations.k8sns.buckets[] | .key, .hourly_buckets.buckets[].key_as_string, .hourly_buckets.buckets[].doc_count' \
    #    | paste - - -  \
    #    | column -t
    printf "\n\n"
}



#10----------------------------------------------
# shard funcs
##-----------------------------------------------
showcfg_num_shards_per_idx () {
    # show number of shards configured per index template
    local env="$1"
    usage_chk1 "$env" || return 1
    ${escmd[$env]} GET '_template/*?pretty&filter_path=*.*.*.number_of_shards' | \
        paste - - - - - - - | \
        column -t | grep -v '}   }' | sort
}

showcfg_shard_allocations () {
    # show cluster level shard allocation configs
    local env="$1"
    usage_chk1 "$env" || return 1
    printf "\nREFS\n----\n - %s\n - %s\n" \
        "https://www.elastic.co/guide/en/elasticsearch/reference/current/shards-allocation.html#_shard_allocation_settings" \
        "https://www.elastic.co/guide/en/elasticsearch/reference/current/disk-allocator.html"

    printf "\nShard Allocation Settings\n-------------------------\n"
    showcfg_cluster "$env" | grep -E "cluster.routing.allocation.(enable|node_concurrent|node_initial_primaries|same_shard.host)|recovery.max_bytes_per_sec"

    printf "\nShard Rebalancing Settings\n--------------------------\n"
    showcfg_cluster "$env" | grep -E "cluster.routing.*(rebalance|allow_rebalance|cluster_concurrent_rebalance)"

    printf "\nShard Balancing Settings\n------------------------\n"
    showcfg_cluster "$env" | grep -E "cluster.routing.allocation.balance"

    printf "\nDisk-based Shard Settings\n-------------------------\n"
    showcfg_cluster "$env" | grep -E "disk.watermark|cluster.info.update.interval|allocation.disk.include_relocations"

    printf "\n"
}

explain_allocations () {
    # show details (aka. explain) cluster allocation activity
    local env="$1"
    usage_chk1 "$env" || return 1
    ${escmd[$env]} GET '_cluster/allocation/explain?pretty' | jq -C . | less -r
}

explain_allocations_hddinfo () {
    # show details (aka. explain) cluster allocation activity (full)
    local env="$1"
    local idxArg="$2"
    usage_chk3 "$env" "$idxArg" || return 1
    EXPLAINL=$(cat <<-EOM
        {
            "index": "${idxArg}",
            "shard": 0,
            "primary": false
        }
	EOM
    )
    ${escmd[$env]} GET '_cluster/allocation/explain?pretty&human&include_yes_decisions=true' \
        -d "$EXPLAIN" | jq -C . | less -r
}

#$ ./esp GET '_cluster/allocation/explain?pretty&include_disk_info=true&include_yes_decisions=true&human' -d '{"index":"filebeat-6.2.2-2019.05.05", "shard": 0, "primary": true}'| jq -C '.cluster_info.shard_sizes | with_entries(select(.key|test("_bytes")|not))' | head
#{
#  "[metricbeat-6.6.1-2019.05.11][4][p]": "17mb",
#  "[filebeat-6.6.1-2019.05.18][4][p]": "4.2mb",
#  "[syslog-2019.05.23][0][r]": "74.4gb",
#  "[filebeat-6.6.1-2019.06.15][3][r]": "5.4mb",
#  "[filebeat-6.6.1-2019.04.20][2][r]": "4.1mb",
#  "[syslog-2019.05.01][0][r]": "58gb",
#  "[packetbeat-6.5.1-2019.05.19][0][r]": "25.8gb",
#  "[filebeat-6.5.1-2019.06.16][1][p]": "14.4gb",
#  "[filebeat-6.6.1-2019.05.24][2][r]": "4.2mb",
#
#$ ./esp GET '_cluster/allocation/explain?pretty&include_yes_decisions=true&human' -d '{"index":"filebeat-6.2.2-2019.05.05", "shard": 0, "primary": true}'| jq -C '.' | head
#{
#  "index": "filebeat-6.2.2-2019.05.05",
#  "shard": 0,
#  "primary": true,
#  "current_state": "started",
#  "current_node": {
#    "id": "dsL3ZeMeQqmvigirSYy6Tw",
#    "name": "rdu-es-data-01a",
#    "transport_address": "192.168.33.195:9300",
#    "attributes": {
#
# https://github.com/stedolan/jq/issues/966

show_shard_routing_allocation () {
    # show status (cluster.routing.allocation.enable)
    local env="$1"
    usage_chk1 "$env" || return 1
    showcfg_shard_allocations $env | grep cluster.routing.allocation.enable
}

enable_shard_allocations () {
    # allow the allocator to route shards (cluster.routing.allocation.enable)
    local env="$1"
    usage_chk1 "$env" || return 1
    ALLOW=$(cat <<-EOM
        {
         "transient": {
           "cluster.routing.allocation.enable":   "all"
         }
        }
	EOM
    )
    ${escmd[$env]} PUT '_cluster/settings' -d "$ALLOW"
}

disable_shard_allocations () {
    # disallow the allocator to route shards (cluster.routing.allocation.enable)
    local env="$1"
    usage_chk1 "$env" || return 1
    DISALLOW=$(cat <<-EOM
        {
         "transient": {
           "cluster.routing.allocation.enable":   "none"
         }
        }
	EOM
    )
    ${escmd[$env]} PUT '_cluster/settings' -d "$DISALLOW"
}

clear_shard_allocations () {
    # clear the allocator to route shards (cluster.routing.allocation.enable)
    local env="$1"
    usage_chk1 "$env" || return 1
    CLEAR=$(cat <<-EOM
        {
         "persistent": {
           "cluster.routing.allocation.enable":    null
         }
        }
	EOM
    )
    ${escmd[$env]} PUT '_cluster/settings' -d "$CLEAR"
}



#11----------------------------------------------
# index stat funcs
##-----------------------------------------------
show_idx_sizes () {
    # show index sizes sorted (big -> small)
    local env="$1"
    usage_chk1 "$env" || return 1
    ${escmd[$env]} GET '_cat/indices?v&h=index,pri,rep,docs.count,store.aize,pri.store.size&human&s=store.size:desc&bytes=gb'
}

show_idx_stats () {
    # show index stats sorted (big -> small)
    local env="$1"
    usage_chk1 "$env" || return 1
    ${escmd[$env]} GET '_cat/indices?pretty&v&s=pri.store.size:desc'
}

delete_idx () {
    # delete an index
    local env="$1"
    local idxArg="$2"
    usage_chk3 "$env" "$idxArg" || return 1
    ${escmd[$env]} DELETE "$idxArg"
}

showcfg_idx_cfgs () {
    # show all '<index name>/_settings' configs
    local env="$1"
    local idxArg="$2"
    usage_chk3 "$env" "$idxArg" || return 1
    ${escmd[$env]} GET ${idxArg}'/_settings?pretty&flat_settings=true&include_defaults=true' | jq -C . | less -r
}

showcfg_idx_stats () {
    # show all '<index name>/_stats'
    local env="$1"
    local idxArg="$2"
    usage_chk3 "$env" "$idxArg" || return 1
    ${escmd[$env]} GET ${idxArg}'/_stats?pretty' | jq -C . | less -r
}

show_idx_version_cnts () {
    # show index sizes sorted (big -> small)
    local env="$1"
    usage_chk1 "$env" || return 1
    (
    printf "\n%10s%10s"   "occurrences" "index"
    printf "\n%10s%10s\n" "-----------" "-----"
    show_idx_sizes "$env" | awk '{print $1}' | \
        grep -E 'beat|f5|syslog' | \
        grep -v '^\.' | sed 's/-2019.*//' | sort | uniq -c
    printf "\n"
    ) | column -t
}

show_idx_mappings () {
    # show an index's _mappings (flattened) '<index name>/_mapping'
    local env="$1"
    local idxArg="$2"
    usage_chk3 "$env" "$idxArg" || return 1

    #${escmd[$env]} GET ${idxArg}'/_mapping?pretty' | jq -C . | less -r
    ${escmd[$env]} GET ${idxArg}'/_mapping?pretty' \
        | jq -C '
            .[].mappings | .properties 
            | [leaf_paths as $path | {"key": $path | join("."), "value": getpath($path)}] 
            | from_entries
          ' \
        | less -r
}



#12----------------------------------------------
# field funcs
##-----------------------------------------------
show_field_capabilities () {
    # show field capabilities (type, searchable, aggregatable) for index pattern
    local env="$1"
    local idxArg="$2"
    usage_chk3 "$env" "$idxArg" || return 1

    colWidth="120"

    printf "\n\n"
    (
        printf "field type searchable aggregatable\n"
        printf -- "----- ---- ---------- ------------\n"
        ${escmd[$env]} GET ${idxArg}'/_field_caps?fields=*&pretty' \
            | jq '.fields' \
            | paste - - - - - - - \
            | $sedCmd 's/:[ \t]\+{.*{//g;s/^{[ \t]\+//g;s/^[ \t]\+},[ \t]\+//g;s/[ \t]\+}$//g;s/[ \t]\+}[ \t]\+}//g' \
            | $sedCmd 's/"type":\|"searchable":\|"aggregatable":\|"\|,//g' \
            | sort -k1,1
    ) | column -t

    printf "%s\n\n\n" "$(printf '=%.0s' $(seq 1 ${colWidth}))"
    # REF: https://www.elastic.co/guide/en/elasticsearch/reference/current/search-field-caps.html
}

show_fields_multiple_defs_summary () {
    # list of fields with multiple capabilities defs. for index pattern
    local env="$1"
    local idxArg="$2"
    usage_chk3 "$env" "$idxArg" || return 1

    colWidth="50"

    printf "\n\n"
    (
        printf "field capabilityDefCount\n"
        printf -- "----- ------------------\n"
        ${escmd[$env]} GET ${idxArg}'/_field_caps?fields=*&pretty' \
            | jq -r '.fields | to_entries | .[] | .key, (.value | length)' \
            | paste - - \
            | grep -v 1 \
            | sort -k1,1
    ) | column -t
    printf "\n\n"
}

show_fields_multiple_defs_details () {
    # detailed view of fields with multiple capabilities defs. for index pattern
    local env="$1"
    local idxArg="$2"
    usage_chk3 "$env" "$idxArg" || return 1

    colWidth="50"

    problemFields="$(show_fields_multiple_defs "$env" "$idxArg" | grep -vE '^$|field|^---' | awk '{print $1}')"

    printf "\n\n"
    for field in $problemFields; do
        printf "[FIELD: %s]\n" "$field"
        printf "%s\n" "$(printf -- '-%.0s' $(seq 1 ${colWidth}))"

        ${escmd[$env]} GET ${idxArg}"/_field_caps?fields=${field}&pretty" \
            | jq -r ".fields | .\"${field}\""

        printf "%s\n\n\n" "$(printf '=%.0s' $(seq 1 ${colWidth}))"
    done
    printf "\n\n"
}

show_field_X_multiple_defs_details () {
    # detailed view of a single field's multiple capabilities defs. for index pattern
    local env="$1"
    local idxArg="$2"
    local field="$3"
    usage_chk12 "$env" "$idxArg" "$field" || return 1

    colWidth="50"

    printf "\n\n"
    printf "[FIELD: %s]\n" "$field"
    printf "%s\n" "$(printf -- '-%.0s' $(seq 1 ${colWidth}))"

     ${escmd[$env]} GET ${idxArg}"/_field_caps?fields=${field}&pretty" \
         | jq -r ".fields | .\"${field}\""

     printf "%s\n\n\n" "$(printf '=%.0s' $(seq 1 ${colWidth}))"
    printf "\n\n"
}

show_fields () {
    # Return a list of fields in a given index pattern
    local env="$1"
    local idxArg="$2"
    usage_chk3 "$env" "$idxArg"  return 1

    printf "Unique fields in '${idxArg}': "
    ${escmd[$env]} GET ${idxArg}'/_field_caps?fields=*&filter_path=fields' \
        | jq '.fields | keys'
    printf "\n\n"

}

show_field_count () {
    # Return a count of fields in a given index pattern
    local env="$1"
    local idxArg="$2"
    usage_chk3 "$env" "$idxArg"  return 1

    printf "Unique count of fields in '${idxArg}': "
    ${escmd[$env]} GET ${idxArg}'/_field_caps?fields=*&filter_path=fields' \
        | jq '.fields | length'
}

#13----------------------------------------------
# node exclude/include funcs
##-----------------------------------------------
show_excluded_nodes () {
    # show excluded nodes from cluster
    local env="$1"
    usage_chk1 "$env" || return 1
    showcfg_cluster "$env" | grep allocation.exclude
}

exclude_node_name () {
    # exclude a node from cluster (node suffix)
    local env="$1"
    local node="$2"
    usage_chk2 "$env" "$node" || return 1

    output=$(${escmd[$env]} GET '_cat/nodes?v&h=ip,name')
    ip=$(echo "${output}"   | awk -v n="$node" '$0 ~ n {print $1}')
    name=$(echo "${output}" | awk -v n="$node" '$0 ~ n {print $2}')

    EXCLUDENAME=$(cat <<-EOM
        {
         "transient": {
           "cluster.routing.allocation.exclude._ip":   "$ip",
           "cluster.routing.allocation.exclude._name": "$name"
         }
        }
	EOM
    )
    ${escmd["$env"]} PUT  '_cluster/settings' -d "$EXCLUDENAME"
}

clear_excluded_nodes () {
    # clear any excluded cluster nodes
    local env="$1"
    usage_chk1 "$env" || return 1

    EXCLUDENAME=$(cat <<-EOM
        {
         "transient": {
           "cluster.routing.allocation.exclude._ip":   null,
           "cluster.routing.allocation.exclude._name": null
         }
        }
	EOM
    )
    ${escmd["$env"]} PUT  '_cluster/settings' -d "$EXCLUDENAME"
}



#14----------------------------------------------
# auth funcs
##-----------------------------------------------
eswhoami () {
    # show auth info about who am i
    local env="$1"
    usage_chk1 "$env" || return 1
    ${escmd["$env"]} GET '_xpack/security/_authenticate?pretty'
}

showcfg_auth_roles () {
    # show auth info about roles
    local env="$1"
    usage_chk1 "$env" || return 1
    ${escmd["$env"]} GET '_xpack/security/role?pretty'
}

showcfg_auth_rolemappings () {
    # show auth info about role mappings
    local env="$1"
    usage_chk1 "$env" || return 1
    ${escmd["$env"]} GET '_xpack/security/role_mapping?pretty'
}

list_auth_roles () {
    # list all roles
    local env="$1"
    usage_chk1 "$env" || return 1
    ${escmd["$env"]} GET "_xpack/security/role?pretty" | jq 'to_entries[] | .key' | sed "s/\"//g" | sort
}

list_auth_rolemappings () {
    # list all rolemappings
    local env="$1"
    usage_chk1 "$env" || return 1
    ${escmd["$env"]} GET "_xpack/security/role_mapping?pretty" | jq 'to_entries[] | .key' | sed "s/\"//g" | sort
}

evict_auth_cred_cache () {
    # evict/clear users from the user cache
    local env="$1"
    usage_chk1 "$env" || return 1
    ${escmd["$env"]} POST '_xpack/security/realm/ldap1/_clear_cache?pretty'
    # https://www.elastic.co/guide/en/elasticsearch/reference/6.5/security-api-clear-cache.html
}

create_bearer_token () {
    # create bearer token for user
    local env="$1"
    usage_chk1 "$env" || return 1
    CREDS=$(cat <<-EOM
        {
         "grant_type": "password",
         "username"  : "XXXXXXXX",
         "password"  : "YYYYYYYY"
        }
	EOM
    )
    ${escmd["$env"]} POST '_xpack/security/oauth2/token?pretty' -d "$CREDS"
}



#15----------------------------------------------
# k8s namespace funcs
##-----------------------------------------------
del_docs_k8s_ns_range () {
    # delete k8s namespace docs over a specific time range
    local env="$1"
    local idxArg="$2"
    local ns="$3"
    local stime="$4"
    local etime="$5"
    usage_chk6 "$env" "$idxArg" "$ns" "$stime" "$etime" || return 1

    DELQUERY=$(cat <<-EOM
        {
          "query": {
            "bool": {
              "must": [
                {
                  "match_phrase": {
                    "kubernetes.namespace": {
                      "query": "${ns}"
                    }
                  }
                },
                {
                  "range": {
                    "@timestamp": {
                      "format": "strict_date_optional_time",
                      "gte": "${stime}",
                      "lte": "${etime}"
                    }
                  }
                }
              ]
            }
          }
        }
	EOM
    )
    ${escmd["$env"]} POST "${idxArg}/_delete_by_query?conflicts=proceed&wait_for_completion=false" -d "$DELQUERY"
}

forcemerge_to_expunge_deletes () {
    # force merge of shards to expunge deleted docs
    local env="$1"
    local idxArg="$2"
    usage_chk3 "$env" "$idxArg" || return 1
    ${escmd["$env"]} POST "${idxArg}/_forcemerge?only_expunge_deletes=true"
}

estail_deletebyquery () {
    # watch deletebyquery tasks
    local env="$1"
    usage_chk1 "$env" || return 1
    clear && cnt=0
    while [ 1 ]; do
        cnt=$((cnt+1))
        [ $cnt -eq 5 ] && clear && cnt=0
        cmd=$(${escmd["$env"]} GET '_cat/tasks?pretty&v&h=action,type,running_time,node' | grep 'delete/byquery')
        status=$?

        echo "${FUNCNAME[0]}"
        echo "==================================="
        echo "$cmd" | column -t
        [ $status -ne 0 ] && echo "done" && break
        echo "==================================="
        sleep 10
    done
}

estail_forcemerge () {
    # watch forcemerges in tasks queue
    local env="$1"
    usage_chk1 "$env" || return 1
    clear && cnt=0
    while [ 1 ]; do
        cnt=$((cnt+1))
        [ $cnt -eq 5 ] && clear && cnt=0
        cmd=$(${escmd["$env"]} GET '_cat/tasks?pretty&v&h=action,type,running_time,node' | grep merg)
        status=$?

        echo "${FUNCNAME[0]}"
        echo "==================================="
        echo "$cmd" | column -t
        [ $status -ne 0 ] && echo "done" && break
        echo "==================================="
        sleep 10
    done
}



#16----------------------------------------------
# capacity planning functions
##-----------------------------------------------
calc_total_docs_hdd_overXdays () {
    # calc. the total docs & HDD storage used by all indices over X days
    local env="$1"
    local days="$2"
    usage_chk10 "$env" "$days" || return 1

    dateRange=$(for i in $(seq 0 $(($days - 1)) ); do calc_date "$i days ago"; done | $pasteCmd -s -d '|')

    printf "\n\n"
    printf "Indexes' Primary Shard Analysis (Total)\n"
    printf "=======================================\n"
    printf "[DATE RANGE: %s]\n" "$(echo "$dateRange" | awk -F'|' '{print $NF" - "$1}')"
    printf "=======================================\n\n"
    
    (
        printf "TotalShards TotalDocs TotalStorageGBs\n"
        printf "=========== ========= ===============\n"
        show_idx_sizes "$env" \
            | grep -E "${dateRange}" \
            | awk '{ total2 += $2; total4 += $4; total5 += $5 } END \
                    { printf("%0.0f %0.0f %0.0f"), total2, total4, total5 }'
        printf "\n"
    ) | column -t

    printf "\n\n"
}

calc_daily_docs_hdd_overXdays () {
    # calc. the individual daily total docs & HDD storage used by all indices over X days
    local env="$1"
    local days="$2"
    usage_chk10 "$env" "$days" || return 1

    dateRange=$(for i in $(seq 0 $(($days - 1)) ); do calc_date "$i days ago"; done | $pasteCmd -s -d '|')
    dateRangeInOrder=$(
        echo "$dateRange" \
            | sed 's/\|/ /g' \
            | awk '{for(i=NF;i>0;--i)printf "%s%s",$i,(i>1?OFS:ORS)}'
    )

    printf "\n\n"
    printf "Indexes' Primmary Shard Analysis (Daily)\n"
    printf "========================================\n"
    printf "[DATE RANGE: %s]\n" "$(echo "$dateRange" | awk -F'|' '{print $NF" - "$1}')"
    printf "========================================\n\n"

    (
        idxData="$(show_idx_sizes "$env")"

        printf "Date JulianDay TotalShards TotalDocs TotalStorageGBs IdxCounts\n"
        printf "==== ========= =========== ========= =============== =========\n"

        for day in $dateRangeInOrder; do
            dayTally="$(
                echo "$idxData" \
                    | grep "$day" \
                    | awk '{ total2 += $2; total4 += $4; total5 += $5 } END \
                            { printf("%0.0f %0.0f %0.0f"), total2, total4, total5 }'
            )"

            idxCount="$(
                echo "$idxData" \
                    | awk -v day="${day}" '$1 ~ day { count++ } END { printf("%d\n"), count }'
            )"

            # calculate Julian Day for $day
            julianDay=$(julian_day ${day//\./})
            printf "%s %s %s %s\n" "$day" "$julianDay" "$dayTally" "$idxCount"
            printf "\n"
        done
    ) | column -t

    printf "\n\n"
}

calc_idx_type_avgs_overXdays () {
    # calc. the avg number of docs & HDD storage used per idx types over X days
    local env="$1"
    local days="$2"
    usage_chk10 "$env" "$days" || return 1

    local DEBUG="off" #[off|on]

    local idxData="$(show_idx_sizes "$env")"
    local xDaysAgo="$(calc_date "${days} days ago")"

    local idxTypes="$(echo "$idxData" \
        | awk '{print $1}' \
        | sed 's/-[0-9]\{4\}.*//' \
        | sort -u \
        | grep -vE 'kibana|monitoring|apm|security|index|watcher|tasks|ilm|management|reporting'
    )"

    printf "\n\n"

    local idxCalculations="$(
        for idx in $idxTypes; do

            local idxDataWithinCutoff="$(
                echo "$idxData" \
                    | grep "$idx" \
                    | sort -k1,1 \
                    | awk -v idxCutOff="${idx}-${xDaysAgo}" '$1 > idxCutOff'
            )"

            [[ $DEBUG == "on" ]] && printf "\n===> [idxType: %s]\n%s\n" "$idx" "$idxDataWithinCutoff"

            # skip if no indexes occur w/in cutoff's range
            echo "$idxDataWithinCutoff" \
                | awk -v idx="${idx}" '$1 ~ idx { count++ } END { printf("%d\n"), count }' \
                | grep -q "^0$" \
                && continue  
            
            # found at least 1 idx for idxType, analyze em
            {
             printf "%s\n" "$idx"
             echo "$idxDataWithinCutoff" \
                 | awk '$5 == 0 { $5 = 1 } 1' \
                 | awk '{ total1 += $4; count1++; total2 += $5; count2++ } END \
                            { printf("%0.0f %0.0f %0.0f %0.0f %g\n"), \
                                total1/count1, total2/count2, 60*(total1/count1), 60*(total2/count2), count2 }'
            } | paste - - - -
        done
    )"

    [[ $DEBUG == "on" ]] && printf "%s\n" "$idxCalculations" && return 1

    local idxTotals="$(
        echo "$idxCalculations" \
                 | awk '{ total2 += $2; total3 += $3; total4 += $4; total5 += $5 } END \
                            { printf("%0.0f %0.0f %0.0f %0.0f"), total2, total3, total4, total5 }'
    )"

    printf "last ~%s day averages \t----\t [NOTE: Storage is in GB's and represents P shard's usage]\n" "$days"
    printf "=====================\n\n"
    local output="$(
        printf "Idx AvgNumDocsDaily AvgStorageUsedDaily 60DayProjectedNumDocs 60DayProjectedStorage IdxCounts\n"
        printf "=== =============== =================== ===================== ===================== =========\n"
        echo "$idxCalculations"
        printf "=== =============== =================== ===================== ===================== =========\n"
    )"

    printf "%s\n\nTotals: %s\n\n" "$output" "$idxTotals" | column -t
    printf "\n\n"
}

calc_num_nodes_overXdays () {
    # calc. the HDD storage required based on idx types usage over X days
    local env="$1"
    local days="$2"
    usage_chk10 "$env" "$days" || return 1

    local stdHDDSize="7600"
    
    idxCalculations="$(calc_idx_type_avgs_overXdays "$env" "$days")"
    sixtyDayDocs="$(echo "$idxCalculations" | awk '/Totals:/ { print $4 }')"
    sixtyDayStorage="$(echo "$idxCalculations" | awk '/Totals:/ { print $5 }')"
    printf "%s\n\n\n" "$idxCalculations" 

    local nodes="$(ceiling_divide "$sixtyDayStorage" "$stdHDDSize")"
    local nodes2x="$(bc <<<"2 * $nodes")"

    local storage2x="$(bc <<<"2 * $sixtyDayStorage")"
    local docs2x="$(bc <<<"2 * $sixtyDayDocs")"

    local storage2xPerNode="$(bc <<<"scale=2; $storage2x / $nodes2x")"
    local docs2xPerNode="$(bc <<<"scale=2; $docs2x / $nodes2x")"
    local pctStorageUtilPerNode="$(bc <<<"scale=4; $storage2xPerNode / $stdHDDSize * 100")"

    local nplus1Storage2x="$(bc <<<"scale=2; ($storage2x + 1 * $stdHDDSize)")"
    local nplus2Storage2x="$(bc <<<"scale=2; ($storage2x + 2 * $stdHDDSize)")"
    local nplus1Nodes="$(ceiling_divide "$nplus1Storage2x" "$stdHDDSize")"
    local nplus2Nodes="$(ceiling_divide "$nplus2Storage2x" "$stdHDDSize")"
    local nplus1PctStorageUtil="$(bc <<<"scale=4; (($storage2x - 1 * $stdHDDSize) / ($nodes2x * $stdHDDSize)) * 100")"
    local nplus2PctStorageUtil="$(bc <<<"scale=4; (($storage2x - 2 * $stdHDDSize) / ($nodes2x * $stdHDDSize)) * 100")"

    outputWidth="$(( $(echo "$idxCalculations" | grep '===' | tail -1 | wc -c) - 1 ))"
    printf "%s\n\n" "$(printf '=%.0s' $(seq 1 ${outputWidth}))"

    # HDD
    printf "HDD Size (GB):                %s\n"     "$stdHDDSize"
    printf "%s\n" "$(printf -- '-%.0s' $(seq 1 $(( ${outputWidth} - 30 )) ))"

    # number of nodes
    printf "Number of nodes (P):          %s\t\t\t [ %s ]\n" "$nodes"   "$sixtyDayStorage / $stdHDDSize"
    printf "Number of nodes (P & R):      %s\t\t\t [ %s ]\n" "$nodes2x" "2 * ($sixtyDayStorage / $stdHDDSize)"
    printf "%s\n" "$(printf -- '-%.0s' $(seq 1 $(( ${outputWidth} - 30 )) ))"

    # docs/storage totals
    printf "Tot. Agg. storage (P & R):    %s\n"     "$storage2x"
    printf "Tot. Agg. docs (P & R):       %s\n"     "$docs2x"
    printf "%s\n" "$(printf -- '-%.0s' $(seq 1 $(( ${outputWidth} - 30 )) ))"

    # docs/storage per node
    printf "Tot. Agg. storage (per node): %.2f\n"   "$storage2xPerNode"
    printf "Tot. Agg. docs (per node):    %.2f\n"   "$docs2xPerNode"
    printf "HDD utilization (per node):   %.2f%%\n" "$pctStorageUtilPerNode"
    printf "%s\n" "$(printf -- '-%.0s' $(seq 1 $(( ${outputWidth} - 30 )) ))"

    # N+1/N+2
    printf "Nodes N+1 (P & R):            %s\n" "$nplus1Nodes"
    printf "Nodes N+2 (P & R):            %s\n" "$nplus2Nodes"

    printf "HDD util. N+1 (per node):     %.2f%%\t\t\t [ %s ]\n" \
        "$nplus1PctStorageUtil" \
        "(($storage2x - 1 * $stdHDDSize) / ($nodes2x * $stdHDDSize)) * 100"

    printf "HDD util. N+2 (per node):     %.2f%%\t\t\t [ %s ]\n" \
        "$nplus2PctStorageUtil" \
        "(($storage2x - 2 * $stdHDDSize) / ($nodes2x * $stdHDDSize)) * 100"
    printf "%s\n" "$(printf -- '-%.0s' $(seq 1 $(( ${outputWidth} - 30 )) ))"

    printf "\n\n\n"
}

### pct_growth_rates_overXdays () {
###     # calc. the total docs & HDD storage used by all indices over X days
###     local env="$1"
###     local days="$2"
###     usage_chk10 "$env" "$days" || return 1
### 
###     # https://www.listendata.com/2018/03/regression-analysis.html
###     # http://www.alcula.com/calculators/statistics/linear-regression/
###     # https://manpages.debian.org/jessie/gmt/GMT.1gmt.en.html
###     # https://www.systutorials.com/docs/linux/man/1-gmtregress/
### }



#17----------------------------------------------
# template funcs
##-----------------------------------------------
list_templates () {
    # show all template details
    local env="$1"
    usage_chk1 "$env" || return 1
    ${escmd["$env"]} GET '_cat/templates?pretty&v&s=name'
}

show_template () {
    # show template X's details
    local env="$1"
    local idxArg="$2"
    if ! usage_chk3 "$env" "$idxArg"; then
        printf "\nExamples\n========\nshow_template l filebeat-6.5.1 | grep settings -A15\n\n\n"
        return 1
    fi
    ${escmd["$env"]} GET "_template/${idxArg}*?pretty"
}



###############################################################################
###############################################################################

#------------------------------------------------
# TODO NOTES
##-----------------------------------------------

# PUT /_security/role_mapping/bw_elasticsearch_ro
# {
#   "roles": [ "bw_elasticsearch_ro"],
#   "enabled": true, 
#   "rules": {
#     "field" : { "groups" : "cn=ipausers,cn=groups,cn=accounts,dc=bandwidthclec,dc=com" }
#   },
#   "metadata" : { 
#     "version" : 1
#   }
# }
#
# DELETE /_security/role_mapping/elasticsearch_ro
#
# $ ./esl GET '_xpack/security/_authenticate?pretty'
# {
#   "username" : "someuser",
#   "roles" : [
#     "index_mbashley_testing",
#     "cluster_user",
#     "index_mbashley_read",
#     "kibana_user",
#     "superuser"
#   ],
#   "full_name" : null,
#   "email" : null,
#   "metadata" : {
#     "ldap_dn" : "uid=someuser, cn=users, cn=accounts, dc=somedom,dc=com",
#     "ldap_groups" : [
#       "cn=ipausers,cn=groups,cn=accounts,dc=somedom,dc=com",
#       "cn=sysadmin,cn=groups,cn=accounts,dc=somedom,dc=com",
#       "cn=eng-systems,cn=groups,cn=accounts,dc=somedom,dc=com"
#     ]
#   },
#   "enabled" : true
# }

# $ ./esl GET '_xpack/security/role?pretty' | jq .[] | head
# {
#   "cluster": [],
#   "indices": [
#     {
#       "names": [
#         ".kibana*"
#       ],
#       "privileges": [
#         "read",
#         "view_index_metadata"

# $ ./esl GET '_xpack/security/role?pretty' | jq 'to_entries[] | .key' | sed 's/"//g' | sort | head
# anon_monitor
# apm_system
# beats_admin
# beats_system
# cluster_user
# index_someuser_read
# index_someuser_testing
# ingest_admin
# kibana_dashboard_only_user

# $ ./esl GET '_xpack/security/user' | jq 'to_entries[] | .key'
# "elastic"
# "kibana"
# "logstash_system"
# "beats_system"
# "apm_system"
# "remote_monitoring_user"
# "anonymous_user"
# "logstash_internal"

# https://www.elastic.co/guide/en/x-pack/current/mapping-roles.html#mapping-roles-api
#
# By default, X-Pack security checks role mapping files for changes every 5 seconds. 
# You can change this default behavior by changing the resource.reload.interval.high 
# setting in the elasticsearch.yml file. Since this is a common setting in Elasticsearch, 
# changing its value might effect other schedules in the system.
#
# $ showcfg_cluster l | grep reload.interval.high
#     "resource.reload.interval.high" : "5s",
# 

###############################################################################

# https://www.elastic.co/guide/en/elasticsearch/reference/current/cluster-nodes-stats.html
#
# ./esl GET '_nodes?pretty' | less
# ./esl GET '_nodes/stats?pretty' | less
# ./esl GET '_nodes/stats/indices?pretty' | less
# ./esl GET 'filebeat-6.5.1-2019.06.03/_recovery?pretty' | less 

###############################################################################

# translogs and recovery
# - https://www.elastic.co/guide/en/elasticsearch/reference/current/index-modules-translog.html
# - https://www.elastic.co/guide/en/elasticsearch/reference/current/indices-recovery.html
# - https://www.elastic.co/guide/en/elasticsearch/guide/current/translog.html


###############################################################################

### collect logs
# $ for node in es-master-01{a..c} es-data-01{a..c}; do ssh ${node}.lab1.bandwidthclec.local 'sudo sh -c "tar zcvf - /var/log/elasticsearch/*.log"' > ${node}.lab1.tgz;done

# $ ./esl GET '_nodes/settings?pretty' | jq '.[] | .. | objects | .unicast.hosts | select(. != null)' | grep -vE '\[|\]' | sort -u | cut -d'"' -f2
#es-data-01a.lab1.bandwidthclec.local
#es-data-01b.lab1.bandwidthclec.local
#es-data-01c.lab1.bandwidthclec.local
#es-master-01a.lab1.bandwidthclec.local
#es-master-01b.lab1.bandwidthclec.local
#es-master-01c.lab1.bandwidthclec.local

###############################################################################

### nodes stats
#$ ./esl GET '_nodes/_local/stats?pretty'
#{
#  "_nodes" : {
#    "total" : 1,
#    "successful" : 1,
#    "failed" : 0
#  },
#  "cluster_name" : "lab-rdu-es-01",
#  "nodes" : {
#    "vudQxvnfSQuxMtdkq8ZTUQ" : {
#      "timestamp" : 1563811322882,
#      "name" : "lab-rdu-es-data-01a",
#      "transport_address" : "192.168.112.141:9300",
#      "host" : "192.168.112.141",
#      "ip" : "192.168.112.141:9300",
#      "roles" : [
#        "data"
#      ],
#      "attributes" : {
#        "ml.machine_memory" : "134905458688",
#        "xpack.installed" : "true",
#        "ml.max_open_jobs" : "20"
#      },
#      "indices" : {
#        "docs" : {
#          "count" : 12642441017,
#          "deleted" : 63186440
#        },
#        "store" : {
#          "size_in_bytes" : 5531888174427
#        },
#        "indexing" : {
#          "index_total" : 7134999906,
#          "index_time_in_millis" : 1776730895,
#          "index_current" : 2,
#          "index_failed" : 0,
#          "delete_total" : 886289422,
#          "delete_time_in_millis" : 94178697,
#          "delete_current" : 0,
#          "noop_update_total" : 0,
#          "is_throttled" : false,
#          "throttle_time_in_millis" : 41
#        },
#        "get" : {
#          "total" : 3134,
#          "time_in_millis" : 1208,
#          "exists_total" : 3134,
#          "exists_time_in_millis" : 1208,
#          "missing_total" : 0,
#
#
#$ ./esl GET '_nodes/_local/stats/http?pretty'
#{
#  "_nodes" : {
#    "total" : 1,
#    "successful" : 1,
#    "failed" : 0
#  },
#  "cluster_name" : "lab-rdu-es-01",
#  "nodes" : {
#    "vudQxvnfSQuxMtdkq8ZTUQ" : {
#      "timestamp" : 1563811368460,
#      "name" : "lab-rdu-es-data-01a",
#      "transport_address" : "192.168.112.141:9300",
#      "host" : "192.168.112.141",
#      "ip" : "192.168.112.141:9300",
#      "roles" : [
#        "data"
#      ],
#      "attributes" : {
#        "ml.machine_memory" : "134905458688",
#        "xpack.installed" : "true",
#        "ml.max_open_jobs" : "20"
#      },
#      "http" : {
#        "current_open" : 110,
#        "total_opened" : 58796
#      }
#    }
#  }
#}

###############################################################################

#$ show_idx_sizes c | grep -E ".ml-ano|.ml-state|.ml-not|\.watches|.security|\.kibana"
#.ml-anomalies-shared                5   0  580005659            109
#.ml-state                           5   0       2382             16
#.ml-notifications                   1   0     268769              0
#.kibana_3                           1   1         72              0
#.kibana_2                           1   1         62              0
#.watches                            1   0         35              0
#.security-6                         1   0         23              0
#.kibana_1                           1   1         11              0
#.kibana_task_manager                1   1          2              0
#
#$ showcfg_idx_cfgs c \* | grep -E '".kibana.*{' -A7
#  ".kibana_1": {
#    "settings": {
#      "index.auto_expand_replicas": "false",
#      "index.creation_date": "1542345587211",
#      "index.number_of_replicas": "0",
#      "index.number_of_shards": "1",
#      "index.provided_name": ".kibana_1",
#      "index.uuid": "by-CIg-9SaWOnVode-TEQQ",
#--
#  ".kibana_3": {
#    "settings": {
#      "index.auto_expand_replicas": "0-1",
#      "index.creation_date": "1556885317955",
#      "index.number_of_replicas": "1",
#      "index.number_of_shards": "1",
#      "index.provided_name": ".kibana_3",
#      "index.uuid": "bcQa00vlT82EmCRMEtXJ0g",
#--
#  ".kibana_task_manager": {
#    "settings": {
#      "index.auto_expand_replicas": "0-1",
#      "index.creation_date": "1556587884346",
#      "index.number_of_replicas": "1",
#      "index.number_of_shards": "1",
#      "index.provided_name": ".kibana_task_manager",
#      "index.uuid": "rZeMQ24uT2WRN5V-3nszfg",
#--
#  ".kibana_2": {
#    "settings": {
#      "index.auto_expand_replicas": "0-1",
#      "index.creation_date": "1542345586527",
#      "index.number_of_replicas": "1",
#      "index.number_of_shards": "1",
#      "index.provided_name": ".kibana_2",
#      "index.uuid": "9_YdG4UySASKUOrTJOluaQ",
#
#

###############################################################################

### Show index sources (unique)
# ./esl GET 'filebeat-6.5.1-2019.12.31/_search?pretty' | jq -r '.hits.hits[]._source.host.name' | sort -u
# es-data-01e.lab1.bwnet.us
# es-data-01f.lab1.bwnet.us


###############################################################################

### Show what the analyzer thinks of a string of text
### NOTE: It's showing that the string is viewed as 2 tokens "akrzos" and "crashloop"
#
# $ ./esl POST '_analyze?pretty' -d '{"analyzer":"standard","text":"akrzos-crashloop"}'
# {
#   "tokens" : [
#     {
#       "token" : "akrzos",
#       "start_offset" : 0,
#       "end_offset" : 6,
#       "type" : "<ALPHANUM>",
#       "position" : 0
#     },
#     {
#       "token" : "crashloop",
#       "start_offset" : 7,
#       "end_offset" : 16,
#       "type" : "<ALPHANUM>",
#       "position" : 1
#     }
#   ]
# }

###############################################################################

### Show number of shards in use by data node
# $ show_shards l | awk '{print $8}' | grep -v node | sort | uniq -c
#  454 lab-rdu-es-data-01a
#  454 lab-rdu-es-data-01b
#  454 lab-rdu-es-data-01c
#  455 lab-rdu-es-data-01d
#  455 lab-rdu-es-data-01e
#  454 lab-rdu-es-data-01f
#  454 lab-rdu-es-data-01g

###############################################################################

### Show thread_pool stats on each node
# $ ./esc | head
# node_name           name                active rejected completed
# instance-0000000058 analyze                  0        0         0
# instance-0000000058 fetch_shard_started      0        0         0
# instance-0000000058 fetch_shard_store        0        0        31
# instance-0000000058 flush                    0        0    211732
# instance-0000000058 force_merge              0        0         0
# instance-0000000058 generic                  1        0   3534840
# instance-0000000058 get                      0        0      2450
# instance-0000000058 listener                 0        0      5893
# instance-0000000058 management               1        0   6725733

# https://www.elastic.co/guide/en/elasticsearch/reference/current/cat-thread-pool.html

###############################################################################

### Show hot threads by node
# $ ./esp GET '_nodes/hot_threads' | head -30
# ::: {rdu-es-data-01r}{_NE3oAPUT2amqt2n7drkCg}{Cpr4txJoQBGTzRTjDi7sYQ}{192.168.138.50}{192.168.138.50:9300}{dl}{ml.machine_memory=134454972416, ml.max_open_jobs=20, xpack.installed=true}
#    Hot threads at 2020-05-07T01:21:44.462Z, interval=500ms, busiestThreads=3, ignoreIdleThreads=true:
# 
#    76.3% (381.4ms out of 500ms) cpu usage by thread 'elasticsearch[rdu-es-data-01r][[messaging-6.5.1-2020.05.07][3]: Lucene Merge Thread #1115]'
#      5/10 snapshots sharing following 11 elements
#        app//org.apache.lucene.codecs.blocktree.BlockTreeTermsWriter$TermsWriter.write(BlockTreeTermsWriter.java:865)
#        app//org.apache.lucene.codecs.blocktree.BlockTreeTermsWriter.write(BlockTreeTermsWriter.java:344)
#        app//org.apache.lucene.codecs.FieldsConsumer.merge(FieldsConsumer.java:105)
#        app//org.apache.lucene.codecs.perfield.PerFieldPostingsFormat$FieldsWriter.merge(PerFieldPostingsFormat.java:197)
#        app//org.apache.lucene.index.SegmentMerger.mergeTerms(SegmentMerger.java:245)
#        app//org.apache.lucene.index.SegmentMerger.merge(SegmentMerger.java:140)
#        app//org.apache.lucene.index.IndexWriter.mergeMiddle(IndexWriter.java:4463)
#        app//org.apache.lucene.index.IndexWriter.merge(IndexWriter.java:4057)
#        app//org.apache.lucene.index.ConcurrentMergeScheduler.doMerge(ConcurrentMergeScheduler.java:625)
#        app//org.elasticsearch.index.engine.ElasticsearchConcurrentMergeScheduler.doMerge(ElasticsearchConcurrentMergeScheduler.java:101)
#        app//org.apache.lucene.index.ConcurrentMergeScheduler$MergeThread.run(ConcurrentMergeScheduler.java:662)
#      5/10 snapshots sharing following 9 elements
#        app//org.apache.lucene.codecs.FieldsConsumer.merge(FieldsConsumer.java:105)
#        app//org.apache.lucene.codecs.perfield.PerFieldPostingsFormat$FieldsWriter.merge(PerFieldPostingsFormat.java:197)
#        app//org.apache.lucene.index.SegmentMerger.mergeTerms(SegmentMerger.java:245)
#        app//org.apache.lucene.index.SegmentMerger.merge(SegmentMerger.java:140)
#        app//org.apache.lucene.index.IndexWriter.mergeMiddle(IndexWriter.java:4463)
#        app//org.apache.lucene.index.IndexWriter.merge(IndexWriter.java:4057)
#        app//org.apache.lucene.index.ConcurrentMergeScheduler.doMerge(ConcurrentMergeScheduler.java:625)
#        app//org.elasticsearch.index.engine.ElasticsearchConcurrentMergeScheduler.doMerge(ElasticsearchConcurrentMergeScheduler.java:101)
#        app//org.apache.lucene.index.ConcurrentMergeScheduler$MergeThread.run(ConcurrentMergeScheduler.java:662)
# 
#     5.9% (29.4ms out of 500ms) cpu usage by thread 'elasticsearch[rdu-es-data-01r][write][T#39]'
#      2/10 snapshots sharing following 2 elements
#        java.base@13.0.2/java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:628)

# https://www.elastic.co/guide/en/elasticsearch/reference/current/cluster-nodes-hot-threads.html

###############################################################################

### Show disk_info on allocation explain
# $ ./esl GET '_cluster/allocation/explain?include_disk_info&pretty' | head -20
# {
#   "index" : ".reindexed-v6-kibana-6",
#   "shard" : 0,
#   "primary" : true,
#   "current_state" : "unassigned",
#   "unassigned_info" : {
#     "reason" : "INDEX_REOPENED",
#     "at" : "2020-05-20T18:26:38.341Z",
#     "last_allocation_status" : "no_valid_shard_copy"
#   },
#   "cluster_info" : {
#     "nodes" : {
#       "3is48GZERPOBPNbNpPXs3Q" : {
#         "node_name" : "lab-rdu-es-data-01f",
#         "least_available" : {
#           "path" : "/mnt/data/nodes/0",
#           "total_bytes" : 7676845096960,
#           "used_bytes" : 5496087470080,
#           "free_bytes" : 2180757626880,
#           "free_disk_percent" : 28.4,
#           ...
#           ...
#               "shard_sizes" : {
#       "[filebeat-flow-2020.05.20-03][0][p]_bytes" : 92172906,
#       "[packetbeat-default-2020.04.20][0][r]_bytes" : 9393908959,
#       "[filebeat-6.5.1-2020.04.25][0][p]_bytes" : 30009805131,
#       "[filebeat-6.5.1-2020.04.26][3][r]_bytes" : 30039754237,
#       "[syslog-2020.05.18][0][r]_bytes" : 11180946816,
#       "[metricbeat-7.6.2-2020.05.17][2][r]_bytes" : 1962187595,
#       "[filebeat-6.5.1-2020.04.23][7][p]_bytes" : 26908059724,
#       "[filebeat-6.5.1-2020.05.16][14][p]_bytes" : 20945511780,
#       "[filebeat-6.5.1-2020.04.21][1][r]_bytes" : 21316835144,
#       "[metricbeat-6.1.1-2020.05.05][0][p]_bytes" : 3899587343,
#       "[filebeat-6.5.1-2020.04.29][8][r]_bytes" : 26165521223,
#       "[.kibana_task_manager_2][0][p]_bytes" : 27896,
#       "[metricbeat-6.1.1-2020.05.15][0][p]_bytes" : 3862449618,
#       "[filebeat-6.5.1-2020.04.07][13][p]_bytes" : 18493,
#       "[filebeat-6.5.1-2020.04.21][0][r]_bytes" : 21179378802,
#       "[metricbeat-default-2020.05.09][2][p]_bytes" : 2225141043,
#       "[filebeat-6.5.1-2020.05.15][0][r]_bytes" : 32267637240,
#       "[syslog-2020.04.27][0][p]_bytes" : 14096624411,
#       "[metricbeat-default-2020.05.15][1][p]_bytes" : 2291584755,

###############################################################################

### Show HDD usage
# $ ./esl GET '_nodes/stats/fs?human&pretty' | head -20
# {
#   "_nodes" : {
#     "total" : 11,
#     "successful" : 11,
#     "failed" : 0
#   },
#   "cluster_name" : "lab-rdu-es-01",
#   "nodes" : {
#     "kp56LtTuTZSVfYfC3uAzjQ" : {
#       "timestamp" : 1590001093604,
#       "name" : "lab-rdu-es-data-01b",
#       "transport_address" : "192.168.112.142:9300",
#       "host" : "192.168.112.142",
#       "ip" : "192.168.112.142:9300",
#       "roles" : [
#         "data",
#         "ml"
#       ],
#       "attributes" : {
#         "ml.machine_memory" : "134924824576",

###############################################################################

### Allocations
# $ ./esl GET '_cat/allocation?v' | head -20
# shards disk.indices disk.used disk.avail disk.total disk.percent host            ip              node
#    429        4.6tb     4.6tb      2.3tb      6.9tb           66 192.168.116.29  192.168.116.29  lab-rdu-es-data-01d
#    409        4.8tb     4.8tb   1019.8gb      5.8tb           82 192.168.112.143 192.168.112.143 lab-rdu-es-data-01c
#    341        4.4tb     4.4tb      2.5tb      6.9tb           63 192.168.116.32  192.168.116.32  lab-rdu-es-data-01g
#    410        4.9tb     4.9tb    917.8gb      5.8tb           84 192.168.112.141 192.168.112.141 lab-rdu-es-data-01a
#    420        4.8tb     4.8tb    969.8gb      5.8tb           83 192.168.112.142 192.168.112.142 lab-rdu-es-data-01b
#    417        4.9tb     4.9tb      1.9tb      6.9tb           71 192.168.116.31  192.168.116.31  lab-rdu-es-data-01f
#      1                                                                                           UNASSIGNED


### analyzing retention outliers
# $  1096  for i in $(show_idx_retention_violations p filebeat 60 | grep filebeat); do \
#     show_idx_doc_sources_all_cnts p $i;done \
#     | grep key \
#     | awk '{print $3}' \
#     | sort -u > b
# $ utc; for i in $(<b); do printf "%-75s  %-s\n" "$i" "$(gtimeout 5 ssh $i date)";done
# $ utc; for i in $(<b); do printf "%-75s  %-s\n" "$i" "$(gtimeout 5 ssh $i grep Cen /etc/redhat-release)";done
# $ utc; for i in $(<b); do printf "%-75s  %-s\n" "$i" "$(gtimeout 5 ssh $i filebeat version)";done

### compare shard time metrics
# $ echo 'idx                               shard node            flush.total_time flush.total indexing.index_time indexing.index_total merges.total_time merges.total refresh.time refresh.total search.fetch_time search.query_total'; for i in {19..28};do ./esp GET '_cat/shards?v&human&h=idx,shard,node,flush.total_time,flush.total,indexing.index_time,indexing.index_total,merges.total_time,merges.total,refresh.time,refresh.total,search.fetch_time,search.fetch_totalsearch.query_time,search.query_total&s=indexing.index_time:desc' | grep -E "node|fileb.*6.5.1.*2020.05.${i}" | head -3 | grep -v node; echo ''; done
# idx                               shard node            flush.total_time flush.total indexing.index_time indexing.index_total merges.total_time merges.total refresh.time refresh.total search.fetch_time search.query_total
# filebeat-6.5.1-2020.05.19         14    rdu-es-data-01g             6.7m         337                  1d             94528754                1d        21353         1.4h         16028                1m              44169
# filebeat-6.5.1-2020.05.19         13    rdu-es-data-01m             6.1m         333                  1d             94528762             23.7h        21632         1.3h         16344             24.8s              20919
# 
# filebeat-6.5.1-2020.05.20         10    rdu-es-data-01m            10.5m         397                1.7d            118275423              1.3d        23182         3.3h         18830              4.2m              42763
# filebeat-6.5.1-2020.05.20         13    rdu-es-data-01m            10.5m         384                1.6d            118281450              1.4d        22206         3.3h         18937             33.1m             371602
# 
# filebeat-6.5.1-2020.05.21         5     rdu-es-data-01i             6.5m         342                1.1d             99387742                1d        24015         1.4h         16065              1.4m              17046
# filebeat-6.5.1-2020.05.21         8     rdu-es-data-01l               6m         330                  1d             99382642                1d        22162         1.3h         16185              1.1m              46364
# 
# filebeat-6.5.1-2020.05.22         6     rdu-es-data-01o            11.1m         544                1.5d            169300056              1.4d        29190         1.5h         17398             27.8s             164828
# filebeat-6.5.1-2020.05.22         0     rdu-es-data-01r            11.5m         567                1.4d            169292819              1.4d        24689         1.4h         16439              1.3m             352700
# 
# filebeat-6.5.1-2020.05.23         14    rdu-es-data-01o             2.9m         201                 15h             64331403             14.7h        21164         1.1h         16223                2s              42910
# filebeat-6.5.1-2020.05.23         13    rdu-es-data-01e               3m         202               14.9h             64327238             14.6h        22260         1.1h         16294              7.6s              28240
# 
# filebeat-6.5.1-2020.05.24         0     rdu-es-data-01m               2m         162               12.5h             51264537             11.1h        23777         1.1h         17145              5.2s              23282
# filebeat-6.5.1-2020.05.24         4     rdu-es-data-01o               2m         161               10.9h             51271281             11.6h        17917           1h         16430                3s               2908
# 
# filebeat-6.5.1-2020.05.25         0     rdu-es-data-01h             2.7m         211                 14h             65052964             14.1h        20287           1h         17217              1.4s               9988
# filebeat-6.5.1-2020.05.25         8     rdu-es-data-01f             2.9m         216               13.3h             65055745             14.6h        20036           1h         16550                3s              25223
# 
# filebeat-6.5.1-2020.05.26         3     rdu-es-data-01f            10.1m         350                1.4d            100531382              1.2d        20939           2h         15027             27.8s              36796
# filebeat-6.5.1-2020.05.26         10    rdu-es-data-01f             9.7m         345                1.3d            100549091              1.2d        19549           2h         15009             39.2s              16040
# 
# filebeat-6.5.1-2020.05.27         9     rdu-es-data-01g             7.9m         364                1.2d            107866059              1.1d        20527         1.6h         15967                2m               6160
# filebeat-6.5.1-2020.05.27         11    rdu-es-data-01j             7.8m         362                1.1d            107871935              1.1d        21644         1.6h         15715              1.8m              17988
# 
# filebeat-6.5.1-2020.05.28         1     rdu-es-data-01g            12.5m         418                2.6d            128744579              1.4d        29551         3.8h         17717                9m              17650
# filebeat-6.5.1-2020.05.28         0     rdu-es-data-01m             7.5m         408                1.3d            128775519              1.2d        34021         1.8h         19332              6.4m               3739

### flush thresholds
# - https://aws.amazon.com/premiumsupport/knowledge-center/elasticsearch-indexing-performance/
#
#  $ ./esp GET 'filebeat-6.5.1-2020.06.04/_stats/flush?pretty'
#  {
#    "_shards" : {
#      "total" : 30,
#      "successful" : 30,
#      "failed" : 0
#    },
#    "_all" : {
#      "primaries" : {
#        "flush" : {
#          "total" : 4206,
#          "periodic" : 4197,
#          "total_time_in_millis" : 3817920
#        }
#      },
#      "total" : {
#        "flush" : {
#          "total" : 8466,
#          "periodic" : 8442,
#          "total_time_in_millis" : 7639364
#        }
#      }
#    },
#    "indices" : {
#      "filebeat-6.5.1-2020.06.04" : {
#        "uuid" : "DIOyGDrfQ_SGGAhFFHF9sA",
#        "primaries" : {
#          "flush" : {
#            "total" : 4206,
#            "periodic" : 4197,
#            "total_time_in_millis" : 3817920
#          }
#        },
#        "total" : {
#          "flush" : {
#            "total" : 8466,
#            "periodic" : 8442,
#            "total_time_in_millis" : 7639364
#          }
#        }
#      }
#    }
#  }
#
#
#  $ ./esp GET 'filebeat-6.5.1-2020.06.04/_stats/flush?pretty' | jq -s '.[][] | .primaries, .total' | grep -vE 'null|^[0-9]' | paste - - - - - - -
#  {	  "flush": {	    "total": 4288,	    "periodic": 4279,	    "total_time_in_millis": 3905137	  }	}
#  {	  "flush": {	    "total": 8632,	    "periodic": 8608,	    "total_time_in_millis": 7815368	  }	}
#  
#  [2020-06-04T00:51:28,917][INFO ][logstash.outputs.elasticsearch][filebeat] retrying failed action with response code: 429 ({"type"=>"es_rejected_execution_exception", "reason"=>"rejected execution of processing of [2370237001][indices:data/write/bulk[s][p]]: request: BulkShardRequest [[filebeat-6.5.1-2020.06.04][4]] containing [10] requests, target allocation id: RINAfN7ORhWeFFto5d4qJA, primary term: 1 on EsThreadPoolExecutor[name = rdu-es-data-01a/write, queue capacity = 200, org.elasticsearch.common.util.concurrent.EsThreadPoolExecutor@3db3e16b[Running, pool size = 48, active threads = 47, queued tasks = 204, completed tasks = 1357279959]]"})
#  [2020-06-04T00:51:28,917][INFO ][logstash.outputs.elasticsearch][filebeat] retrying failed action with response code: 429 ({"type"=>"es_rejected_execution_exception", "reason"=>"rejected execution of processing of [2370237001][indices:data/write/bulk[s][p]]: request: BulkShardRequest [[filebeat-6.5.1-2020.06.04][4]] containing [10] requests, target allocation id: RINAfN7ORhWeFFto5d4qJA, primary term: 1 on EsThreadPoolExecutor[name = rdu-es-data-01a/write, queue capacity = 200, org.elasticsearch.common.util.concurrent.EsThreadPoolExecutor@3db3e16b[Running, pool size = 48, active threads = 47, queued tasks = 204, completed tasks = 1357279959]]"})
#  [2020-06-04T00:51:28,917][INFO ][logstash.outputs.elasticsearch][filebeat] retrying failed action with response code: 429 ({"type"=>"es_rejected_execution_exception", "reason"=>"rejected execution of processing of [2370237001][indices:data/write/bulk[s][p]]: request: BulkShardRequest [[filebeat-6.5.1-2020.06.04][4]] containing [10] requests, target allocation id: RINAfN7ORhWeFFto5d4qJA, primary term: 1 on EsThreadPoolExecutor[name = rdu-es-data-01a/write, queue capacity = 200, org.elasticsearch.common.util.concurrent.EsThreadPoolExecutor@3db3e16b[Running, pool size = 48, active threads = 47, queued tasks = 204, completed tasks = 1357279959]]"})
#  [2020-06-04T00:51:28,918][INFO ][logstash.outputs.elasticsearch][filebeat] retrying failed action with response code: 429 ({"type"=>"es_rejected_execution_exception", "reason"=>"rejected execution of processing of [2370237001][indices:data/write/bulk[s][p]]: request: BulkShardRequest [[filebeat-6.5.1-2020.06.04][4]] containing [10] requests, target allocation id: RINAfN7ORhWeFFto5d4qJA, primary term: 1 on EsThreadPoolExecutor[name = rdu-es-data-01a/write, queue capacity = 200, org.elasticsearch.common.util.concurrent.EsThreadPoolExecutor@3db3e16b[Running, pool size = 48, active threads = 47, queued tasks = 204, completed tasks = 1357279959]]"})
#  [2020-06-04T00:51:28,918][INFO ][logstash.outputs.elasticsearch][filebeat] retrying failed action with response code: 429 ({"type"=>"es_rejected_execution_exception", "reason"=>"rejected execution of processing of [2370237001][indices:data/write/bulk[s][p]]: request: BulkShardRequest [[filebeat-6.5.1-2020.06.04][4]] containing [10] requests, target allocation id: RINAfN7ORhWeFFto5d4qJA, primary term: 1 on EsThreadPoolExecutor[name = rdu-es-data-01a/write, queue capacity = 200, org.elasticsearch.common.util.concurrent.EsThreadPoolExecutor@3db3e16b[Running, pool size = 48, active threads = 47, queued tasks = 204, completed tasks = 1357279959]]"})
#  [2020-06-04T00:51:28,918][INFO ][logstash.outputs.elasticsearch][filebeat] retrying failed action with response code: 429 ({"type"=>"es_rejected_execution_exception", "reason"=>"rejected execution of processing of [2370237043][indices:data/write/bulk[s][p]]: request: BulkShardRequest [[filebeat-6.5.1-2020.06.04][10]] containing [6] requests, target allocation id: W4bn5H6YRKqseji2KsP2eQ, primary term: 2 on EsThreadPoolExecutor[name = rdu-es-data-01a/write, queue capacity = 200, org.elasticsearch.common.util.concurrent.EsThreadPoolExecutor@3db3e16b[Running, pool size = 48, active threads = 48, queued tasks = 204, completed tasks = 1357279982]]"})
#  [2020-06-04T00:51:28,918][INFO ][logstash.outputs.elasticsearch][filebeat] retrying failed action with response code: 429 ({"type"=>"es_rejected_execution_exception", "reason"=>"rejected execution of processing of [2370237043][indices:data/write/bulk[s][p]]: request: BulkShardRequest [[filebeat-6.5.1-2020.06.04][10]] containing [6] requests, target allocation id: W4bn5H6YRKqseji2KsP2eQ, primary term: 2 on EsThreadPoolExecutor[name = rdu-es-data-01a/write, queue capacity = 200, org.elasticsearch.common.util.concurrent.EsThreadPoolExecutor@3db3e16b[Running, pool size = 48, active threads = 48, queued tasks = 204, completed tasks = 1357279982]]"})
#  [2020-06-04T00:51:28,918][INFO ][logstash.outputs.elasticsearch][filebeat] retrying failed action with response code: 429 ({"type"=>"es_rejected_execution_exception", "reason"=>"rejected execution of processing of [2370237001][indices:data/write/bulk[s][p]]: request: BulkShardRequest [[filebeat-6.5.1-2020.06.04][4]] containing [10] requests, target allocation id: RINAfN7ORhWeFFto5d4qJA, primary term: 1 on EsThreadPoolExecutor[name = rdu-es-data-01a/write, queue capacity = 200, org.elasticsearch.common.util.concurrent.EsThreadPoolExecutor@3db3e16b[Running, pool size = 48, active threads = 47, queued tasks = 204, completed tasks = 1357279959]]"})
#  [2020-06-04T00:51:28,918][INFO ][logstash.outputs.elasticsearch][filebeat] retrying failed action with response code: 429 ({"type"=>"es_rejected_execution_exception", "reason"=>"rejected execution of processing of [2370237043][indices:data/write/bulk[s][p]]: request: BulkShardRequest [[filebeat-6.5.1-2020.06.04][10]] containing [6] requests, target allocation id: W4bn5H6YRKqseji2KsP2eQ, primary term: 2 on EsThreadPoolExecutor[name = rdu-es-data-01a/write, queue capacity = 200, org.elasticsearch.common.util.concurrent.EsThreadPoolExecutor@3db3e16b[Running, pool size = 48, active threads = 48, queued tasks = 204, completed tasks = 1357279982]]"})
#  [2020-06-04T00:51:28,918][INFO ][logstash.outputs.elasticsearch][filebeat] retrying failed action with response code: 429 ({"type"=>"es_rejected_execution_exception", "reason"=>"rejected execution of processing of [2370237001][indices:data/write/bulk[s][p]]: request: BulkShardRequest [[filebeat-6.5.1-2020.06.04][4]] containing [10] requests, target allocation id: RINAfN7ORhWeFFto5d4qJA, primary term: 1 on EsThreadPoolExecutor[name = rdu-es-data-01a/write, queue capacity = 200, org.elasticsearch.common.util.concurrent.EsThreadPoolExecutor@3db3e16b[Running, pool size = 48, active threads = 47, queued tasks = 204, completed tasks = 1357279959]]"})

# https://www.elastic.co/guide/en/elasticsearch/reference/current/indices-split-index.html#split-index-api-desc

### _mappings and other bits/pieces
# - https://gist.github.com/slmingol/ff667c1faa9163686a50fe1f9c0928ec

# $ ./esl GET 'filebeat-ilm-6.5.1-2020.06.05-000008/_mapping?pretty' | jq '.[].mappings | .properties | [leaf_paths as $path | {"key": $path | join("."), "value": getpath($path)}] | from_entries' | head -20
#  {
#    "@timestamp.type": "date",
#    "@version.type": "keyword",
#    "@version.ignore_above": 1024,
#    "GoVersion.type": "keyword",
#    "GoVersion.ignore_above": 1024,
#    "NumCPUs.type": "long",
#    "PV.type": "keyword",
#    "PV.ignore_above": 1024,
#    "PVC.type": "keyword",
#    "PVC.ignore_above": 1024,
#    "PV_volume.type": "keyword",
#    "PV_volume.ignore_above": 1024,
#    "Request.properties.Name.type": "keyword",
#    "Request.properties.Name.ignore_above": 1024,
#    "Request.properties.Namespace.type": "keyword",
#    "Request.properties.Namespace.ignore_above": 1024,
#    "Service.properties.Name.type": "keyword",
#    "Service.properties.Name.ignore_above": 1024,
#    "Service.properties.Namespace.type": "keyword",

# $ ./esl GET 'filebeat-ilm-6.5.1-2020.06.05-000008/_mapping?pretty' |  jq 'reduce ( tostream | select(length==2) | .[0] |= [join(".")] ) as [$p,$v] ( {} ; setpath($p; $v) )' | head -20
#  {
#    "filebeat-ilm-6.5.1-2020.06.05-000008.mappings._meta.version": "6.5.1",
#    "filebeat-ilm-6.5.1-2020.06.05-000008.mappings.dynamic_templates.0.fields.path_match": "fields.*",
#    "filebeat-ilm-6.5.1-2020.06.05-000008.mappings.dynamic_templates.0.fields.match_mapping_type": "string",
#    "filebeat-ilm-6.5.1-2020.06.05-000008.mappings.dynamic_templates.0.fields.mapping.type": "keyword",
#    "filebeat-ilm-6.5.1-2020.06.05-000008.mappings.dynamic_templates.1.docker.container.labels.path_match": "docker.container.labels.*",
#    "filebeat-ilm-6.5.1-2020.06.05-000008.mappings.dynamic_templates.1.docker.container.labels.match_mapping_type": "string",
#    "filebeat-ilm-6.5.1-2020.06.05-000008.mappings.dynamic_templates.1.docker.container.labels.mapping.type": "keyword",
#    "filebeat-ilm-6.5.1-2020.06.05-000008.mappings.dynamic_templates.2.kibana.log.meta.path_match": "kibana.log.meta.*",
#    "filebeat-ilm-6.5.1-2020.06.05-000008.mappings.dynamic_templates.2.kibana.log.meta.match_mapping_type": "string",
#    "filebeat-ilm-6.5.1-2020.06.05-000008.mappings.dynamic_templates.2.kibana.log.meta.mapping.type": "keyword",
#    "filebeat-ilm-6.5.1-2020.06.05-000008.mappings.dynamic_templates.3.strings_as_keyword.match_mapping_type": "string",
#    "filebeat-ilm-6.5.1-2020.06.05-000008.mappings.dynamic_templates.3.strings_as_keyword.mapping.ignore_above": 1024,
#    "filebeat-ilm-6.5.1-2020.06.05-000008.mappings.dynamic_templates.3.strings_as_keyword.mapping.type": "keyword",
#    "filebeat-ilm-6.5.1-2020.06.05-000008.mappings.date_detection": false,
#    "filebeat-ilm-6.5.1-2020.06.05-000008.mappings.properties.@timestamp.type": "date",
#    "filebeat-ilm-6.5.1-2020.06.05-000008.mappings.properties.@version.type": "keyword",
#    "filebeat-ilm-6.5.1-2020.06.05-000008.mappings.properties.@version.ignore_above": 1024,
#    "filebeat-ilm-6.5.1-2020.06.05-000008.mappings.properties.GoVersion.type": "keyword",
#    "filebeat-ilm-6.5.1-2020.06.05-000008.mappings.properties.GoVersion.ignore_above": 1024,

# $ ./esl GET 'filebeat-ilm-6.5.1-2020.06.05-000008/_mapping?pretty' |  jq '. as $in
#  | reduce leaf_paths as $path ({};
#       . + { ($path | map(tostring) | join(".")): $in | getpath($path) })' | head -20
#  {
#    "filebeat-ilm-6.5.1-2020.06.05-000008.mappings._meta.version": "6.5.1",
#    "filebeat-ilm-6.5.1-2020.06.05-000008.mappings.dynamic_templates.0.fields.path_match": "fields.*",
#    "filebeat-ilm-6.5.1-2020.06.05-000008.mappings.dynamic_templates.0.fields.match_mapping_type": "string",
#    "filebeat-ilm-6.5.1-2020.06.05-000008.mappings.dynamic_templates.0.fields.mapping.type": "keyword",
#    "filebeat-ilm-6.5.1-2020.06.05-000008.mappings.dynamic_templates.1.docker.container.labels.path_match": "docker.container.labels.*",
#    "filebeat-ilm-6.5.1-2020.06.05-000008.mappings.dynamic_templates.1.docker.container.labels.match_mapping_type": "string",
#    "filebeat-ilm-6.5.1-2020.06.05-000008.mappings.dynamic_templates.1.docker.container.labels.mapping.type": "keyword",
#    "filebeat-ilm-6.5.1-2020.06.05-000008.mappings.dynamic_templates.2.kibana.log.meta.path_match": "kibana.log.meta.*",
#    "filebeat-ilm-6.5.1-2020.06.05-000008.mappings.dynamic_templates.2.kibana.log.meta.match_mapping_type": "string",
#    "filebeat-ilm-6.5.1-2020.06.05-000008.mappings.dynamic_templates.2.kibana.log.meta.mapping.type": "keyword",
#    "filebeat-ilm-6.5.1-2020.06.05-000008.mappings.dynamic_templates.3.strings_as_keyword.match_mapping_type": "string",
#    "filebeat-ilm-6.5.1-2020.06.05-000008.mappings.dynamic_templates.3.strings_as_keyword.mapping.ignore_above": 1024,
#    "filebeat-ilm-6.5.1-2020.06.05-000008.mappings.dynamic_templates.3.strings_as_keyword.mapping.type": "keyword",
#    "filebeat-ilm-6.5.1-2020.06.05-000008.mappings.properties.@timestamp.type": "date",
#    "filebeat-ilm-6.5.1-2020.06.05-000008.mappings.properties.@version.type": "keyword",
#    "filebeat-ilm-6.5.1-2020.06.05-000008.mappings.properties.@version.ignore_above": 1024,
#    "filebeat-ilm-6.5.1-2020.06.05-000008.mappings.properties.GoVersion.type": "keyword",
#    "filebeat-ilm-6.5.1-2020.06.05-000008.mappings.properties.GoVersion.ignore_above": 1024,
#    "filebeat-ilm-6.5.1-2020.06.05-000008.mappings.properties.NumCPUs.type": "long",

### URL - http://www.javachain.com/wp-content/uploads/2019/02/elasticsearch_monitoring_cheatsheet.pdf

#  METRIC DESCRIPTION                       COMMAND
#  Total number of queries                  curl 'localhost:9200/_cat/nodes?v&h=name,searchQueryTotal'
#  Total time spent on queries              curl 'localhost:9200/_cat/nodes?v&h=name,searchQueryTime'
#  Number of queries currently in progress  curl 'localhost:9200/_cat/nodes?v&h=name,searchQueryCurrent'
#  Total number of fetches                  curl 'localhost:9200/_cat/nodes?v&h=name,searchFetchTotal'
#  Total time spent on fetches              curl 'localhost:9200/_cat/nodes?v&h=name,searchFetchTime'
#  Number of fetches currently in progress  curl 'localhost:9200/_cat/nodes?v&h=name,searchFetchCurrent'

#  $ ./esl GET '_cat/nodes?v&h=name,search*'
#  name                  search.fetch_current search.fetch_time search.fetch_total search.open_contexts search.query_current search.query_time search.query_total search.scroll_current search.scroll_time search.scroll_total
#  lab-rdu-es-master-01b                    0                0s                  0                    0                    0                0s                  0                     0                 0s                   0
#  lab-rdu-es-data-01a                      0              4.4h           38154697                    0                    0              7.2d           81379672                     0              37.1d              883709
#  lab-rdu-es-master-01c                    0                0s                  0                    0                    0                0s                  0                     0                 0s                   0
#  lab-rdu-es-ml-01b                        0                0s                  0                    0                    0                0s                  0                     0                 0s                   0
#  lab-rdu-es-master-01a                    0                0s                  0                    0                    0                0s                  0                     0                 0s                   0
#  lab-rdu-es-data-01f                      0              5.4h           30780808                    0                    0              4.6d           48895470                     0              27.9d              275674
#  lab-rdu-es-data-01b                      0              5.1h           40792211                    0                    0              7.4d           81991439                     0              35.3d             2333088
#  lab-rdu-es-data-01g                      0              6.6h           39498174                    0                    0              6.8d           55235709                     0              30.9d              403116
#  lab-rdu-es-data-01e                      0              5.3h           30798550                    0                    0              4.7d           43743665                     0              27.1d              739857
#  lab-rdu-es-ml-01a                        0                0s                  0                    0                    0                0s                  0                     0                 0s                   0
#  lab-rdu-es-data-01c                      0              4.7h           38287961                    0                    0              7.8d           82490200                     0              32.9d              960862
#  lab-rdu-es-data-01d                      0              7.6h           39549885                    0                    0              9.9d           84728378                     0              33.7d             1706192


#  METRIC DESCRIPTION                              COMMAND
#  Total number of documents indexed               curl 'localhost:9200/_cat/nodes?v&h=name,indexingIndexTotal'
#  Total time spent indexing documents             curl 'localhost:9200/_cat/nodes?v&h=name,indexingIndexTime'
#  Number of documents currently being indexed     curl 'localhost:9200/_cat/nodes?v&h=name,indexingIndexCurrent'
#  Total number of index flushes to disk           curl 'localhost:9200/_cat/nodes?v&h=name,flushTotal'
#  Total time spent on flushing indices to disk    curl 'localhost:9200/_cat/nodes?v&h=name,flushTotalTime'

#  $ ./esl GET '_cat/nodes?v&h=name,index*,flush*&s=name'
#  name                  indexing.delete_current indexing.delete_time indexing.delete_total indexing.index_current indexing.index_time indexing.index_total indexing.index_failed flush.total flush.total_time
#  lab-rdu-es-data-01a                         0                   0s                     0                     21               60.2d          21839154970                   135      104776            10.9h
#  lab-rdu-es-data-01b                         0                 1.3s                 38841                      1               51.3d          17923454032                   107       97473             8.7h
#  lab-rdu-es-data-01c                         0                181ms                   316                      5               62.2d          21603788589                  1163      111210            12.4h
#  lab-rdu-es-data-01d                         0                 62ms                   210                      2               80.9d          17343894967                   179       97929            13.5h
#  lab-rdu-es-data-01e                         0                 43ms                     1                      1               29.4d           5801276095                     0       28557             6.7h
#  lab-rdu-es-data-01f                         0                 2.1s                 38826                      3               25.6d           4839833004                     0       27987             5.7h
#  lab-rdu-es-data-01g                         0                369ms                    92                      1               30.8d           6047979835                     2       32114             6.4h
#  lab-rdu-es-master-01a                       0                   0s                     0                      0                  0s                    0                     0           0               0s
#  lab-rdu-es-master-01b                       0                   0s                     0                      0                  0s                    0                     0           0               0s
#  lab-rdu-es-master-01c                       0                   0s                     0                      0                  0s                    0                     0           0               0s
#  lab-rdu-es-ml-01a                           0                   0s                     0                      0                  0s                    0                     0           0               0s
#  lab-rdu-es-ml-01b                           0                   0s                     0                      0                  0s                    0                     0           0               0s

#  $ ./esl GET '_cluster/pending_tasks?pretty'
#  {
#    "tasks" : [
#      {
#        "insert_order" : 57823107,
#        "priority" : "URGENT",
#        "source" : "create-index [.triggered_watches], cause [auto(bulk api)]",
#        "executing" : true,
#        "time_in_queue_millis" : 126,
#        "time_in_queue" : "126ms"
#      }
#    ]
#  }

#  $ ./esl GET '_nodes/stats/thread_pool' | jq '.nodes[]
#  | {node_name: .name, bulk_queue: .thread_pool.bulk.queue,
#  search_queue: .thread_pool.search.queue, index_queue:
#  .thread_pool.index.queue}' | paste - - - - - -  | sort -k3,3
#  {	  "node_name": "lab-rdu-es-data-01a",	  "bulk_queue": null,	  "search_queue": 0,	  "index_queue": null	}
#  {	  "node_name": "lab-rdu-es-data-01b",	  "bulk_queue": null,	  "search_queue": 0,	  "index_queue": null	}
#  {	  "node_name": "lab-rdu-es-data-01c",	  "bulk_queue": null,	  "search_queue": 0,	  "index_queue": null	}
#  {	  "node_name": "lab-rdu-es-data-01d",	  "bulk_queue": null,	  "search_queue": 0,	  "index_queue": null	}
#  {	  "node_name": "lab-rdu-es-data-01e",	  "bulk_queue": null,	  "search_queue": 0,	  "index_queue": null	}
#  {	  "node_name": "lab-rdu-es-data-01f",	  "bulk_queue": null,	  "search_queue": 0,	  "index_queue": null	}
#  {	  "node_name": "lab-rdu-es-data-01g",	  "bulk_queue": null,	  "search_queue": 0,	  "index_queue": null	}
#  {	  "node_name": "lab-rdu-es-master-01a",	  "bulk_queue": null,	  "search_queue": 0,	  "index_queue": null	}
#  {	  "node_name": "lab-rdu-es-master-01b",	  "bulk_queue": null,	  "search_queue": 0,	  "index_queue": null	}
#  {	  "node_name": "lab-rdu-es-master-01c",	  "bulk_queue": null,	  "search_queue": 0,	  "index_queue": null	}
#  {	  "node_name": "lab-rdu-es-ml-01a",	  "bulk_queue": null,	  "search_queue": 0,	  "index_queue": null	}
#  {	  "node_name": "lab-rdu-es-ml-01b",	  "bulk_queue": null,	  "search_queue": 0,	  "index_queue": null	}

#  $ ./esl GET '_nodes/stats/thread_pool' | jq '.nodes[] | {node_name: .name, bulk_rejected:
#  .thread_pool.bulk.rejected, search_rejected:
#  .thread_pool.search.rejected, index_rejected:
#  .thread_pool.index.rejected}' | paste - - - - - - | sort -k3,3
#  {	  "node_name": "lab-rdu-es-data-01a",	  "bulk_rejected": null,	  "search_rejected": 0,	  "index_rejected": null	}
#  {	  "node_name": "lab-rdu-es-data-01b",	  "bulk_rejected": null,	  "search_rejected": 0,	  "index_rejected": null	}
#  {	  "node_name": "lab-rdu-es-data-01c",	  "bulk_rejected": null,	  "search_rejected": 0,	  "index_rejected": null	}
#  {	  "node_name": "lab-rdu-es-data-01d",	  "bulk_rejected": null,	  "search_rejected": 0,	  "index_rejected": null	}
#  {	  "node_name": "lab-rdu-es-data-01e",	  "bulk_rejected": null,	  "search_rejected": 0,	  "index_rejected": null	}
#  {	  "node_name": "lab-rdu-es-data-01f",	  "bulk_rejected": null,	  "search_rejected": 0,	  "index_rejected": null	}
#  {	  "node_name": "lab-rdu-es-data-01g",	  "bulk_rejected": null,	  "search_rejected": 0,	  "index_rejected": null	}
#  {	  "node_name": "lab-rdu-es-master-01a",	  "bulk_rejected": null,	  "search_rejected": 0,	  "index_rejected": null	}
#  {	  "node_name": "lab-rdu-es-master-01b",	  "bulk_rejected": null,	  "search_rejected": 0,	  "index_rejected": null	}
#  {	  "node_name": "lab-rdu-es-master-01c",	  "bulk_rejected": null,	  "search_rejected": 0,	  "index_rejected": null	}
#  {	  "node_name": "lab-rdu-es-ml-01a",	  "bulk_rejected": null,	  "search_rejected": 0,	  "index_rejected": null	}
#  {	  "node_name": "lab-rdu-es-ml-01b",	  "bulk_rejected": null,	  "search_rejected": 0,	  "index_rejected": null	}

#  $ ./esl GET '_cat/nodes?v&h=name,field*&s=name'
#  name                  fielddata.memory_size fielddata.evictions
#  lab-rdu-es-data-01a                 658.8kb                   0
#  lab-rdu-es-data-01b                 613.6kb                   0
#  lab-rdu-es-data-01c                 574.1kb                   0
#  lab-rdu-es-data-01d                 598.8kb                   0
#  lab-rdu-es-data-01e                   245kb                   0
#  lab-rdu-es-data-01f                 688.5kb                   0
#  lab-rdu-es-data-01g                 698.9kb                   0
#  lab-rdu-es-master-01a                    0b                   0
#  lab-rdu-es-master-01b                    0b                   0
#  lab-rdu-es-master-01c                    0b                   0
#  lab-rdu-es-ml-01a                        0b                   0
#  lab-rdu-es-ml-01b                        0b                   0

# https://www.elastic.co/guide/en/elasticsearch/reference/current/circuit-breaker.html#:~:text=Elasticsearch%20contains%20multiple%20circuit%20breakers,be%20used%20across%20all%20breakers.

#  $ ./esl GET '_nodes/stats/breaker' | jq '.nodes[] |
#  {node_name: .name, fielddata: .breakers.fielddata}' | paste - - - - - - - - - - - | gsed 's/ [{,}]\+[ \t]\+//g;s/,[ \t]\+/ /g' | column -t | sort -k3,3
#  {  "node_name":  "lab-rdu-es-data-01a"    "fielddata":"limit_size_in_bytes":  13199264972  "limit_size":  "12.2gb"  "estimated_size_in_bytes":  674712  "estimated_size":  "658.8kb"  "overhead":  1.03  "tripped":  0  }
#  {  "node_name":  "lab-rdu-es-data-01b"    "fielddata":"limit_size_in_bytes":  13199264972  "limit_size":  "12.2gb"  "estimated_size_in_bytes":  628328  "estimated_size":  "613.6kb"  "overhead":  1.03  "tripped":  0  }
#  {  "node_name":  "lab-rdu-es-data-01c"    "fielddata":"limit_size_in_bytes":  13199264972  "limit_size":  "12.2gb"  "estimated_size_in_bytes":  587944  "estimated_size":  "574.1kb"  "overhead":  1.03  "tripped":  0  }
#  {  "node_name":  "lab-rdu-es-data-01d"    "fielddata":"limit_size_in_bytes":  13216697548  "limit_size":  "12.3gb"  "estimated_size_in_bytes":  613228  "estimated_size":  "598.8kb"  "overhead":  1.03  "tripped":  0  }
#  {  "node_name":  "lab-rdu-es-data-01e"    "fielddata":"limit_size_in_bytes":  13216697548  "limit_size":  "12.3gb"  "estimated_size_in_bytes":  250968  "estimated_size":  "245kb"    "overhead":  1.03  "tripped":  0  }
#  {  "node_name":  "lab-rdu-es-data-01f"    "fielddata":"limit_size_in_bytes":  13216697548  "limit_size":  "12.3gb"  "estimated_size_in_bytes":  705096  "estimated_size":  "688.5kb"  "overhead":  1.03  "tripped":  0  }
#  {  "node_name":  "lab-rdu-es-data-01g"    "fielddata":"limit_size_in_bytes":  13216697548  "limit_size":  "12.3gb"  "estimated_size_in_bytes":  715768  "estimated_size":  "698.9kb"  "overhead":  1.03  "tripped":  0  }
#  {  "node_name":  "lab-rdu-es-master-01a"  "fielddata":"limit_size_in_bytes":  2570007347   "limit_size":  "2.3gb"   "estimated_size_in_bytes":  0       "estimated_size":  "0b"       "overhead":  1.03  "tripped":  0  }
#  {  "node_name":  "lab-rdu-es-master-01b"  "fielddata":"limit_size_in_bytes":  2570007347   "limit_size":  "2.3gb"   "estimated_size_in_bytes":  0       "estimated_size":  "0b"       "overhead":  1.03  "tripped":  0  }
#  {  "node_name":  "lab-rdu-es-master-01c"  "fielddata":"limit_size_in_bytes":  2570007347   "limit_size":  "2.3gb"   "estimated_size_in_bytes":  0       "estimated_size":  "0b"       "overhead":  1.03  "tripped":  0  }
#  {  "node_name":  "lab-rdu-es-ml-01a"      "fielddata":"limit_size_in_bytes":  2563034316   "limit_size":  "2.3gb"   "estimated_size_in_bytes":  0       "estimated_size":  "0b"       "overhead":  1.03  "tripped":  0  }
#  {  "node_name":  "lab-rdu-es-ml-01b"      "fielddata":"limit_size_in_bytes":  2563034316   "limit_size":  "2.3gb"   "estimated_size_in_bytes":  0       "estimated_size":  "0b"       "overhead":  1.03  "tripped":  0  }

#  $ ./esl GET '_nodes/stats/fs?pretty&human' | jq '.nodes[] | {node_name:
#  .name, disk_total_in_bytes: .fs.total.total_in_bytes,
#  disk_free_in_bytes: .fs.total.free_in_bytes, disk_available_in_bytes:
#  .fs.total.available_in_bytes}' | paste - - - - - - | column -t | sort -k3,3
#  {  "node_name":  "lab-rdu-es-data-01a",    "disk_total_in_bytes":  6396823207936,  "disk_free_in_bytes":  811044171776,   "disk_available_in_bytes":  811044171776   }
#  {  "node_name":  "lab-rdu-es-data-01b",    "disk_total_in_bytes":  6396823207936,  "disk_free_in_bytes":  1354002599936,  "disk_available_in_bytes":  1354002599936  }
#  {  "node_name":  "lab-rdu-es-data-01c",    "disk_total_in_bytes":  6396823207936,  "disk_free_in_bytes":  761359892480,   "disk_available_in_bytes":  761359892480   }
#  {  "node_name":  "lab-rdu-es-data-01d",    "disk_total_in_bytes":  7676845096960,  "disk_free_in_bytes":  2568922083328,  "disk_available_in_bytes":  2568922083328  }
#  {  "node_name":  "lab-rdu-es-data-01e",    "disk_total_in_bytes":  7677860118528,  "disk_free_in_bytes":  2131772026880,  "disk_available_in_bytes":  2131772026880  }
#  {  "node_name":  "lab-rdu-es-data-01f",    "disk_total_in_bytes":  7676845096960,  "disk_free_in_bytes":  2690559541248,  "disk_available_in_bytes":  2690559541248  }
#  {  "node_name":  "lab-rdu-es-data-01g",    "disk_total_in_bytes":  7677860118528,  "disk_free_in_bytes":  2741536256000,  "disk_available_in_bytes":  2741536256000  }
#  {  "node_name":  "lab-rdu-es-master-01a",  "disk_total_in_bytes":  18746441728,    "disk_free_in_bytes":  8568393728,     "disk_available_in_bytes":  8568393728     }
#  {  "node_name":  "lab-rdu-es-master-01b",  "disk_total_in_bytes":  18746441728,    "disk_free_in_bytes":  8084430848,     "disk_available_in_bytes":  8084430848     }
#  {  "node_name":  "lab-rdu-es-master-01c",  "disk_total_in_bytes":  18746441728,    "disk_free_in_bytes":  8984297472,     "disk_available_in_bytes":  8984297472     }
#  {  "node_name":  "lab-rdu-es-ml-01a",      "disk_total_in_bytes":  18238930944,    "disk_free_in_bytes":  14374723584,    "disk_available_in_bytes":  14374723584    }
#  {  "node_name":  "lab-rdu-es-ml-01b",      "disk_total_in_bytes":  18238930944,    "disk_free_in_bytes":  14413008896,    "disk_available_in_bytes":  14413008896    }

#  $ ./esl GET '_nodes/stats/transport' | jq '.nodes[] |
#  {node_name: .name, network_bytes_sent: .transport.tx_size_in_bytes,
#  network_bytes_received: .transport.rx_size_in_bytes}' | paste - - - - - | column -t  | sort -k3,3
#  {  "node_name":  "lab-rdu-es-data-01a",    "network_bytes_sent":  52408944342847,  "network_bytes_received":  54247274051103  }
#  {  "node_name":  "lab-rdu-es-data-01b",    "network_bytes_sent":  45309895222860,  "network_bytes_received":  43896368799662  }
#  {  "node_name":  "lab-rdu-es-data-01c",    "network_bytes_sent":  58203554544463,  "network_bytes_received":  51159440090052  }
#  {  "node_name":  "lab-rdu-es-data-01d",    "network_bytes_sent":  45018050581456,  "network_bytes_received":  42779196428855  }
#  {  "node_name":  "lab-rdu-es-data-01e",    "network_bytes_sent":  15507376230658,  "network_bytes_received":  21391180675913  }
#  {  "node_name":  "lab-rdu-es-data-01f",    "network_bytes_sent":  15514256843812,  "network_bytes_received":  14883378980091  }
#  {  "node_name":  "lab-rdu-es-data-01g",    "network_bytes_sent":  17364386204816,  "network_bytes_received":  22156836628921  }
#  {  "node_name":  "lab-rdu-es-master-01a",  "network_bytes_sent":  188026793694,    "network_bytes_received":  120334542247    }
#  {  "node_name":  "lab-rdu-es-master-01b",  "network_bytes_sent":  323265855649,    "network_bytes_received":  341691482926    }
#  {  "node_name":  "lab-rdu-es-master-01c",  "network_bytes_sent":  3094866179457,   "network_bytes_received":  4946955444395   }
#  {  "node_name":  "lab-rdu-es-ml-01a",      "network_bytes_sent":  31545943912,     "network_bytes_received":  7756849840      }
#  {  "node_name":  "lab-rdu-es-ml-01b",      "network_bytes_sent":  31545033884,     "network_bytes_received":  7744644242      }

#  $  ./esl GET '_nodes/stats/http' | jq '.nodes[] | {node_name:
#  .name, http_current_open: .http.current_open, http_total_opened:
#  .http.total_opened}' | paste - - - - - | column -t | sort -k3,3
#  {  "node_name":  "lab-rdu-es-data-01a",    "http_current_open":  294,  "http_total_opened":  264866  }
#  {  "node_name":  "lab-rdu-es-data-01b",    "http_current_open":  291,  "http_total_opened":  195392  }
#  {  "node_name":  "lab-rdu-es-data-01c",    "http_current_open":  290,  "http_total_opened":  195319  }
#  {  "node_name":  "lab-rdu-es-data-01d",    "http_current_open":  292,  "http_total_opened":  194386  }
#  {  "node_name":  "lab-rdu-es-data-01e",    "http_current_open":  292,  "http_total_opened":  32983   }
#  {  "node_name":  "lab-rdu-es-data-01f",    "http_current_open":  294,  "http_total_opened":  33073   }
#  {  "node_name":  "lab-rdu-es-data-01g",    "http_current_open":  291,  "http_total_opened":  44012   }
#  {  "node_name":  "lab-rdu-es-master-01a",  "http_current_open":  0,    "http_total_opened":  500     }
#  {  "node_name":  "lab-rdu-es-master-01b",  "http_current_open":  0,    "http_total_opened":  492     }
#  {  "node_name":  "lab-rdu-es-master-01c",  "http_current_open":  0,    "http_total_opened":  494     }
#  {  "node_name":  "lab-rdu-es-ml-01a",      "http_current_open":  0,    "http_total_opened":  4       }
#  {  "node_name":  "lab-rdu-es-ml-01b",      "http_current_open":  0,    "http_total_opened":  4       }

#  $ ./esl GET '_cat/allocation?v&h=*&s=node'
#  shards disk.indices disk.used disk.avail disk.total disk.percent host            ip              node
#     331          5tb       5tb    754.6gb      5.8tb           87 192.168.112.141 192.168.112.141 lab-rdu-es-data-01a
#     331        4.5tb     4.5tb      1.2tb      5.8tb           78 192.168.112.142 192.168.112.142 lab-rdu-es-data-01b
#     332        5.1tb     5.1tb    705.9gb      5.8tb           88 192.168.112.143 192.168.112.143 lab-rdu-es-data-01c
#     332        4.6tb     4.6tb      2.3tb      6.9tb           66 192.168.116.29  192.168.116.29  lab-rdu-es-data-01d
#     331          5tb       5tb      1.9tb      6.9tb           72 192.168.116.30  192.168.116.30  lab-rdu-es-data-01e
#     331        4.5tb     4.5tb      2.4tb      6.9tb           64 192.168.116.31  192.168.116.31  lab-rdu-es-data-01f
#     331        4.4tb     4.4tb      2.4tb      6.9tb           64 192.168.116.32  192.168.116.32  lab-rdu-es-data-01g

#  $ ./esl GET '_cat/segments?v&h=*'  | head
#  index                                     shard prirep ip              id                     segment generation docs.count docs.deleted     size size.memory committed searchable version compound
#  .reporting-2020.02.02                     0     p      192.168.112.142 kp56LtTuTZSVfYfC3uAzjQ _2               2          1            0    1.4mb        3925 true      true       8.3.0   true
#  .reporting-2020.02.02                     0     r      192.168.116.32  WuOMAIxrRcKG8TqPy8Zleg _2               2          1            0    1.4mb        3925 true      true       8.3.0   true
#  .reporting-2020.01.26                     0     p      192.168.116.29  P4uG_g_JTiC2xk14UpZdIA _12             38         12            4      7mb        4677 true      true       8.3.0   false
#  .reporting-2020.01.26                     0     p      192.168.116.29  P4uG_g_JTiC2xk14UpZdIA _14             40          1            0    2.1mb        3925 true      true       8.3.0   true
#  .reporting-2020.01.26                     0     p      192.168.116.29  P4uG_g_JTiC2xk14UpZdIA _17             43          1            0    2.1mb        3925 true      true       8.3.0   true
#  .reporting-2020.01.26                     0     p      192.168.116.29  P4uG_g_JTiC2xk14UpZdIA _1a             46          1            0      2mb        3925 true      true       8.3.0   true
#  .reporting-2020.01.26                     0     r      192.168.116.31  3is48GZERPOBPNbNpPXs3Q _12             38         12            4      7mb        4677 true      true       8.3.0   false
#  .reporting-2020.01.26                     0     r      192.168.116.31  3is48GZERPOBPNbNpPXs3Q _14             40          1            0    2.1mb        3925 true      true       8.3.0   true
#  .reporting-2020.01.26                     0     r      192.168.116.31  3is48GZERPOBPNbNpPXs3Q _17             43          1            0    2.1mb        3925 true      true       8.3.0   true


#  $ ./esl GET '_cat/segments/filebeat-ilm-6.5.1-2020.06.05*?v&h=*'  | head -20
#  index                                shard prirep ip              id                     segment generation docs.count docs.deleted     size size.memory committed searchable version compound
#  filebeat-ilm-6.5.1-2020.06.05-000007 0     p      192.168.116.30  _N1uuYoxTgOrgbB2l-vg2w _57e          6746      41195            0     39mb       88877 true      true       8.4.0   true
#  filebeat-ilm-6.5.1-2020.06.05-000007 0     p      192.168.116.30  _N1uuYoxTgOrgbB2l-vg2w _5lf          7251      52835            0   52.9mb       75321 true      true       8.4.0   true
#  filebeat-ilm-6.5.1-2020.06.05-000007 0     p      192.168.116.30  _N1uuYoxTgOrgbB2l-vg2w _5xf          7683     182874            0  180.1mb      189464 true      true       8.4.0   true
#  filebeat-ilm-6.5.1-2020.06.05-000007 0     p      192.168.116.30  _N1uuYoxTgOrgbB2l-vg2w _600          7776      68920            0   66.3mb      108566 true      true       8.4.0   true
#  filebeat-ilm-6.5.1-2020.06.05-000007 0     p      192.168.116.30  _N1uuYoxTgOrgbB2l-vg2w _630          7884     164765            0  159.7mb      175977 true      true       8.4.0   true
#  filebeat-ilm-6.5.1-2020.06.05-000007 0     p      192.168.116.30  _N1uuYoxTgOrgbB2l-vg2w _67o          8052     156916            0  161.3mb      178639 true      true       8.4.0   true
#  filebeat-ilm-6.5.1-2020.06.05-000007 0     p      192.168.116.30  _N1uuYoxTgOrgbB2l-vg2w _6az          8171      37713            0     35mb       89133 true      true       8.4.0   true
#  filebeat-ilm-6.5.1-2020.06.05-000007 0     p      192.168.116.30  _N1uuYoxTgOrgbB2l-vg2w _6be          8186     101201            0   82.7mb      121679 true      true       8.4.0   true
#  filebeat-ilm-6.5.1-2020.06.05-000007 0     p      192.168.116.30  _N1uuYoxTgOrgbB2l-vg2w _6dk          8264      13721            0   12.7mb       43238 true      true       8.4.0   true
#  filebeat-ilm-6.5.1-2020.06.05-000007 0     p      192.168.116.30  _N1uuYoxTgOrgbB2l-vg2w _6dz          8279    3376907            0      5gb     3765256 true      true       8.4.0   false
#  filebeat-ilm-6.5.1-2020.06.05-000007 0     p      192.168.116.30  _N1uuYoxTgOrgbB2l-vg2w _6e3          8283      12034            0   10.6mb       41434 true      true       8.4.0   true
#  filebeat-ilm-6.5.1-2020.06.05-000007 0     p      192.168.116.30  _N1uuYoxTgOrgbB2l-vg2w _6es          8308      13432            0   12.3mb       46394 true      true       8.4.0   true
#  filebeat-ilm-6.5.1-2020.06.05-000007 0     p      192.168.116.30  _N1uuYoxTgOrgbB2l-vg2w _6fm          8338       5386            0    5.2mb       36914 true      true       8.4.0   true
#  filebeat-ilm-6.5.1-2020.06.05-000007 0     p      192.168.116.30  _N1uuYoxTgOrgbB2l-vg2w _6g0          8352       5320            0    5.1mb       35248 true      true       8.4.0   true
#  filebeat-ilm-6.5.1-2020.06.05-000007 0     p      192.168.116.30  _N1uuYoxTgOrgbB2l-vg2w _6ga          8362      13524            0   12.3mb       45734 true      true       8.4.0   true
#  filebeat-ilm-6.5.1-2020.06.05-000007 0     p      192.168.116.30  _N1uuYoxTgOrgbB2l-vg2w _6go          8376       3510            0    3.4mb       31955 true      true       8.4.0   true
#  filebeat-ilm-6.5.1-2020.06.05-000007 0     p      192.168.116.30  _N1uuYoxTgOrgbB2l-vg2w _6gq          8378       3069            0    3.1mb       27779 true      true       8.4.0   true
#  filebeat-ilm-6.5.1-2020.06.05-000007 0     p      192.168.116.30  _N1uuYoxTgOrgbB2l-vg2w _6gt          8381     241880            0  210.5mb      214053 true      true       8.4.0   true
#  filebeat-ilm-6.5.1-2020.06.05-000007 0     p      192.168.116.30  _N1uuYoxTgOrgbB2l-vg2w _6gw          8384       2864            0    2.9mb       30675 true      true       8.4.0   true

#  $ ./esl GET 'filebeat-ilm-6.5.1-2020.06.05*/_shard_stores?pretty'
#  {
#    "indices" : { }
#  }

# https://github.com/sematext/cheatsheets
# https://davidlu1001.github.io/2020/04/16/ElasticSearch-Runbook/
# https://www.elastic.co/guide/en/elasticsearch/reference/current/indices-get-settings.html

#  $ ./esl GET "*/_settings/index.refresh_interval?flat_settings&pretty" | grep -E ': {|index' | sed 's/: {//g' | paste - - -|column -t | sort -k1,1 | sed 's/2020.*[^\"]"set/  "set/g' | sort | uniq -c | column -t
#  1   ".security-tokens-7"               "settings"  "index.refresh_interval"  :  "1s"
#  5   "apm-7.2.0-onboarding-             "settings"  "index.refresh_interval"  :  "5s"
#  1   "apm-7.2.0-onboarding-2019.12.13"  "settings"  "index.refresh_interval"  :  "5s"
#  8   "filebeat-6.2.3-                   "settings"  "index.refresh_interval"  :  "5s"
#  45  "filebeat-6.5.1-                   "settings"  "index.refresh_interval"  :  "5s"
#  45  "filebeat-7.6.2-                   "settings"  "index.refresh_interval"  :  "5s"
#  45  "filebeat-default-                 "settings"  "index.refresh_interval"  :  "5s"
#  11  "filebeat-flow-                    "settings"  "index.refresh_interval"  :  "5s"
#  9   "filebeat-ilm-6.5.1-               "settings"  "index.refresh_interval"  :  "5s"
#  1   "filebeat-ilm-7.6.2-               "settings"  "index.refresh_interval"  :  "5s"
#  28  "heartbeat-7.5.1-                  "settings"  "index.refresh_interval"  :  "5s"
#  1   "messaging-6.5.1-                  "settings"  "index.refresh_interval"  :  "5s"
#  1   "messaging-ilm-6.5.1-              "settings"  "index.refresh_interval"  :  "5s"
#  1   "messaging-ilm-7.6.2-              "settings"  "index.refresh_interval"  :  "5s"
#  15  "metricbeat-6.1.1-                 "settings"  "index.refresh_interval"  :  "5s"
#  14  "metricbeat-6.2.3-                 "settings"  "index.refresh_interval"  :  "5s"
#  17  "metricbeat-6.5.1-                 "settings"  "index.refresh_interval"  :  "5s"
#  17  "metricbeat-7.6.2-                 "settings"  "index.refresh_interval"  :  "5s"
#  14  "metricbeat-default-               "settings"  "index.refresh_interval"  :  "5s"
#  21  "packetbeat-default-               "settings"  "index.refresh_interval"  :  "5s"

#  $ ./esl GET "*/_settings?flat_settings&include_defaults&pretty" | grep -E "index.refresh_interval|provided_name" | paste - -  | column -t | sort -k3,3 | sed 's/-2020.*", //g' | sort | uniq -c | grep -vE '"\.[a-z]' | column -t
#  1   "index.provided_name"  :  "<filebeat-ilm-6.5.1-{now/d}-000001>",     "index.refresh_interval"  :  "5s",
#  1   "index.provided_name"  :  "<filebeat-ilm-6.5.1-{now/d}-000002>",     "index.refresh_interval"  :  "5s",
#  1   "index.provided_name"  :  "<filebeat-ilm-6.5.1-{now/d}-000003>",     "index.refresh_interval"  :  "5s",
#  1   "index.provided_name"  :  "<filebeat-ilm-6.5.1-{now/d}-000004>",     "index.refresh_interval"  :  "5s",
#  1   "index.provided_name"  :  "<filebeat-ilm-6.5.1-{now/d}-000005>",     "index.refresh_interval"  :  "5s",
#  1   "index.provided_name"  :  "<filebeat-ilm-6.5.1-{now/d}-000006>",     "index.refresh_interval"  :  "5s",
#  1   "index.provided_name"  :  "<filebeat-ilm-6.5.1-{now/d}-000007>",     "index.refresh_interval"  :  "5s",
#  1   "index.provided_name"  :  "<filebeat-ilm-6.5.1-{now/d}-000008>",     "index.refresh_interval"  :  "5s",
#  1   "index.provided_name"  :  "<filebeat-ilm-6.5.1-{now/d}-000009>",     "index.refresh_interval"  :  "5s",
#  1   "index.provided_name"  :  "<filebeat-ilm-7.6.2-{now/d}-000001>",     "index.refresh_interval"  :  "5s",
#  1   "index.provided_name"  :  "<filebeat-ilm-default-{now/d}-000001>",   "index.refresh_interval"  :  "1s",
#  1   "index.provided_name"  :  "<messaging-ilm-6.5.1-{now/d}-000001>",    "index.refresh_interval"  :  "5s",
#  1   "index.provided_name"  :  "<messaging-ilm-7.6.2-{now/d}-000001>",    "index.refresh_interval"  :  "5s",
#  1   "index.provided_name"  :  "<messaging-ilm-default-{now/d}-000001>",  "index.refresh_interval"  :  "1s",
#  1   "index.provided_name"  :  "api",                                     "index.refresh_interval"  :  "1s",
#  5   "index.provided_name"  :  "apm-7.2.0-onboarding                      "index.refresh_interval"  :  "5s",
#  1   "index.provided_name"  :  "apm-7.2.0-onboarding-2019.12.13",         "index.refresh_interval"  :  "5s",
#  28  "index.provided_name"  :  "f5                                        "index.refresh_interval"  :  "1s",
#  8   "index.provided_name"  :  "filebeat-6.2.3                            "index.refresh_interval"  :  "5s",
#  45  "index.provided_name"  :  "filebeat-6.5.1                            "index.refresh_interval"  :  "5s",
#  45  "index.provided_name"  :  "filebeat-7.6.2                            "index.refresh_interval"  :  "5s",
#  45  "index.provided_name"  :  "filebeat-default                          "index.refresh_interval"  :  "5s",
#  12  "index.provided_name"  :  "filebeat-flow                             "index.refresh_interval"  :  "5s",
#  28  "index.provided_name"  :  "heartbeat-7.5.1                           "index.refresh_interval"  :  "5s",
#  1   "index.provided_name"  :  "ilm-history-1-000001",                    "index.refresh_interval"  :  "1s",
#  1   "index.provided_name"  :  "ilm-history-1-000002",                    "index.refresh_interval"  :  "1s",
#  1   "index.provided_name"  :  "ilm-history-1-000003",                    "index.refresh_interval"  :  "1s",
#  1   "index.provided_name"  :  "k8scapacity                               "index.refresh_interval"  :  "1s",
#  1   "index.provided_name"  :  "k8scapacity-rollup",                      "index.refresh_interval"  :  "1s",
#  1   "index.provided_name"  :  "messaging-6.5.1                           "index.refresh_interval"  :  "5s",
#  15  "index.provided_name"  :  "metricbeat-6.1.1                          "index.refresh_interval"  :  "5s",
#  14  "index.provided_name"  :  "metricbeat-6.2.3                          "index.refresh_interval"  :  "5s",
#  17  "index.provided_name"  :  "metricbeat-6.5.1                          "index.refresh_interval"  :  "5s",
#  17  "index.provided_name"  :  "metricbeat-7.6.2                          "index.refresh_interval"  :  "5s",
#  14  "index.provided_name"  :  "metricbeat-default                        "index.refresh_interval"  :  "5s",
#  21  "index.provided_name"  :  "packetbeat-default                        "index.refresh_interval"  :  "5s",
#  22  "index.provided_name"  :  "syslog                                    "index.refresh_interval"  :  "1s",
#  1   "index.provided_name"  :  "watcher",                                 "index.refresh_interval"  :  "1s",

#  $ ./esl GET '_cat/indices?pretty&v&h=*' -H "Accept: application/json" | head -30
#  [
#    {
#      "health" : "green",
#      "status" : "open",
#      "index" : ".reporting-2020.02.02",
#      "uuid" : "TiSO-koHQoWX-4gTnTMpNg",
#      "pri" : "1",
#      "rep" : "1",
#      "docs.count" : "1",
#      "docs.deleted" : "0",
#      "creation.date" : "1580856822274",
#      "creation.date.string" : "2020-02-04T22:53:42.274Z",
#      "store.size" : "2.9mb",
#      "pri.store.size" : "1.4mb",
#      "completion.size" : "0b",
#      "pri.completion.size" : "0b",
#      "fielddata.memory_size" : "0b",
#      "pri.fielddata.memory_size" : "0b",
#      "fielddata.evictions" : "0",
#      "pri.fielddata.evictions" : "0",
#      "query_cache.memory_size" : "0b",
#      "pri.query_cache.memory_size" : "0b",
#      "query_cache.evictions" : "0",
#      "pri.query_cache.evictions" : "0",
#      "request_cache.memory_size" : "2.7kb",
#      "pri.request_cache.memory_size" : "764b",
#      "request_cache.evictions" : "0",
#      "pri.request_cache.evictions" : "0",
#      "request_cache.hit_count" : "94",
#      "pri.request_cache.hit_count" : "1",

#  $ ./esl GET '_cat/shards/*06.06*?v&h=index,indexing.ind*,node&s=indexing.index_current&pretty' | grep -E '01a|node'
#  index                             indexing.index_current indexing.index_time indexing.index_total indexing.index_failed node
#  filebeat-flow-2020.06.06-09                            0               21.6m              5523467                     0 lab-rdu-es-data-01a
#  metricbeat-6.5.1-2020.06.06                            0                2.3h             42233940                     0 lab-rdu-es-data-01a
#  metricbeat-6.5.1-2020.06.06                            0                2.2h             42245814                     0 lab-rdu-es-data-01a
#  filebeat-flow-2020.06.06-06                            0               20.5m              5562920                     0 lab-rdu-es-data-01a
#  filebeat-flow-2020.06.06-13                            0               21.2m              5490736                     0 lab-rdu-es-data-01a
#  filebeat-flow-2020.06.06-02                            0               22.6m              5806199                     0 lab-rdu-es-data-01a
#  f5-2020.06.06                                          0                3.3m              1339635                     0 lab-rdu-es-data-01a
#  metricbeat-7.6.2-2020.06.06                            0               16.6m              3675532                     0 lab-rdu-es-data-01a
#  metricbeat-7.6.2-2020.06.06                            0               16.9m              3674945                     0 lab-rdu-es-data-01a

#  $ ./esl GET '_cat/indices?pretty&v&h=index,indexing.index*&s=indexing.index_current:desc' -H 'Accept: application/json' | jq .[] | paste - - - - - - - | gsed 's/indexing\.//g;s/[}{]\+[ \t]\+//g;s/[ \t]\+}//g;s/\"//g' | column -t  | head
#  index:  .reporting-2020.02.02,                      index_current:  0,  index_time:  0s,     index_total:  0,          index_failed:  0
#  index:  .reporting-2020.01.26,                      index_current:  0,  index_time:  0s,     index_total:  0,          index_failed:  0
#  index:  heartbeat-7.5.1-2020.05.14,                 index_current:  0,  index_time:  31.1m,  index_total:  10359892,   index_failed:  0
#  index:  heartbeat-7.5.1-2020.05.13,                 index_current:  0,  index_time:  31.2m,  index_total:  10372263,   index_failed:  0
#  index:  heartbeat-7.5.1-2020.05.12,                 index_current:  0,  index_time:  22.6m,  index_total:  10390919,   index_failed:  0
#  index:  heartbeat-7.5.1-2020.05.11,                 index_current:  0,  index_time:  0s,     index_total:  0,          index_failed:  0
#  index:  heartbeat-7.5.1-2020.05.10,                 index_current:  0,  index_time:  23m,    index_total:  10386600,   index_failed:  0
#  index:  .reporting-2019.12.22,                      index_current:  0,  index_time:  0s,     index_total:  0,          index_failed:  0
#  index:  heartbeat-7.5.1-2020.05.19,                 index_current:  0,  index_time:  21.9m,  index_total:  10443265,   index_failed:  0
#  index:  .reporting-2019.12.29,                      index_current:  0,  index_time:  0s,     index_total:  0,          index_failed:  0
  
#  $ /esl GET '_cat/nodes?v&h=name,index*,segments.count,segments.index_writer_memory&s=name'
#  name                  indexing.delete_current indexing.delete_time indexing.delete_total indexing.index_current indexing.index_time indexing.index_total indexing.index_failed segments.count segments.index_writer_memory
#  lab-rdu-es-data-01a                         0                   0s                     0                     22               60.8d          22048637193                   135           8781                      338.1mb
#  lab-rdu-es-data-01b                         0                 1.8s                 50206                      0               51.9d          18155839499                   107           8473                      271.4mb
#  lab-rdu-es-data-01c                         0                189ms                   323                      5               62.7d          21799151001                  1163           8588                      306.1mb
#  lab-rdu-es-data-01d                         0                 62ms                   210                      3                 82d          17522450551                   179           8220                      632.1mb
#  lab-rdu-es-data-01e                         0                 43ms                     1                      1               30.3d           6007364340                     0           8554                      229.5mb
#  lab-rdu-es-data-01f                         0                 3.2s                 50191                      3               26.6d           5050718598                     0           8336                      340.9mb
#  lab-rdu-es-data-01g                         0                382ms                    99                      2               31.5d           6206951502                     2           8558                      524.4mb
#  lab-rdu-es-master-01a                       0                   0s                     0                      0                  0s                    0                     0              0                           0b
#  lab-rdu-es-master-01b                       0                   0s                     0                      0                  0s                    0                     0              0                           0b
#  lab-rdu-es-master-01c                       0                   0s                     0                      0                  0s                    0                     0              0                           0b
#  lab-rdu-es-ml-01a                           0                   0s                     0                      0                  0s                    0                     0              0                           0b
#  lab-rdu-es-ml-01b                           0                   0s                     0                      0                  0s                    0                     0              0                           0b

#  $ show_shards l | grep -E '06.0[456]' | awk '$3 == "p" {print}' | sort -k8,8 | awk '{print $8}' | uniq -c
#    11 lab-rdu-es-data-01d
#    13 lab-rdu-es-data-01e
#    13 lab-rdu-es-data-01f
#     9 lab-rdu-es-data-01g
#    20 lab-rdu-es-data-01a
#    25 lab-rdu-es-data-01b
#    49 lab-rdu-es-data-01c
