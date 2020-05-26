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
### Globals
#################################################
# sed
[ "$(uname)" == 'Darwin' ] && sedCmd=gsed || sedCmd=sed

#################################################
### Functions 
#################################################

#0-----------------------------------------------
# helper funcs
##-----------------------------------------------
calc_date () {
    # print UTC date X "days | days ago"
    local english_days="$1"

    [ "$(uname)" == 'Darwin' ] && dateCmd=gdate || dateCmd=date
    [[ $english_days != *days* ]] && \
        printf "\nUSAGE: ${FUNCNAME[1]} [X days ago | X days]\n\n" && return 1

    ${dateCmd} -u --date="$english_days" +%Y.%m.%d
}

calc_date_1daybefore () {
    # print UTC date X 1 day before given date (YYYY-mm-dd)
    local date="$1"

    [ "$(uname)" == 'Darwin' ] && dateCmd=gdate || dateCmd=date
    [[ ! $date =~ [0-9]{4}-[0-9]+-[0-9]+ ]] && \
        printf "\nUSAGE: ${FUNCNAME[1]} [YYYY-mm-dd]\n\n" && return 1

    ${dateCmd} -u --date="$date -1 days" +%Y.%m.%d
}

calc_date_1dayafter () {
    # print UTC date X 1 day after given date (YYYY-mm-dd)
    local date="$1"

    [ "$(uname)" == 'Darwin' ] && dateCmd=gdate || dateCmd=date
    [[ ! $date =~ [0-9]{4}-[0-9]+-[0-9]+ ]] && \
        printf "\nUSAGE: ${FUNCNAME[1]} [YYYY-mm-dd]\n\n" && return 1

    ${dateCmd} -u --date="$date +1 days" +%Y.%m.%d
}

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
                paste - - | pr -t -e37
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

    [[ $env =~ [lpc] && $idxArg != '' \
            && $namespace != '' \
            && $sTime != '' \
            && $sTime =~ [0-9]{4}-[0-9]{2}-[0-9]{2}T && $sTime =~ [0-9]{2}:[0-9]{2}:[0-9]{2}.[0-9]{3}Z \
            && $eTime != '' \
            && $eTime =~ [0-9]{4}-[0-9]{2}-[0-9]{2}T && $eTime =~ [0-9]{2}:[0-9]{2}:[0-9]{2}.[0-9]{3}Z ]] \
        && return 0 || \
            printf "\nUSAGE: ${FUNCNAME[1]} [l|p|c] <idx pattern> <k8s namespace> <start time> <end time>\n\n\n" \
                && printf "  * TIME FORMAT: 2019-07-10T00:00:00.000Z\n\n" \
                && printf "  * INDX FORMAT:\n      -- %s\n      -- %s\n      -- %s\n\n\n" \
                    "filebeat-*" \
                    "-or- filebeat-6.5.1-2019.07.04,filebeat-6.5.1-2019.07.05,...." \
                    "-or- filebeat-*-2019.07*" \
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


#2-----------------------------------------------
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



#3-----------------------------------------------
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
    printf "valid data node suffixes: %s\n\n" "${dnodes}"
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

#4-----------------------------------------------
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

#5-----------------------------------------------
# increase/decrease relo/recovery throttles
##-----------------------------------------------
show_balance_throttle () {
    # show routing allocations for balancing & recoveries (current)
    local env="$1"
    usage_chk1 "$env" || return 1
    showcfg_cluster "$env" | jq '.' | grep -E "allocation.(node|cluster|type)|recovery.max_bytes_per_sec"
}

increase_balance_throttle () {
    # increase routing allocations for balancing & recoveries (throttle open)
    local env="$1"
    usage_chk1 "$env" || return 1
    THROTTLEINC=$(cat <<-EOM
        {
            "persistent": {
                "cluster.routing.allocation.cluster_concurrent_rebalance" : "10",
                "cluster.routing.allocation.node_concurrent_incoming_recoveries" : "5",
                "cluster.routing.allocation.node_concurrent_outgoing_recoveries" : "5",
                "cluster.routing.allocation.node_concurrent_recoveries" : "20",
                "cluster.routing.allocation.node_initial_primaries_recoveries" : "10",
                "indices.recovery.max_bytes_per_sec" : "2000mb"
            }
        }
	EOM
    )
    cmdOutput=$(${escmd[$env]} PUT '_cluster/settings' -d "$THROTTLEINC")
    showcfg_cluster "$env" | jq .persistent
}

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



#6-----------------------------------------------
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



#7-----------------------------------------------
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

    ${escmd[$env]} GET ${idxArg}'/_search?pretty' -d \
        '{
          "size": 0,
          "aggs": {
            "hosts": {
                "terms" : { "field": "host.name",  "size": 500 }
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
		              "calendar_interval": "day"
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



#8-----------------------------------------------
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



#9-----------------------------------------------
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



#10----------------------------------------------
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



#11----------------------------------------------
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



#12----------------------------------------------
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
    # eg: 
    # $ del_docs_k8s_ns_range l filebeat-* big-dipper-perf 2019-07-11T11:57:20.968Z 2019-07-12T04:26:38.757Z
    # {"task":"vudQxvnfSQuxMtdkq8ZTUQ:844209600"}

    # REF: https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-delete-by-query.html
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



#13----------------------------------------------
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
# $ ./esc GET '_cat/thread_pool?v&h=node_name,name,active,rejected,completed' | head
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
