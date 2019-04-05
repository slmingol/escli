### es wrapper cmd inventory
declare -A escmd
escmd[l]="./esl"
escmd[p]="./esp"

### es data node naming conventions
nodeBaseName="rdu-es-data-0"
declare -A esnode
esnode[l]="lab-${nodeBaseName}"
esnode[p]="${nodeBaseName}"

#################################################
### Functions 
#################################################


#------------------------------------------------
# usage funcs
#------------------------------------------------
usage_chk1 () {
    local env="$1"

    [[ $env =~ [lp] ]] && return 0 || \
        printf "\nUSAGE: ${FUNCNAME[1]} [l|p]\n\n" && return 1
}

usage_chk2 () {
    local env="$1"
    local node="$2"

    [[ $env =~ [lp] && $node =~ 1[a-z] ]] && return 0 || \
        printf "\nUSAGE: ${FUNCNAME[1]} [l|p] <node suffix--[1a|1b|1c|1d...]>\n\n" \
        && return 1
}

usage_chk3 () {
    local env="$1"
    local idxArg="$2"

    [[ $env =~ [lp] && $idxArg != '' ]] && return 0 || \
        printf "\nUSAGE: ${FUNCNAME[1]} [l|p] <idx pattern]>\n\n" \
        && return 1
}

#------------------------------------------------
# node funcs
#------------------------------------------------
list_nodes () {
    local env="$1"
    usage_chk1 "$env" || return 1
    output=$(${escmd[$env]} GET '_cat/nodes')
    dnodes=$(echo "${output}" | awk '/data/ { print $10 }' | sed 's/.*-0//' | sort | paste -s -d"," -)

    printf "\n%s\n\n"                         "${output}"
    printf "valid data node suffixes: %s\n\n" "${dnodes}"
}


#------------------------------------------------
# shard funcs
#------------------------------------------------
show_shards () {
    local env="$1"
    usage_chk1 "$env" || return 1
    ${escmd[$env]} GET '_cat/shards?v&human&pretty&s=store:desc,index,shard'
}

show_big_shards () {
    local env="$1"
    local node="$2"
    usage_chk2 "$env" "$node" || return 1
    show_shards "$env" | grep -E "index|${node}" | head -20
}

show_small_shards () {
    local env="$1"
    local node="$2"
    usage_chk2 "$env" "$node" || return 1
    show_shards "$env" | grep -E "index|${node}" | tail -20
}

relo_shard () {
    shardName=$1
    shardNum=$2
    fromCode=$3
    toCode=$4
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
    ${escmd[$env]} POST '_cluster/reroute' -d "$MOVE"
}


#------------------------------------------------
# recovery funcs
#------------------------------------------------
show_recovery () {
    local env="$1"
    usage_chk1 "$env" || return 1
    ${escmd[$env]} GET '_cat/recovery?bytes=gb&v&h=index,shard,time,type,stage,source_node,target_node,files,files_recovered,files_percent,bytes_total,bytes_percent' \
        | grep -v done | head
}

show_recovery_full () {
    local env="$1"
    usage_chk1 "$env" || return 1
    ${escmd[$env]} GET '_cat/recovery?v' \
        | grep -v done | head
}


unblock_readonly_idxs () {
    local env="$1"
    usage_chk1 "$env" || return 1
    ALLOWDEL=$(cat <<-EOM
        {
         "index": {
           "blocks": {
             "read_only_allow_delete": "false"
            }
          }
        }
	EOM
    )
    ${escmd[$env]} PUT '_all/_settings' -d "$ALLOWDEL"
}


#------------------------------------------------
# stat funcs
#------------------------------------------------
estop () {
    local env="$1"
    usage_chk1 "$env" || return 1
    watch "${escmd[$env]} GET '_cat/nodes?v&h=ip,heap.percent,ram.percent,cpu,load_1m,load_5m,load_15m,node.role,master,name,nodeId,diskAvail'"
}

estop_recovery () {
    local env="$1"
    usage_chk1 "$env" || return 1
    watch "${escmd["$env"]} GET '_cat/recovery?bytes=gb&v&h=index,shard,time,type,stage,source_node,target_node,files,files_recovered,files_percent,bytes_total,bytes_percent' | grep -v done | head"
}

show_health () {
    local env="$1"
    usage_chk1 "$env" || return 1
    ${escmd[$env]} GET '_cluster/health?pretty'
}

show_state () {
    local env="$1"
    usage_chk1 "$env" || return 1
    ${escmd[$env]} GET '_cat/shards?bytes=gb&v&human' | grep -v STARTED
}

showcfg_num_shards_per_idx () {
    local env="$1"
    usage_chk1 "$env" || return 1
    ${escmd[$env]} GET '_template/*?pretty&filter_path=*.*.*.number_of_shards' | \
        paste - - - - - - - | \
        column -t | grep -v '}   }' | sort
}

explain_allocations () {
    local env="$1"
    usage_chk1 "$env" || return 1
    ${escmd[$env]} GET '_cluster/allocation/explain?pretty'
}


#------------------------------------------------
# help funcs
#------------------------------------------------
help_cat () {
    local env="$1"
    usage_chk1 "$env" || return 1
    ${escmd[$env]} GET '_cat'
}

help_indices () {
    local env="$1"
    usage_chk1 "$env" || return 1
    ${escmd[$env]} GET '_cat/indices?pretty&v&help' | less
}


#------------------------------------------------
# index funcs
#------------------------------------------------
show_idx_sizes () {
    local env="$1"
    usage_chk1 "$env" || return 1
    ${escmd[$env]} GET '_cat/indices?v&h=index,pri,rep,docs.count,store.aize,pri.store.size&human&s=store.size:desc&bytes=gb'
}

show_idx_stats () {
    local env="$1"
    usage_chk1 "$env" || return 1
    ${escmd[$env]} GET '_cat/indices?pretty&v&s=pri.store.size:desc'
}

delete_idx () {
    local env="$1"
    local idxArg="$2"
    usage_chk3 "$env" "$idxArg" || return 1
    ${escmd[$env]} DELETE "$idxArg"
}
