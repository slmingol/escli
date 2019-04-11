### es wrapper cmd inventory
declare -A escmd
escmd[l]="./esl"
escmd[p]="./esp"

### es data node naming conventions
nodeBaseName="rdu-es-data-0"
declare -A esnode
esnode[l]="lab-${nodeBaseName}"
esnode[p]="${nodeBaseName}"

filename="es_funcs.bash"

#################################################
### Functions 
#################################################


#------------------------------------------------
# usage funcs
#------------------------------------------------
escli_ls () {
    # list function names
    awk '/\(\)/ {print $1}' ${filename}
}

escli_lsl () {
    # list function names + desc.
    while read line; do
        grep -A1 "^${line} () {" "${filename}" | sed 's/ ().*//' | \
            paste - - | pr -t -e30
    done < <(awk '/^[a-z_-]+ \(\) {/ {print $1}' "${filename}")
}

usage_chk1 () {
    # usage msg for cmds w/ 1 arg
    local env="$1"

    [[ $env =~ [lp] ]] && return 0 || \
        printf "\nUSAGE: ${FUNCNAME[1]} [l|p]\n\n" && return 1
}

usage_chk2 () {
    # usage msg for cmds w/ 2 arg (where 2nd arg. is a node suffix)
    local env="$1"
    local node="$2"

    [[ $env =~ [lp] && $node =~ 1[a-z] ]] && return 0 || \
        printf "\nUSAGE: ${FUNCNAME[1]} [l|p] <node suffix--[1a|1b|1c|1d...]>\n\n" \
        && return 1
}

usage_chk3 () {
    # usage msg for cmds w/ 2 arg (where 2nd arg. is a index pattern)
    local env="$1"
    local idxArg="$2"

    [[ $env =~ [lp] && $idxArg != '' ]] && return 0 || \
        printf "\nUSAGE: ${FUNCNAME[1]} [l|p] <idx pattern>\n\n" \
        && return 1
}

usage_chk4 () {
    # usage msg for cmds w/ 4 arg (<shard name> <shard num> <from node suf.>)
    local env="$1"
    local shardName="$2"
    local shardNum="$3"
    local fromCode="$4"

    [[ $env =~ [lp] && $shardName != '' \
        && $shardNum != '' \
        && $fromCode =~ 1[a-z] ]] && return 0 || \
        printf "\nUSAGE: ${FUNCNAME[1]} [l|p] <shard name> <shard num> <from node>\n\n" \
        && return 1
}

usage_chk5 () {
    # usage msg for cmds w/ 5 arg (<shard name> <shard num> <from node suf.> <to node suf.>)
    local env="$1"
    local shardName="$2"
    local shardNum="$3"
    local fromCode="$4"
    local toCode="$5"

    [[ $env =~ [lp] && $shardName != '' \
        && $shardNum != '' \
        && $fromCode =~ 1[a-z] \
        && $toCode =~ 1[a-z] ]] && return 0 || \
        printf "\nUSAGE: ${FUNCNAME[1]} [l|p] <shard name> <shard num> <from node> <to node>\n\n" \
        && return 1
}

#------------------------------------------------
# node funcs
#------------------------------------------------
list_nodes () {
    # list ES nodes along w/ a list of data node suffixes for use by other cmds.
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
    show_shards "$env" | grep -E "index|${node}" | head -20
}

show_small_shards () {
    # list smallest 20 shards for a given node's suffix (1a, 1b, etc.)
    local env="$1"
    local node="$2"
    usage_chk2 "$env" "$node" || return 1
    show_shards "$env" | grep -E "index|${node}" | tail -20
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
    ${escmd[$env]} POST '_cluster/reroute' -d "$MOVE"
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
    ${escmd[$env]} POST '_cluster/reroute' -d "$CANCEL"
}


#------------------------------------------------
# recovery funcs
#------------------------------------------------
show_recovery () {
    # show a summary of recovery queue
    local env="$1"
    usage_chk1 "$env" || return 1
    ${escmd[$env]} GET '_cat/recovery?bytes=gb&v&h=index,shard,time,type,stage,source_node,target_node,files,files_recovered,files_percent,bytes_total,bytes_percent' \
        | grep -v done | head
}

show_recovery_full () {
    # show full details of recovery queue
    local env="$1"
    usage_chk1 "$env" || return 1
    ${escmd[$env]} GET '_cat/recovery?v' \
        | grep -v done | head
}


enable_readonly_idx_pattern () {
    # set read_only_allow_delete flag for set of indices
    local env="$1"
    local idxArg="$2"
    usage_chk3 "$env" "$idxArg" || return 1
    DISALLOWDEL=$(cat <<-EOM
        {
         "index": {
           "blocks": {
             "read_only_allow_delete": "true"
            }
          }
        }
	EOM
    )
    ${escmd[$env]} PUT "${idxArg}/_settings" -d "$DISALLOWDEL"
}

disable_readonly_idx_pattern () {
    # disable read_only_allow_delete flag for set of indices
    local env="$1"
    local idxArg="$2"
    usage_chk3 "$env" "$idxArg" || return 1
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
    ${escmd[$env]} PUT "${idxArg}/_settings" -d "$ALLOWDEL"
}

enable_readonly_idxs () {
    # set read_only_allow_delete flag
    local env="$1"
    usage_chk1 "$env" || return 1
    DISALLOWDEL=$(cat <<-EOM
        {
         "index": {
           "blocks": {
             "read_only_allow_delete": "true"
            }
          }
        }
	EOM
    )
    ${escmd[$env]} PUT '_all/_settings' -d "$DISALLOWDEL"
}

disable_readonly_idxs () {
    # clear read_only_allow_delete flag
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

show_readonly_idxs_full () {
    # show read_only_allow_delete setting for all indices
    local env="$1"
    usage_chk1 "$env" || return 1
    ${escmd[$env]} GET \
        '_all/_settings?pretty&filter_path=*.*.*.*.read_only_allow_delete' | \
        paste - - - - - - - - - | \
        column -t |  grep -v '}   }' | sort
}

show_readonly_idxs () {
    # show read_only_allow_delete setting which are enabled (true)
    local env="$1"
    usage_chk1 "$env" || return 1
    printf "\nindices with read_only_allow_delete flag set (true)"
    printf "\n---------------------------------------------------\n"
    show_readonly_idxs_full "$env" | grep -v false
    printf "\n--------- end of check ----------------------------\n\n"
}


#------------------------------------------------
# stat funcs
#------------------------------------------------
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
    watch "${escmd["$env"]} GET '_cat/recovery?bytes=gb&v&h=index,shard,time,type,stage,source_node,target_node,files,files_recovered,files_percent,bytes_total,bytes_percent' | grep -v done | head"
}

show_health () {
    # cluster's health stats
    local env="$1"
    usage_chk1 "$env" || return 1
    ${escmd[$env]} GET '_cluster/health?pretty'
}

show_state () {
    # shows the state of the indicies' shards (RELO, Translog, etc.)
    local env="$1"
    usage_chk1 "$env" || return 1
    ${escmd[$env]} GET '_cat/shards?bytes=gb&v&human' | grep -v STARTED
}

showcfg_num_shards_per_idx () {
    # show number of shards configured per index template
    local env="$1"
    usage_chk1 "$env" || return 1
    ${escmd[$env]} GET '_template/*?pretty&filter_path=*.*.*.number_of_shards' | \
        paste - - - - - - - | \
        column -t | grep -v '}   }' | sort
}

explain_allocations () {
    # show details (aka. explain) cluster allocation activity
    local env="$1"
    usage_chk1 "$env" || return 1
    ${escmd[$env]} GET '_cluster/allocation/explain?pretty'
}


#------------------------------------------------
# help funcs
#------------------------------------------------
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


#------------------------------------------------
# index funcs
#------------------------------------------------
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
