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

filename="es_funcs.bash"

#################################################
### Tips
#################################################
# watch -x bash -c ". es_funcs.bash; show_recovery p"



#################################################
### Functions 
#################################################


#0-----------------------------------------------
# usage funcs
##-----------------------------------------------
escli_ls () {
    # list function names
    awk '/\(\)/ {print $1}' ${filename} | grep -v usage_chk
}

escli_lsl () {
    # list function names + desc.
    while read line; do
        if [[ $line =~ ^#[0-9]+-- ]]; then
            printf "\n"
            grep --color=never -A2 "^${line}" "${filename}"
        else
            grep --color=never -A1 "^${line} () {" "${filename}" | sed 's/ ().*//' | \
                paste - - | pr -t -e30
        fi
    done < <(awk '/^[a-z_-]+ \(\) {|^#[0-9]+--/ {print $1}' "${filename}" | grep -v usage_chk)
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



#1-----------------------------------------------
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



#2-----------------------------------------------
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



#3-----------------------------------------------
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
    cmdOutput=$(${escmd[$env]} POST '_cluster/reroute?explain' -d "$CANCEL")
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

#4-----------------------------------------------
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



#5-----------------------------------------------
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

show_readonly_idxs () {
    # show read_only_allow_delete setting which are enabled (true)
    local env="$1"
    usage_chk1 "$env" || return 1
    printf "\nindices with read_only_allow_delete flag set (true)"
    printf "\n---------------------------------------------------\n"
    show_readonly_idxs_full "$env" | grep -v false
    printf "\n--------- end of check ----------------------------\n\n"
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



#6-----------------------------------------------
# stat funcs
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
    ${escmd[$env]} GET '_nodes/_local/hot_threads' | jq -C . | less -r
}

shorecov_idx_shard_stats () {
    # show an index's shard stats
    local env="$1"
    local idxArg="$2"
    usage_chk3 "$env" "$idxArg" || return 1
    ${escmd[$env]} GET ${idxArg}'/_stats?level=shards&pretty' | jq -C . | less -r
}



#7-----------------------------------------------
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
    ${escmd[$env]} GET '_cluster/allocation/explain?pretty' | jq .
}

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



#8-----------------------------------------------
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



#9-----------------------------------------------
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
    usage_chk1 "$env"|| return 1

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



#10----------------------------------------------
# auth funcs
##-----------------------------------------------
eswhoami () {
    # show auth info about who am i
    local env="$1"
    usage_chk1 "$env"|| return 1
    ${escmd["$env"]} GET '_xpack/security/_authenticate?pretty'
}

show_auth_roles () {
    # show auth info about roles
    local env="$1"
    usage_chk1 "$env"|| return 1
    ${escmd["$env"]} GET '_xpack/security/role?pretty'
}

show_auth_rolemappings () {
    # show auth info about role mappings
    local env="$1"
    usage_chk1 "$env"|| return 1
    ${escmd["$env"]} GET '_xpack/security/role_mapping?pretty'
}

evict_auth_cred_cache () {
    # evict/clear users from the user cache
    local env="$1"
    usage_chk1 "$env"|| return 1
    ${escmd["$env"]} POST '_xpack/security/realm/ldap1/_clear_cache?pretty'
    # https://www.elastic.co/guide/en/elasticsearch/reference/6.5/security-api-clear-cache.html
}



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

# https://www.elastic.co/guide/en/elasticsearch/reference/current/cluster-nodes-stats.html
#
# ./esl GET '_nodes?pretty' | less
# ./esl GET '_nodes/stats?pretty' | less
# ./esl GET '_nodes/stats/indices?pretty' | less
# ./esl GET 'filebeat-6.5.1-2019.06.03/_recovery?pretty' | less 
