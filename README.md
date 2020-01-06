### BACKGROUND
This repo includes a CLI tool to simplify interacting with the Elasticsearch REST API. It makes a couple of assumptions:

- On OSX you have `greadlink` installed via `brew`
- ***(Preferred)*** Your credentials are stored in LastPass
- ***(Preferred)*** You have the LastPass CLI tool installed, `lpass` via `brew`
- ***(Alternative)*** Use some other method to provide credentials (see ``escli.conf.sample`` for other methods)

- Make a copy of `escli.conf.sample` to `escli.conf` and customize (follow guidances within file)
- Optionally make a copy of `escli_c.conf.sample` to `escli_c.conf` and customize

### STRUCTURE
There is 1 CLI tool `escli.bash` which is then linked as `esl` and `esp` to point to a 'lab' and 'production' instances of Elasticsearch clusters. 

The CLI tool `escli.bash` has a single configuration file, `escli.conf`.  Within the config file are the base URL for interacting with the 2 ES clusters, the "Content Type" header to use, and 2 commands for acquiring the username + password to use when interacting with the ES clusters.

The `es_funcs.bash` includes Bash functions which can be sourced into your shell and executed. These functions all leverage the base CLI tool, `escli.bash`.

Finally there's a file `cmds.md` which includes examples with output showcasing how to use the `escli.bash` CLI tool.

```
$ tree -I '*ARCHIVE*|*WIP*' -L 3
.
├── LICENSE
├── README.md
├── cmds.md
├── es_funcs.bash
├── esc -> escli.bash
├── escli.bash
├── escli.conf
├── escli.conf.sample
├── escli_c.conf
├── escli_c.conf.sample
├── esl -> escli.bash
├── esp -> escli.bash
├── upgrade_notes.txt
├── urls.txt
├── zencli.bash
├── zencli.conf
├── zencli.conf.sample
├── zsl -> zencli.bash
└── zsp -> zencli.bash

0 directories, 19 files
```

### USAGE

#### `escli.bash`
The `escli.bash` has 2 "personalities" on which it can operate. When you want to use the "lab" persona, you'd invoke it using the `./esl` symbolic link.

```
$ ./esl

    USAGE: ./esl [HEAD|GET|PUT|POST] '...ES REST CALL...'

    EXAMPLES:

        ./esl GET  '_cat/shards?pretty'
        ./esl GET  '_cat/indices?pretty&v&human'
        ./esl GET  '_cat'
        ./esl GET  ''
        ./esl PUT  '_all/_settings'   -d "$DATA"
        ./esl POST '_cluster/reroute' -d "$DATA"


```

Alternatively, when wanting to use the "production" persona, you'd invoke it using the `./esp` symbolic link.
```
$ ./esp

    USAGE: ./esp [HEAD|GET|PUT|POST] '...ES REST CALL...'

    EXAMPLES:

        ./esp GET  '_cat/shards?pretty'
        ./esp GET  '_cat/indices?pretty&v&human'
        ./esp GET  '_cat'
        ./esp GET  ''
        ./esp PUT  '_all/_settings'   -d "$DATA"
        ./esp POST '_cluster/reroute' -d "$DATA"


```

Additionally if you maintain a cluster that's hosted via Elastic's found.io domain you can use the `./esc` symbolic link.
```
./esc

    USAGE: ./esc [HEAD|GET|PUT|POST] '...ES REST CALL...'

    EXAMPLES:

        ./esc GET  '_cat/shards?pretty'
        ./esc GET  '_cat/indices?pretty&v&human'
        ./esc GET  '_cat'
        ./esc GET  ''
        ./esc PUT  '_all/_settings'   -d "$DATA"
        ./esc POST '_cluster/reroute' -d "$DATA"


```

#### es_funcs.bash
If you'd like to make use of the helper functions within the file `es_funcs.bash` you simply source this file into your existing shell.

```
$ . es_funcs.bash
$
```

This is a list of the functions it provides:
```
$ escli_ls
escli_ls
escli_lsl
help_cat
help_indices
list_nodes
list_nodes_storage
list_nodes_zenoss_alarms
show_shards
show_big_shards
show_small_shards
relo_shard
cancel_relo_shard
cancel_relo_shards_all
retry_unassigned_shards
show_balance_throttle
increase_balance_throttle
reset_balance_throttle
change_allocation_threshold
show_recovery
show_recovery_full
enable_readonly_idx_pattern
disable_readonly_idx_pattern
enable_readonly_idxs
disable_readonly_idxs
show_readonly_idxs
show_readonly_idxs_full
set_idx_default_field
set_tmplate_default_field
set_idx_num_replicas_to_X
estop
estop_recovery
estop_relo
estop_tasks
show_health
show_watermarks
show_state
showcfg_cluster
showrecov_stats
shorecov_hot_threads
shorecov_idx_shard_stats
show_stats_cluster
show_tasks_stats
verify_idx_retentions
showcfg_num_shards_per_idx
showcfg_shard_allocations
explain_allocations
explain_allocations_hddinfo
show_shard_routing_allocation
enable_shard_allocations
disable_shard_allocations
clear_shard_allocations
show_idx_sizes
show_idx_stats
delete_idx
showcfg_idx_cfgs
showcfg_idx_stats
show_idx_version_cnts
show_excluded_nodes
exclude_node_name
clear_excluded_nodes
eswhoami
showcfg_auth_roles
showcfg_auth_rolemappings
list_auth_roles
list_auth_rolemappings
evict_auth_cred_cache
create_bearer_token
del_docs_k8s_ns_range
forcemerge_to_expunge_deletes
estail_deletebyquery
estail_forcemerge
list_templates
```

You can also get that list with a short description of each function:
```
$ escli_lsl

#0-----------------------------------------------
# usage funcs
##-----------------------------------------------
escli_ls                          # list function names
escli_lsl                         # list function names + desc.

#1-----------------------------------------------
# help funcs
##-----------------------------------------------
help_cat                          # print help for _cat API call
help_indices                      # print help for _cat/indices API call

#2-----------------------------------------------
# node funcs
##-----------------------------------------------
list_nodes                        # list ES nodes along w/ a list of data node suffixes for use by other cmds.
list_nodes_storage                # list ES nodes HDD usage
list_nodes_zenoss_alarms          # list ES node HDD usage alarms in Zenoss

#3-----------------------------------------------
# shard mgmt funcs
##-----------------------------------------------
show_shards                       # list all the index shards sorted by size (big->small)
show_big_shards                   # list top 20 shards for a given node's suffix (1a, 1b, etc.)
show_small_shards                 # list smallest 20 shards for a given node's suffix (1a, 1b, etc.)
relo_shard                        # move an indices' shard from node suffix X to node suffix Y
cancel_relo_shard                 # cancel move of an index shard from node suffix X
cancel_relo_shards_all            # cancel all shard RELOCATIONS in recovery queue
retry_unassigned_shards           # reallocate all unassignable shards (elapsed past 5 retries)

#4-----------------------------------------------
# increase/decrease relo/recovery throttles
##-----------------------------------------------
show_balance_throttle             # show routing allocations for balancing & recoveries (current)
increase_balance_throttle         # increase routing allocations for balancing & recoveries (throttle open)
reset_balance_throttle            # reset routing allocations for balancing & recoveries (throttle default)
change_allocation_threshold       # override the allocation threshold (cluster.routing.allocation.balance.threshold)

#5-----------------------------------------------
# recovery funcs
##-----------------------------------------------
show_recovery                     # show a summary of recovery queue
show_recovery_full                # show full details of recovery queue
enable_readonly_idx_pattern       # set read_only_allow_delete flag for set of indices
disable_readonly_idx_pattern      # disable read_only_allow_delete flag for set of indices
enable_readonly_idxs              # set read_only_allow_delete flag
disable_readonly_idxs             # clear read_only_allow_delete flag
show_readonly_idxs                # show read_only_allow_delete setting which are enabled (true)
show_readonly_idxs_full           # show read_only_allow_delete setting for all indices
set_idx_default_field             # set index.query.default_field => [ "*" ]
set_tmplate_default_field         # set template index.query.default_field => [ "*" ]

#6-----------------------------------------------
# health/stat funcs
##-----------------------------------------------
estop                             # mimics `top` command, watching ES nodes CPU/MEM usage
estop_recovery                    # watches the ES recovery queue
estop_relo                        # watches ES relocations
estop_tasks                       # watches ES tasks
show_health                       # cluster's health stats
show_watermarks                   # show watermarks when storage marks readonly
show_state                        # shows the state of the indicies' shards (RELO, Translog, etc.)
showcfg_cluster                   # show all '_cluster/settings' configs
showrecov_stats                   # show recovery stats (_recovery)
shorecov_hot_threads              # show hot thread details
shorecov_idx_shard_stats          # show an index's shard stats
show_stats_cluster                # shows the _stats for entire cluster
show_tasks_stats                  # shows the tasks queue
verify_idx_retentions             # shows the distribution of index retentions (days per index type & version)

#7-----------------------------------------------
# shard funcs
##-----------------------------------------------
showcfg_num_shards_per_idx        # show number of shards configured per index template
showcfg_shard_allocations         # show cluster level shard allocation configs
explain_allocations               # show details (aka. explain) cluster allocation activity
explain_allocations_hddinfo       # show details (aka. explain) cluster allocation activity (full)
show_shard_routing_allocation     # show status (cluster.routing.allocation.enable)
enable_shard_allocations          # allow the allocator to route shards (cluster.routing.allocation.enable)
disable_shard_allocations         # disallow the allocator to route shards (cluster.routing.allocation.enable)
clear_shard_allocations           # clear the allocator to route shards (cluster.routing.allocation.enable)

#8-----------------------------------------------
# index stat funcs
##-----------------------------------------------
show_idx_sizes                    # show index sizes sorted (big -> small)
show_idx_stats                    # show index stats sorted (big -> small)
delete_idx                        # delete an index
showcfg_idx_cfgs                  # show all '<index name>/_settings' configs
showcfg_idx_stats                 # show all '<index name>/_stats'
show_idx_version_cnts             # show index sizes sorted (big -> small)

#9-----------------------------------------------
# node exclude/include funcs
##-----------------------------------------------
show_excluded_nodes               # show excluded nodes from cluster
exclude_node_name                 # exclude a node from cluster (node suffix)
clear_excluded_nodes              # clear any excluded cluster nodes

#10----------------------------------------------
# auth funcs
##-----------------------------------------------
eswhoami                          # show auth info about who am i
showcfg_auth_roles                # show auth info about roles
showcfg_auth_rolemappings         # show auth info about role mappings
list_auth_roles                   # list all roles
list_auth_rolemappings            # list all rolemappings
evict_auth_cred_cache             # evict/clear users from the user cache
create_bearer_token               # create bearer token for user

#11----------------------------------------------
# k8s namespace funcs
##-----------------------------------------------
del_docs_k8s_ns_range             # delete k8s namespace docs over a specific time range
forcemerge_to_expunge_deletes     # force merge of shards to expunge deleted docs
estail_deletebyquery              # watch deletebyquery tasks
estail_forcemerge                 # watch forcemerges in tasks queue

#12----------------------------------------------
# template funcs
##-----------------------------------------------
list_templates                    # show all template details


```

Each function includes a 'show usage' if you run it without any arguments. For example:
```
$ list_nodes

USAGE: list_nodes [l|p|c]

```

Most of the functions will take a single argument, either `l` or `p` or `c` to denote which cluster you want it to target. A handful of functions can take additional items, such as `relo_shard` & `delete_idx`. Consult their usage for more details.

### WORKFLOWS

#### Deleting docs from an index

```
del_docs_k8s_ns_range

USAGE: del_docs_k8s_ns_range [l|p|c] <idx pattern> <k8s namespace> <start time> <end time>


  * TIME FORMAT: 2019-07-10T00:00:00.000Z

  * INDX FORMAT:
      -- filebeat-*
      -- -or- filebeat-6.5.1-2019.07.04,filebeat-6.5.1-2019.07.05,....
      -- -or- filebeat-*-2019.07*


```

```
$ del_docs_k8s_ns_range l filebeat-6.5.1-2019.07.31 big-dripper 2019-07-31T13:58:29.145Z 2019-07-31T17:40:00.000Z
{"task":"vudQxvnfSQuxMtdkq8ZTUQ:2390166372"}

$ del_docs_k8s_ns_range l filebeat-6.5.1-2019.07.31 flex-generator 2019-07-31T13:58:29.145Z 2019-07-31T17:40:00.000Z
{"task":"vudQxvnfSQuxMtdkq8ZTUQ:2390297564"}
```

```
$ estail_deletebyquery l
estail_deletebyquery
===================================
indices:data/write/delete/byquery  transport  43m    lab-rdu-es-data-01a
indices:data/write/delete/byquery  transport  42.8m  lab-rdu-es-data-01a
===================================
estail_deletebyquery
===================================
indices:data/write/delete/byquery  transport  43.2m  lab-rdu-es-data-01a
indices:data/write/delete/byquery  transport  43m    lab-rdu-es-data-01a
===================================
estail_deletebyquery
===================================
indices:data/write/delete/byquery  transport  43.3m  lab-rdu-es-data-01a
===================================
estail_deletebyquery
===================================
indices:data/write/delete/byquery  transport  43.5m  lab-rdu-es-data-01a
===================================
estail_deletebyquery
===================================
done
```

```
$ forcemerge_to_expunge_deletes l filebeat-6.5.1-2019.07.31
...
... Ctrl-C at any time, it's scheduled
...
```

```
$ estail_forcemerge l
estail_forcemerge
===================================
indices:admin/forcemerge     transport  15.1m  lab-rdu-es-data-01a
indices:admin/forcemerge[n]  direct     15.1m  lab-rdu-es-data-01a
indices:admin/forcemerge[n]  transport  15.1m  lab-rdu-es-data-01c
indices:admin/forcemerge[n]  transport  15.1m  lab-rdu-es-data-01b
===================================
estail_forcemerge
===================================
indices:admin/forcemerge     transport  15.3m  lab-rdu-es-data-01a
indices:admin/forcemerge[n]  direct     15.3m  lab-rdu-es-data-01a
indices:admin/forcemerge[n]  transport  15.3m  lab-rdu-es-data-01b
indices:admin/forcemerge[n]  transport  15.3m  lab-rdu-es-data-01c
===================================
...
...
estail_forcemerge
===================================
indices:admin/forcemerge     transport  24.6m  lab-rdu-es-data-01a
indices:admin/forcemerge[n]  direct     24.6m  lab-rdu-es-data-01a
indices:admin/forcemerge[n]  transport  24.6m  lab-rdu-es-data-01b
indices:admin/forcemerge[n]  transport  24.6m  lab-rdu-es-data-01c
===================================
estail_forcemerge
===================================
done
```

### REFERENCES
* [Document APIs](https://www.elastic.co/guide/en/elasticsearch/reference/current/docs.html)
* [Cluster APIs](https://www.elastic.co/guide/en/elasticsearch/reference/current/cluster.html)
* [cat APIs](https://www.elastic.co/guide/en/elasticsearch/reference/current/cat.html)
* [hub, and extension to CLI git that helps with github](https://hub.github.com/)


