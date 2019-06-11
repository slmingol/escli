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
├── escli_c.conf.sample
├── esl -> escli.bash
└── esp -> escli.bash

0 directories, 11 files
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
grep
help_cat
help_indices
list_nodes
list_nodes_storage
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
show_recovery
show_recovery_full
enable_readonly_idx_pattern
disable_readonly_idx_pattern
enable_readonly_idxs
disable_readonly_idxs
show_readonly_idxs
show_readonly_idxs_full
estop
estop_recovery
estop_relo
show_health
show_watermarks
show_state
showcfg_cluster
showrecov_stats
shorecov_hot_threads
shorecov_idx_shard_stats
showcfg_num_shards_per_idx
showcfg_shard_allocations
explain_allocations
show_shard_routing_allocation
enable_shard_allocations
disable_shard_allocations
show_idx_sizes
show_idx_stats
delete_idx
showcfg_idx
showcfg_idx_stats
show_excluded_nodes
exclude_node_name
clear_excluded_nodes
eswhoami
show_auth_roles
show_auth_rolemappings
evict_auth_cred_cache
create_bearer_token
```

You can also get that list with a short description of each function:
```
escli_lsl

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

#6-----------------------------------------------
# health/stat funcs
##-----------------------------------------------
estop                             # mimics `top` command, watching ES nodes CPU/MEM usage
estop_recovery                    # watches the ES recovery queue
estop_relo                        # watches ES relocations
show_health                       # cluster's health stats
show_watermarks                   # show watermarks when storage marks readonly
show_state                        # shows the state of the indicies' shards (RELO, Translog, etc.)
showcfg_cluster                   # show all '_cluster/settings' configs
showrecov_stats                   # show recovery stats (_recovery)
shorecov_hot_threads              # show hot thread details
shorecov_idx_shard_stats          # show an index's shard stats

#7-----------------------------------------------
# shard funcs
##-----------------------------------------------
showcfg_num_shards_per_idx        # show number of shards configured per index template
showcfg_shard_allocations         # show cluster level shard allocation configs
explain_allocations               # show details (aka. explain) cluster allocation activity
show_shard_routing_allocation     # show status (cluster.routing.allocation.enable)
enable_shard_allocations          # allow the allocator to route shards (cluster.routing.allocation.enable)
disable_shard_allocations         # disallow the allocator to route shards (cluster.routing.allocation.enable)

#8-----------------------------------------------
# index stat funcs
##-----------------------------------------------
show_idx_sizes                    # show index sizes sorted (big -> small)
show_idx_stats                    # show index stats sorted (big -> small)
delete_idx                        # delete an index
showcfg_idx                       # show all '<index name>/_settings' configs
showcfg_idx_stats                 # show all '<index name>/_stats'

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
show_auth_roles                   # show auth info about roles
show_auth_rolemappings            # show auth info about role mappings
evict_auth_cred_cache             # evict/clear users from the user cache
create_bearer_token               # create bearer token for user


```

Each function includes a 'show usage' if you run it without any arguments. For example:
```
$ list_nodes

USAGE: list_nodes [l|p|c]

```

Most of the functions will take a single argument, either `l` or `p` or `c` to denote which cluster you want it to target. A handful of functions can take additional items, such as `relo_shard` & `delete_idx`. Consult their usage for more details.

### REFERENCES
* [Document APIs](https://www.elastic.co/guide/en/elasticsearch/reference/current/docs.html)
* [Cluster APIs](https://www.elastic.co/guide/en/elasticsearch/reference/current/cluster.html)
* [cat APIs](https://www.elastic.co/guide/en/elasticsearch/reference/current/cat.html)
* [hub, and extension to CLI git that helps with github](https://hub.github.com/)


