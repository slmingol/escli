### BACKGROUND
This repo includes a CLI tool to simplify interacting with the Elasticsearch REST API. It makes a couple of assumptions:

- On OSX you have `greadlink` installed via `brew`
- (Preferred) Your credentials are store in LastPass
- (Preferred) You have the LastPass CLI tool install, `lpass` via `brew`
- (Alternative) Use some other method to provide credentials (see escli.conf for other methods)

### STRUCTURE
There is 1 CLI tool `escli.bash` which is then linked as `esl` and `esp` to point to a 'lab' and 'production' instances of Elasticsearch clusters. 

The CLI tool `escli.bash` has a single configuration file, `escli.conf`.  Within the config file are the base URL for interacting with the 2 ES clusters, the "Content Type" header to use, and 2 commands for acquiring the username + password to use when interacting with the ES clusters.

The `es_funcs.bash` includes Bash functions which can be sourced into your shell and executed. These functions all leverage the base CLI tool, `escli.bash`.

Finally there's a file `cmds.md` which includes examples with output showcasing how to use the `escli.bash` CLI tool.

```
$ tree -I '*ARCHIVE*|*WIP*' -L 3
.
├── README.md
├── cmds.md
├── es_funcs.bash
├── escli.bash
├── escli.conf
├── esl -> escli.bash
└── esp -> escli.bash

0 directories, 7 files
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
usage_chk1
usage_chk2
usage_chk3
usage_chk4
usage_chk5
list_nodes
show_shards
show_big_shards
show_small_shards
relo_shard
cancel_relo_shard
show_recovery
show_recovery_full
enable_readonly_idx_pattern
disable_readonly_idx_pattern
enable_readonly_idxs
disable_readonly_idxs
show_readonly_idxs_full
show_readonly_idxs
estop
estop_recovery
estop_relo
show_health
show_watermarks
show_state
showcfg_cluster
showcfg_num_shards_per_idx
showcfg_shard_allocations
explain_allocations
help_cat
help_indices
show_idx_sizes
show_idx_stats
delete_idx
exclude_node_name
show_excluded_nodes
clear_excluded_nodes
```

You can also get that list with a short description of each function:
```
$ escli_lsl

#1-----------------------------------------------
# usage funcs
##-----------------------------------------------
escli_ls                          # list function names
escli_lsl                         # list function names + desc.

#2-----------------------------------------------
# node funcs
##-----------------------------------------------
list_nodes                        # list ES nodes along w/ a list of data node suffixes for use by other cmds.

#3-----------------------------------------------
# shard funcs
##-----------------------------------------------
show_shards                       # list all the index shards sorted by size (big->small)
show_big_shards                   # list top 20 shards for a given node's suffix (1a, 1b, etc.)
show_small_shards                 # list smallest 20 shards for a given node's suffix (1a, 1b, etc.)
relo_shard                        # move an indices' shard from node suffix X to node suffix Y
cancel_relo_shard                 # cancel move of an index shard from node suffix X

#4-----------------------------------------------
# recovery funcs
##-----------------------------------------------
show_recovery                     # show a summary of recovery queue
show_recovery_full                # show full details of recovery queue
enable_readonly_idx_pattern       # set read_only_allow_delete flag for set of indices
disable_readonly_idx_pattern      # disable read_only_allow_delete flag for set of indices
enable_readonly_idxs              # set read_only_allow_delete flag
disable_readonly_idxs             # clear read_only_allow_delete flag
show_readonly_idxs_full           # show read_only_allow_delete setting for all indices
show_readonly_idxs                # show read_only_allow_delete setting which are enabled (true)

#5-----------------------------------------------
# stat funcs
##-----------------------------------------------
estop                             # mimics `top` command, watching ES nodes CPU/MEM usage
estop_recovery                    # watches the ES recovery queue
estop_relo                        # watches ES relocations
show_health                       # cluster's health stats
show_watermarks                   # show watermarks when storage marks readonly
show_state                        # shows the state of the indicies' shards (RELO, Translog, etc.)
showcfg_cluster                   # show all '_cluster/settings' configs
showcfg_num_shards_per_idx        # show number of shards configured per index template
showcfg_shard_allocations         # show cluster level shard allocation configs
explain_allocations               # show details (aka. explain) cluster allocation activity

#6-----------------------------------------------
# help funcs
##-----------------------------------------------
help_cat                          # print help for _cat API call
help_indices                      # print help for _cat/indices API call

#7-----------------------------------------------
# index funcs
##-----------------------------------------------
show_idx_sizes                    # show index sizes sorted (big -> small)
show_idx_stats                    # show index stats sorted (big -> small)
delete_idx                        # delete an index

#8-----------------------------------------------
# node funcs
##-----------------------------------------------
exclude_node_name                 # exclude a node from cluster (node suffix)
show_excluded_nodes               # show excluded nodes from cluster
clear_excluded_nodes              # clear any excluded cluster nodes


```

Each function includes a 'show usage' if you run it without any arguments. For example:
```
$ list_nodes

USAGE: list_nodes [l|p]

```

Most of the functions will take a single argument, either `l` or `p` to denote which cluster you want it to target. A handful of functions can take additional items, such as `relo_shard` & `delete_idx`. Consult their usage for more details.

### REFERENCES
* [Document APIs](https://www.elastic.co/guide/en/elasticsearch/reference/current/docs.html)
* [Cluster APIs](https://www.elastic.co/guide/en/elasticsearch/reference/current/cluster.html)
* [cat APIs](https://www.elastic.co/guide/en/elasticsearch/reference/current/cat.html)
* [hub, and extension to CLI git that helps with github](https://hub.github.com/)


