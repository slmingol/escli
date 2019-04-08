### BACKGROUND
This repo includes a CLI tool to simplify interacting with the Elasticsearch REST API. It makes a couple of assumptions:

- On OSX you have `greadlink` installed via `brew`
- Your credentials are store in LastPass
- You have the LastPass CLI tool install, `lpass` via `brew`

### STRUCTURE
There is 1 CLI tool `escli.bash` which is then linked as `esl` and `esp` to point to a 'lab' and 'production' instances of Elasticsearch clusters. 

The CLI tool `escli.bash` has a single configuration file, `escli.conf`.  Within the config file are the base URL for interacting with the 2 ES clusters, the "Content Type" header to use, and 2 commands for acquiring the username + password to use when interacting with the ES clusters.

The `es_funcs.bash` includes Bash functions which can be sourced into your shell and executed. These functions all leverage the base CLI tool, `escli.bash`.

Finally there's a file `cmds.md` which includes examples with output showcasing how to use the `escli.bash` CLI tool.

```
$ tree -I '*ARCHIVE*|*WIP*' -L 3
.
├── cmds.md
├── es_funcs.bash
├── escli.bash
├── escli.conf
├── esl -> escli.bash
└── esp -> escli.bash

0 directories, 6 files
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
delete_idx
estop
estop_recovery
explain_allocations
help_cat
help_indices
list_nodes
relo_shard
show_big_shards
show_health
show_idx_sizes
show_idx_stats
show_recovery
show_recovery_full
show_shards
show_small_shards
show_state
showcfg_num_shards_per_idx
unblock_readonly_idxs
usage_chk1
usage_chk2
usage_chk3
```

You can also get that list with a short description of each function:
```
$ escli_lsl
escli_ls                          # list function names
escli_lsl                         # list function names + desc.
list_nodes                        # list ES nodes along w/ a list of data node suffixes for use by other cmds.
show_shards                       # list all the index shards sorted by size (big->small)
show_big_shards                   # list top 20 shards for a given node's suffix (1a, 1b, etc.)
show_small_shards                 # list smallest 20 shards for a given node's suffix (1a, 1b, etc.)
relo_shard                        # move an indices' shard from node suffix X to node suffix Y
show_recovery                     # show a summary of recovery queue
show_recovery_full                # show full details of recovery queue
unblock_readonly_idxs             # clear read_only_allow_delete flag
estop                             # mimics `top` command, watching ES nodes CPU/MEM usage
estop_recovery                    # watches the ES recovery queue
show_health                       # cluster's health stats
show_state                        # shows the state of the indicies' shards (RELO, Translog, etc.)
showcfg_num_shards_per_idx        # show number of shards configured per index template
explain_allocations               # show details (aka. explain) cluster allocation activity
help_cat                          # print help for _cat API call
help_indices                      # print help for _cat/indices API call
show_idx_sizes                    # show index sizes sorted (big -> small)
show_idx_stats                    # show index stats sorted (big -> small)
delete_idx                        # delete an index
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


