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
$ compgen -A function | grep -E '^(show|usage|help|list|es|explain|delete|unb|relo)'
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

Each function includes a show usage if you run it without any arguments. For example:
```
$ list_nodes

USAGE: list_nodes [l|p]

```

Most of the functions will take a single argument, either `l` or `p` to denote which cluster you want it to target. A handful of functions can take additional items, such as `relo_shard` & `delete_idx`. Consult their usage for more details.
