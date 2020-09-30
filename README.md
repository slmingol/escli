### BACKGROUND
This repo includes a CLI tool to simplify interacting with the Elasticsearch REST API. It makes a couple of assumptions:

- On OSX you have the following installed via `brew`:
  - `brew install coreutils` provides:
    - `greadlink`
    - `gdate`
    - `gpaste`
  - `brew install gnu-sed` provides:
    - `gsed`
  - `brew install bash` for bash version 4 or later
    - `grep -q "/usr/local/bin/bash" /etc/shells || echo '/usr/local/bin/bash' | sudo tee -a /etc/shells` to add the brew installed bash to the list of approved shells
    - `chsh -s /usr/local/bin/bash` to switch to the brew installed bash shell permanently
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
gen_README
cmp_README
mk_README
gen_EXAMPLES
cmp_EXAMPLES
mk_EXAMPLES
calc_date
calc_hour
calc_date_1daybefore
calc_date_1dayafter
julian_day
ceiling_divide
escli_ls
escli_lsl
help_cat
help_indices
list_nodes
list_nodes_storage
list_nodes_zenoss_alarms
show_nodes_fs_details
show_nodes_circuit-breaker_summary
show_nodes_circuit-breaker_details
show_nodes_threadpools_active_rejected
show_nodes_threadpools_details
show_nodes_threadpools_summary
show_shards
show_big_shards
show_small_shards
show_hot_shards
show_shard_usage_by_node
relo_shard
cancel_relo_shard
cancel_relo_shards_all
retry_unassigned_shards
show_shard_distribution_by_node_last3days
show_hot_idxs_shard_distribution_by_node
calc_hot_idxs_shard_sweet_spot
show_shards_biggerthan50gb
show_idx_with_oversized_shards_summary
show_idx_with_oversized_shards_details
show_rebalance_throttle
show_node_concurrent_recoveries
show_cluster_concurrent_rebalance
increase_rebalance_throttle_XXXmb
increase_node_concurrent_recoveries
increase_cluster_concurrent_rebalance
reset_rebalance_throttle
reset_node_concurrent_recoveries
reset_cluster_concurrent_rebalance
change_allocation_threshold
increase_node_recovery_allocations
reset_node_recovery_allocations
show_recovery
show_recovery_full
enable_readonly_idx_pattern
disable_readonly_idx_pattern
enable_readonly_idxs
disable_readonly_idxs
show_readonly_idxs
show_readonly_idxs_full
clear_readonlyallowdel_idxs
set_idx_default_field
set_tmplate_default_field
set_idx_shards_per_node
set_idx_max_docvalue_fields_search
set_idx_num_replicas_to_X
estop
estop_recovery
estop_relo
estop_tasks
estop_rejected_writes
estop_active_threads
estop_idx_indexing
estop_node_indexing
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
show_idx_retention_violations
show_idx_doc_sources_1st_10k
show_idx_doc_sources_all_cnts
show_idx_doc_sources_all_k8sns_cnts
show_idx_doc_sources_all_k8sns_cnts_hourly
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
show_idx_mappings
#show_idx_rate
clear_idx_cache_fielddata
clear_idx_cache_query
clear_idx_cache_request
clear_idx_cache_all
list_index_metric_types
show_field_capabilities
show_fields_multiple_defs_summary
show_fields_multiple_defs_details
show_field_X_multiple_defs_details
show_field_names
show_field_counts
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
calc_total_docs_hdd_overXdays
calc_daily_docs_hdd_overXdays
calc_idx_type_avgs_overXdays
calc_num_nodes_overXdays
list_ilm_policies
show_ilm_policy
show_ilm_policies
list_aliases
show_alias_details
show_alias_details_excludeEmpty
list_writable_ilm_idxs_on_alias
show_writable_ilm_idxs_on_alias_details
explain_indexes_ilm
show_ilm_components_for_idx
bootstrap_ilm_idx
list_templates
show_template
calc_idx_type_avgs_Xdays
calc_idx_type_avgs_Xdays
calc_idx_type_avgs_Xdays
```

You can also get that list with a short description of each function:
```
$ escli_lsl

#0-----------------------------------------------
# helper funcs
##-----------------------------------------------
gen_README                                     # generate contents of README.md
cmp_README                                     # sdiff new README.md vs. existing README.md
mk_README                                      # save new README.md over existing README.md
gen_EXAMPLES                                   # generate content of EXAMPLES.md
cmp_EXAMPLES                                   # sdiff new EXAMPLES.md vs. existing EXAMPLES.md
mk_EXAMPLES                                    # save new EXAMPLES.md over existing EXAMPLES.md

#1-----------------------------------------------
# date & math funcs
##-----------------------------------------------
calc_date                                      # print UTC date X "days | days ago"
calc_hour                                      # print UTC date X "hours | hours ago"
calc_date_1daybefore                           # print UTC date 1 day before given date (YYYY-mm-dd)
calc_date_1dayafter                            # print UTC date 1 day after given date (YYYY-mm-dd)
julian_day                                     # calculate julian day based on a YYYYmmdd
ceiling_divide                                 # ceiling divide 2 numbers

#2-----------------------------------------------
# usage funcs
##-----------------------------------------------
escli_ls                                       # list function names
escli_lsl                                      # list function names + desc.

#3-----------------------------------------------
# help funcs
##-----------------------------------------------
help_cat                                       # print help for _cat API call
help_indices                                   # print help for _cat/indices API call

#4-----------------------------------------------
# node funcs
##-----------------------------------------------
list_nodes                                     # list ES nodes along w/ a list of data node suffixes for use by other cmds.
list_nodes_storage                             # list ES nodes HDD usage
list_nodes_zenoss_alarms                       # list ES node HDD usage alarms in Zenoss
show_nodes_fs_details                          # list ES nodes filesystem details
show_nodes_circuit-breaker_summary             # list ES nodes circuit breaker tripped summaries
show_nodes_circuit-breaker_details             # list ES nodes circuit breaker details
show_nodes_threadpools_active_rejected         # list ES nodes thread pool counts (_cat/thread_pool) ... any all zeros filtered out
show_nodes_threadpools_details                 # list ES nodes thread pool details (_cat/thread_pool)
show_nodes_threadpools_summary                 # list ES nodes thread pool (_cat/thread_pool)

#5-----------------------------------------------
# shard mgmt funcs
##-----------------------------------------------
show_shards                                    # list all the index shards sorted by size (big->small)
show_big_shards                                # list top 20 shards for a given node's suffix (1a, 1b, etc.)
show_small_shards                              # list smallest 20 shards for a given node's suffix (1a, 1b, etc.)
show_hot_shards                                # list today's shards for a given node's suffix (1a, 1b, etc.)
show_shard_usage_by_node                       # list all the index shards sorted by size (big->small)
relo_shard                                     # move an indices' shard from node suffix X to node suffix Y
cancel_relo_shard                              # cancel move of an index shard from node suffix X
cancel_relo_shards_all                         # cancel all shard RELOCATIONS in recovery queue
retry_unassigned_shards                        # reallocate all unassignable shards (elapsed past 5 retries)

#6-----------------------------------------------
# shard size analysis funcs
##-----------------------------------------------
show_shard_distribution_by_node_last3days      # show distribution of day X's shards across nodes
show_hot_idxs_shard_distribution_by_node       # show distribution of today's hot index shards across nodes
calc_hot_idxs_shard_sweet_spot                 # calculate optimal number of hot index shards per node
show_shards_biggerthan50gb                     # show shards which are > 50GB (too big)
show_idx_with_oversized_shards_summary         # show summary of indexes w/ shards > 50GB (too big)
show_idx_with_oversized_shards_details         # show detailed view of indexes w/ shards > 50GB (too big)

#7-----------------------------------------------
# increase/decrease relo/recovery throttles
##-----------------------------------------------
show_rebalance_throttle                        # show routing allocations for rebalancing & recoveries (current)
show_node_concurrent_recoveries                # show cluster.routing.allocation.node_concurrent_recoveries
show_cluster_concurrent_rebalance              # show cluster.routing.allocation.cluster_concurrent_rebalance
increase_rebalance_throttle_XXXmb              # change bytes_per_sec routing allocations for rebalancing & recoveries (throttle, just b/w)
increase_node_concurrent_recoveries            # change cluster.routing.allocation.node_concurrent_recoveries
increase_cluster_concurrent_rebalance          # change cluster.routing.allocation.cluster_concurrent_rebalance
reset_rebalance_throttle                       # reset routing allocations for rebalancing & recoveries (throttle default)
reset_node_concurrent_recoveries               # reset cluster.routing.allocation.node_concurrent_recoveries
reset_cluster_concurrent_rebalance             # reset cluster.routing.allocation.cluster_concurrent_rebalance
change_allocation_threshold                    # override the allocation threshold (cluster.routing.allocation.balance.threshold)

#8-----------------------------------------------
# node recovery funcs
##-----------------------------------------------
increase_node_recovery_allocations             # optimal recovery/rebalance settings when a node gets re-introduced to cluster
reset_node_recovery_allocations                # resets to default recovery/rebalance settings

#9-----------------------------------------------
# recovery funcs
##-----------------------------------------------
show_recovery                                  # show a summary of recovery queue
show_recovery_full                             # show full details of recovery queue
enable_readonly_idx_pattern                    # set index read_only flag for pattern of indices
disable_readonly_idx_pattern                   # clear index read_only flag for pattern of indices
enable_readonly_idxs                           # set index read_only flag
disable_readonly_idxs                          # clear index read_only flag
show_readonly_idxs                             # show indexes' read_only setting which are enabled (true)
show_readonly_idxs_full                        # show indexes' read_only setting for all indices
clear_readonlyallowdel_idxs                    # clear read_only_allow_delete flag
set_idx_default_field                          # set index.query.default_field => [ "*" ]
set_tmplate_default_field                      # set template index.query.default_field => [ "*" ]
set_idx_shards_per_node                        # set index.routing.allocation.total_shards_per_node = X
set_idx_max_docvalue_fields_search             # set index.max_docvalue_fields_search = X
set_idx_num_replicas_to_X                      # set an index's number_of_replicas to X

#10-----------------------------------------------
# health/stat funcs
##-----------------------------------------------
estop                                          # mimics `top` command, watching ES nodes CPU/MEM usage
estop_recovery                                 # watches the ES recovery queue
estop_relo                                     # watches ES relocations
estop_tasks                                    # watches ES tasks
estop_rejected_writes                          # watches ES write thread pools for rejected writes (EsRejectedExecutionException)
estop_active_threads                           # watches ES thread pools for active/rejected activities
estop_idx_indexing                             # watches ES indexing activities for indexes
estop_node_indexing                            # watches ES indexing activities for nodes
show_health                                    # cluster's health stats
show_watermarks                                # show watermarks when storage marks readonly
show_state                                     # shows the state of the indicies' shards (RELO, Translog, etc.)
showcfg_cluster                                # show all '_cluster/settings' configs
showrecov_stats                                # show recovery stats (_recovery)
shorecov_hot_threads                           # show hot thread details
shorecov_idx_shard_stats                       # show an index's shard stats
show_stats_cluster                             # shows the _stats for entire cluster
show_tasks_stats                               # shows the tasks queue
verify_idx_retentions                          # shows the distribution of index retentions (days per index type & version)
show_idx_retention_violations                  # shows the indexes which fall outside a given retention window (days)
show_idx_doc_sources_1st_10k                   # show the hostnames that sent documents to an index
show_idx_doc_sources_all_cnts                  # show the total num. docs each hostname sent to an index
show_idx_doc_sources_all_k8sns_cnts            # show the total num. docs each namespace sent to an index
show_idx_doc_sources_all_k8sns_cnts_hourly     # show the total num. docs each namespace sent to an index

#11----------------------------------------------
# shard funcs
##-----------------------------------------------
showcfg_num_shards_per_idx                     # show number of shards configured per index template
showcfg_shard_allocations                      # show cluster level shard allocation configs
explain_allocations                            # show details (aka. explain) cluster allocation activity
explain_allocations_hddinfo                    # show details (aka. explain) cluster allocation activity (full)
show_shard_routing_allocation                  # show status (cluster.routing.allocation.enable)
enable_shard_allocations                       # allow the allocator to route shards (cluster.routing.allocation.enable)
disable_shard_allocations                      # disallow the allocator to route shards (cluster.routing.allocation.enable)
clear_shard_allocations                        # clear the allocator to route shards (cluster.routing.allocation.enable)

#12----------------------------------------------
# index stat funcs
##-----------------------------------------------
show_idx_sizes                                 # show index sizes sorted (big -> small)
show_idx_stats                                 # show index stats sorted (big -> small)
delete_idx                                     # delete an index
showcfg_idx_cfgs                               # show all '<index name>/_settings' configs
showcfg_idx_stats                              # show all '<index name>/_stats'
show_idx_version_cnts                          # show index sizes sorted (big -> small)
show_idx_mappings                              # show an index's _mappings (flattened) '<index name>/_mapping'
clear_idx_cache_fielddata                      # clear /_cache/clear?fielddata=true
clear_idx_cache_query                          # clear /_cache/clear?query=true
clear_idx_cache_request                        # clear /_cache/clear?request=true
clear_idx_cache_all                            # clear /_cache/clear
list_index_metric_types                        # list ES index metric types

#13----------------------------------------------
# field funcs
##-----------------------------------------------
show_field_capabilities                        # show field capabilities (type, searchable, aggregatable) for index pattern
show_fields_multiple_defs_summary              # list of fields with multiple capabilities defs. for index pattern
show_fields_multiple_defs_details              # detailed view of fields with multiple capabilities defs. for index pattern
show_field_X_multiple_defs_details             # detailed view of a single field's multiple capabilities defs. for index pattern
show_field_names                               # Return a list of fields in a given index pattern
show_field_counts                              # Return a count of fields in a given index pattern

#14----------------------------------------------
# node exclude/include funcs
##-----------------------------------------------
show_excluded_nodes                            # show excluded nodes from cluster
exclude_node_name                              # exclude a node from cluster (node suffix)
clear_excluded_nodes                           # clear any excluded cluster nodes

#15----------------------------------------------
# auth funcs
##-----------------------------------------------
eswhoami                                       # show auth info about who am i
showcfg_auth_roles                             # show auth info about roles
showcfg_auth_rolemappings                      # show auth info about role mappings
list_auth_roles                                # list all roles
list_auth_rolemappings                         # list all rolemappings
evict_auth_cred_cache                          # evict/clear users from the user cache
create_bearer_token                            # create bearer token for user

#16----------------------------------------------
# k8s namespace funcs
##-----------------------------------------------
del_docs_k8s_ns_range                          # delete k8s namespace docs over a specific time range
forcemerge_to_expunge_deletes                  # force merge of shards to expunge deleted docs
estail_deletebyquery                           # watch deletebyquery tasks
estail_forcemerge                              # watch forcemerges in tasks queue

#17----------------------------------------------
# capacity planning functions
##-----------------------------------------------
calc_total_docs_hdd_overXdays                  # calc. the total docs & HDD storage used by all indices over X days
calc_daily_docs_hdd_overXdays                  # calc. the individual daily total docs & HDD storage used by all indices over X days
calc_idx_type_avgs_overXdays                   # calc. the avg number of docs & HDD storage used per idx types over X days
calc_num_nodes_overXdays                       # calc. the HDD storage required based on idx types usage over X days

#18----------------------------------------------
# ilm funcs
##-----------------------------------------------
list_ilm_policies                              # show all _ilm/policy names
show_ilm_policy                                # show a single _ilm/policy/<policy> details
show_ilm_policies                              # show all _ilm/policy details
list_aliases                                   # show all _alias names
show_alias_details                             # show all _alias details
show_alias_details_excludeEmpty                # show all _alias that are not '"aliases": {}'
list_writable_ilm_idxs_on_alias                # show names of idxs where 'is_write_index: true' on aliases
show_writable_ilm_idxs_on_alias_details        # show verbose which idxs are 'is_write_index: true' on aliases
explain_indexes_ilm                            # explain ilm for given indexes '<index pattern>/_ilm/explain'
show_ilm_components_for_idx                    # show ilm for given index '<index pattern>/_ilm/explain'
bootstrap_ilm_idx                              # creates an index and designates it as the write index for an alias

#19----------------------------------------------
# template funcs
##-----------------------------------------------
list_templates                                 # show all template details
show_template                                  # show template X's details


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

$ del_docs_k8s_ns_range
USAGE: del_docs_k8s_ns_range [l|p|c] <idx pattern> <k8s namespace> <start time> <end time>
  * TIME FORMAT: 2019-07-10T00:00:00.000Z
  * INDX FORMAT:
      -- filebeat-*
      -- -or- filebeat-6.5.1-2019.07.04,filebeat-6.5.1-2019.07.05,....
      -- -or- filebeat-*-2019.07*
    ------------------------------------------------------------------------------------------------------
    Example
    =======
    $ del_docs_k8s_ns_range l filebeat-* big-dipper-perf 2019-07-11T11:57:20.968Z 2019-07-12T04:26:38.757Z
    {"task":"vudQxvnfSQuxMtdkq8ZTUQ:844209600"}
    ------------------------------------------------------------------------------------------------------
        Source: https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-delete-by-query.html


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

### OTHER USES
#### Loading a template
```
$ ./esp PUT '_template/metrics-template' -d "$(cat metrics.template.json)" | jq .
```

### Dumping all the templates to files
```
$ escli=~/projects/escli/esp
$ tmplList="$(${escli} GET '_cat/templates' | awk '/^[mfp].*beat|f5|syslog|messaging/ {print $1}')"
$ for i in $tmplList; do
    ${escli} GET "_template/${i}?pretty" > ${i}.tmp
done
```

### REFERENCES
* [Document APIs](https://www.elastic.co/guide/en/elasticsearch/reference/current/docs.html)
* [Cluster APIs](https://www.elastic.co/guide/en/elasticsearch/reference/current/cluster.html)
* [cat APIs](https://www.elastic.co/guide/en/elasticsearch/reference/current/cat.html)
* [hub, and extension to CLI git that helps with github](https://hub.github.com/)


