#!/usr/bin/env bash

set -e
set -o errexit

[ "$(uname)" == 'Darwin' ] && readlink=greadlink || readlink=readlink
[ "$(uname)" == 'Darwin' ] && sedCmd=gsed        || sedCmd=sed

. $(dirname $($readlink -f $0))/es_funcs.bash


strings=(
    calc_date
    "calc_date '20 days ago'"
    "calc_date '20 days'"
    calc_hour
    "calc_hour '10 hours ago'"
    "calc_hour '10 hours'"
    calc_date_1daybefore
    "calc_date_1daybefore '2000-10-31'"
    calc_date_1dayafter
    "calc_date_1dayafter '2000-10-31'"
    calc_millis_date
    "calc_millis_date 1599861452868" 
    julian_day
    "julian_day 20201010"
    ceiling_divide
    "ceiling_divide 99 2"
    help_cat
    list_nodes
    "list_nodes l"
    list_nodes_storage
    "list_nodes_storage l"
    show_nodes_fs_details
    "show_nodes_fs_details l"
    show_nodes_circuit-breaker_summary
    "show_nodes_circuit-breaker_summary l"
    show_nodes_circuit-breaker_details
    "show_nodes_circuit-breaker_details l"
    show_shards
    "show_shards l"
    show_big_shards
    "show_big_shards l 1a"
    show_small_shards
    "show_small_shards l 1a"
    show_shard_usage_by_node
    "show_shard_usage_by_node l"
    relo_shard
    cancel_relo_shard
    cancel_relo_shards_all
    retry_unassigned_shards
    "show_balance_throttle l"
    increase_balance_throttle
    increase_balance_throttle_XXXmb
    reset_balance_throttle
    change_allocation_threshold
    show_recovery
    "show_recovery l"
    show_recovery_full
    "show_recovery_full l"
    enable_readonly_idx_pattern
    disable_readonly_idx_pattern
    enable_readonly_idxs
    disable_readonly_idxs
    show_readonly_idxs
    "show_readonly_idxs l"
    show_readonly_idxs_full
    "show_readonly_idxs_full l"
    clear_readonlyallowdel_idxs
    set_idx_default_field
    set_tmplate_default_field
    set_idx_num_replicas_to_X
    show_health
    "show_health l"
    show_watermarks
    "show_watermarks l"
    show_state
    "show_state l"
    showcfg_cluster
    "showcfg_cluster l"
    showrecov_stats
    "showrecov_stats l"
    shorecov_hot_threads
    "shorecov_hot_threads l"
    shorecov_idx_shard_stats
    "shorecov_idx_shard_stats l filebeat*$(calc_date '1 days ago')"
    show_stats_cluster
    "show_stats_cluster l"
    show_tasks_stats
    "show_tasks_stats l"
    verify_idx_retentions
    "verify_idx_retentions l"
    show_idx_retention_violations
    "show_idx_retention_violations l filebeat 30"
    show_idx_doc_sources_1st_10k
    "show_idx_doc_sources_1st_10k l filebeat*$(calc_date '1 days ago')"
    show_idx_doc_sources_all_cnts
    "show_idx_doc_sources_all_cnts l filebeat*$(calc_date '1 days ago')"
    show_idx_doc_sources_all_k8sns_cnts
    "show_idx_doc_sources_all_k8sns_cnts l filebeat*$(calc_date '1 days ago')"
    showcfg_num_shards_per_idx
    "showcfg_num_shards_per_idx l"
    showcfg_shard_allocations
    "showcfg_shard_allocations l"
    explain_allocations
    "explain_allocations l"
    explain_allocations_hddinfo
    "explain_allocations_hddinfo l"
    show_shard_routing_allocation
    "show_shard_routing_allocation l"
    enable_shard_allocations
    "enable_shard_allocations l"
    disable_shard_allocations
    clear_shard_allocations
    show_idx_sizes
    "show_idx_sizes l"
    show_idx_stats
    "show_idx_stats l"
    delete_idx
    showcfg_idx_cfgs
    "showcfg_idx_cfgs l"
    showcfg_idx_stats
    "showcfg_idx_stats l"
    show_idx_version_cnts
    "show_idx_version_cnts l"
    show_excluded_nodes
    "show_excluded_nodes l"
    exclude_node_name
    clear_excluded_nodes
    eswhoami
    showcfg_auth_roles
    "showcfg_auth_roles l"
    showcfg_auth_rolemappings
    "showcfg_auth_rolemappings l"
    list_auth_roles
    "list_auth_roles l"
    list_auth_rolemappings
    "list_auth_rolemappings l"
    evict_auth_cred_cache
    del_docs_k8s_ns_range
    forcemerge_to_expunge_deletes
    estail_deletebyquery
    estail_forcemerge
    list_templates
    "list_templates l"
    show_template
)

printf "\n\n"

for i in "${strings[@]}"; do
    cat <<-EOM
\`\`\`
####################################################################################################
    CMD: [$i]
####################################################################################################

OUTPUT
================================
$(printf "\n%s\n" "$(eval "$i" | cat | head -20 | sed 's/^/     /' | gsed 's/\x1b\[[0-9;]*m//g')")
================================


$(printf '*%.0s' {1..100})
$(printf '*%.0s' {1..100})

\`\`\`
	EOM

printf "\n"
printf -- '-%.0s' {1..100}
printf "\n\n"

done

