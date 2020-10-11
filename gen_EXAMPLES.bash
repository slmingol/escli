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
    help_indices
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
    show_nodes_threadpools_active_rejected
    "show_nodes_threadpools_active_rejected p"
    show_nodes_threadpools_details
    "show_nodes_threadpools_details p"
    show_nodes_threadpools_summary
    "show_nodes_threadpools_summary p"
    show_shards
    "show_shards l"
    show_big_shards
    "show_big_shards l 1a"
    show_small_shards
    "show_small_shards l 1a"
    show_hot_shards
    "show_hot_shards p 1a"
    show_shard_usage_by_node
    "show_shard_usage_by_node l"
    relo_shard
    cancel_relo_shard
    cancel_relo_shards_all
    retry_unassigned_shards
    show_shard_distribution_by_node_last3days
    "show_shard_distribution_by_node_last3days p"
    show_hot_idxs_shard_distribution_by_node
    "show_hot_idxs_shard_distribution_by_node p"
    show_shards_biggerthan50gb
    "show_shards_biggerthan50gb p"
    show_idx_with_oversized_shards_summary
    "show_idx_with_oversized_shards_summary p"
    show_idx_with_oversized_shards_details
    "show_idx_with_oversized_shards_details p"
    show_rebalance_throttle
    "show_rebalance_throttle p"
    show_node_concurrent_recoveries
    "show_node_concurrent_recoveries p"
    show_cluster_concurrent_rebalance
    "show_cluster_concurrent_rebalance p"
    increase_rebalance_throttle_XXXmb
    increase_node_concurrent_recoveries
    increase_cluster_concurrent_rebalance
    reset_balance_throttle
    reset_node_concurrent_recoveries
    reset_cluster_concurrent_rebalance
    change_allocation_threshold
    increase_node_recovery_allocations
    reset_node_recovery_allocations
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
    set_idx_shards_per_node
    set_idx_max_docvalue_fields_search
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
    show_idx_doc_sources_all_k8sns_cnts_hourly
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
    show_idx_create_timestamps_utc
    "show_idx_create_timestamps_utc p"
    show_idx_create_timestamps_localtz_last20
    "show_idx_create_timestamps_localtz_last20 p"
    show_idx_types
    "show_idx_types p"
    show_idx_last10
    "show_idx_last10 p"
    delete_idx
    showcfg_idx_cfgs
    "showcfg_idx_cfgs l"
    showcfg_idx_stats
    "showcfg_idx_stats l"
    show_idx_version_cnts
    "show_idx_version_cnts l"
    show_idx_mappings
    "show_idx_mappings p"
    clear_idx_cache_fielddata
    clear_idx_cache_query
    clear_idx_cache_request
    clear_idx_cache_all
    list_index_metric_types
    "list_index_metric_types p"
    show_field_capabilities
    "show_field_capabilities p filebeat-60d*"
    show_fields_multiple_defs_summary
    "show_fields_multiple_defs_summary p filebeat-60d*"
    show_field_X_multiple_defs_details
    "show_field_X_multiple_defs_details p filebeat-60d* logstash.slowlog.plugin_params"
    show_field_names
    "show_field_names p filebeat-60d* | head -50"
    show_field_counts
    "show_field_counts p filebeat-60d*"
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
    create_bearer_token
    del_docs_k8s_ns_range
    forcemerge_to_expunge_deletes
    estail_deletebyquery
    estail_forcemerge
    calc_total_docs_hdd_overXdays
    "calc_total_docs_hdd_overXdays p 30"
    calc_idx_type_avgs_overXdays
    "calc_idx_type_avgs_overXdays p 30"
    calc_num_nodes_overXdays
    "calc_num_nodes_overXdays p 30"
    list_ilm_policies
    "list_ilm_policies p"
    show_ilm_policy
    "show_ilm_policy p filebeat-30d"
    show_ilm_policies
    "show_ilm_policies p"
    list_aliases
    "list_aliases p"
    show_alias_details
    "show_alias_details p"
    show_alias_details_excludeEmpty
    "show_alias_details_excludeEmpty p"
    show_alias_for_idxs
    "show_alias_for_idxs p filebeat-60d"
    list_writable_ilm_idxs_on_alias
    "list_writable_ilm_idxs_on_alias p"
    show_writable_ilm_idxs_on_alias_details
    "show_writable_ilm_idxs_on_alias_details p"
    explain_indexes_ilm
    "explain_indexes_ilm p filebeat-60d-7.6.2*"
    show_ilm_components_for_idx
    "explain_indexes_ilm p filebeat-60d-7.6.2-2020.10.10-000110"
    bootstrap_ilm_idx
    trigger_ilm_rollover
    list_templates
    "list_templates l"
    show_template
    show_template_idx_patterns
    "show_template_idx_patterns p metricbeat*7.8.0*"
    show_template_ilm_idx_alias_details
    "show_template_ilm_idx_alias_details p metricbeat*7.8.0*"
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

