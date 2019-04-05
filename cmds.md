### cat cmds
```
$ esp GET '_cat'
=^.^=
/_cat/allocation
/_cat/shards
/_cat/shards/{index}
/_cat/master
/_cat/nodes
/_cat/tasks
/_cat/indices
/_cat/indices/{index}
/_cat/segments
/_cat/segments/{index}
/_cat/count
/_cat/count/{index}
/_cat/recovery
/_cat/recovery/{index}
/_cat/health
/_cat/pending_tasks
/_cat/aliases
/_cat/aliases/{alias}
/_cat/thread_pool
/_cat/thread_pool/{thread_pools}
/_cat/plugins
/_cat/fielddata
/_cat/fielddata/{fields}
/_cat/nodeattrs
/_cat/repositories
/_cat/snapshots/{repository}
/_cat/templates
```

### index sizes
```
$ ./esl GET '_cat/indices?v&h=index,pri,rep,docs.count,store.aize,pri.store.size&human&s=store.size:desc&bytes=gb' | head
index                             pri rep docs.count pri.store.size
metricbeat-6.5.1-2019.01.15         5   1  706222100            270
metricbeat-6.5.1-2019.01.14         5   1  706442770            268
metricbeat-6.5.1-2019.01.13         5   1  705176649            266
metricbeat-6.5.1-2019.01.16         5   1  637363823            245
metricbeat-6.5.1-2019.01.12         5   1  624260901            235
metricbeat-6.5.1-2019.01.11         5   1  353330118            134
metricbeat-6.5.1-2019.01.17         5   1  337684266            130
filebeat-6.5.1-2019.01.14           1   1  363580899            120
filebeat-6.5.1-2019.01.13           1   1  351797610            115

$ ./esl GET '_cat/indices?v&h=index,pri,rep,docs.count,store.aize,pri.store.size&human&s=store.size:desc&bytes=gb' | head
index                             pri rep docs.count pri.store.size
filebeat-6.5.1-2019.03.11          10   1 2818415924            825
filebeat-6.5.1-2019.03.10          10   1 2123447523            693
filebeat-6.5.1-2019.03.12          10   1 1263342696            503
filebeat-6.5.1-2019.03.09          10   1 1054440130            448
filebeat-6.5.1-2019.03.13           1   1 1050395533            423
filebeat-6.5.1-2019.03.05          10   1 1387060633            349
filebeat-6.5.1-2019.03.08          10   1  882588962            337
filebeat-6.5.1-2019.03.14          10   1  588765423            277
filebeat-6.5.1-2019.03.15          10   1  518841198            246
```

### shard sizes
```
$ ./esp GET '_cat/shards?v&human&pretty&s=store:desc' | head
index                             shard prirep state         docs    store ip             node
filebeat-6.5.1-2019.03.07         1     p      STARTED 1139273422  264.1gb 192.168.33.197 rdu-es-data-01c
filebeat-6.5.1-2019.03.07         1     r      STARTED 1139273422  264.1gb 192.168.33.196 rdu-es-data-01b
filebeat-6.5.1-2019.03.07         0     r      STARTED 1139208231  264.1gb 192.168.7.85   rdu-es-data-01e
filebeat-6.5.1-2019.03.07         0     p      STARTED 1139208231  264.1gb 192.168.33.195 rdu-es-data-01a
filebeat-6.5.1-2019.03.06         1     p      STARTED  899910417    213gb 192.168.33.195 rdu-es-data-01a
filebeat-6.5.1-2019.03.06         1     r      STARTED  899910417  203.2gb 192.168.33.196 rdu-es-data-01b
filebeat-6.5.1-2019.03.06         0     p      STARTED  899997329  203.2gb 192.168.7.85   rdu-es-data-01e
filebeat-6.5.1-2019.03.06         0     r      STARTED  899997329    203gb 192.168.33.197 rdu-es-data-01c
filebeat-6.5.1-2019.03.05         1     r      STARTED  825585535  189.8gb 192.168.7.85   rdu-es-data-01e
```

```
$ ./esp GET '_cat/shards?v&human&pretty&s=store:desc' | grep -E "index|1e" | head
index                             shard prirep state         docs    store ip             node
filebeat-6.5.1-2019.03.07         0     r      STARTED 1139208231  264.1gb 192.168.7.85   rdu-es-data-01e
filebeat-6.5.1-2019.03.06         0     p      STARTED  899997329  203.2gb 192.168.7.85   rdu-es-data-01e
filebeat-6.5.1-2019.03.05         1     r      STARTED  825585535  189.8gb 192.168.7.85   rdu-es-data-01e
filebeat-6.5.1-2019.03.08         0     r      STARTED  664096376  155.2gb 192.168.7.85   rdu-es-data-01e
filebeat-6.5.1-2019.03.08         2     r      STARTED  664062615    153gb 192.168.7.85   rdu-es-data-01e
messaging-6.5.1-2019.03.19        1     r      STARTED  158253598   80.6gb 192.168.7.85   rdu-es-data-01e
messaging-6.5.1-2019.03.19        3     p      STARTED  158270912   80.6gb 192.168.7.85   rdu-es-data-01e
messaging-6.5.1-2019.03.18        1     r      STARTED  155686867   79.2gb 192.168.7.85   rdu-es-data-01e
messaging-6.5.1-2019.03.18        2     p      STARTED  155700930   79.2gb 192.168.7.85   rdu-es-data-01e
```

### delete index
```
$ ./esl DELETE 'packetbeat-6.5.1-2019.03.01'
{"acknowledged":true}
```

```
$ ./esl DELETE 'packetbeat-6.5.1-2019.03.*'
{"acknowledged":true}
```

### recovery queue (all)
```
$ ./esl GET '_cat/recovery?v' | head
index                             shard time  type           stage source_host    source_node     target_host    target_node     repository snapshot files files_recovered files_percent files_total bytes        bytes_recovered bytes_percent bytes_total  translog_ops translog_ops_recovered translog_ops_percent
filebeat-6.2.4-2019.01.10         0     189ms peer           done  192.168.33.196 rdu-es-data-01b 192.168.33.195 rdu-es-data-01a n/a        n/a      0     0               0.0%          0           0            0               0.0%          0            0            0                      100.0%
filebeat-6.2.4-2019.01.10         0     17.6s peer           done  192.168.33.195 rdu-es-data-01a 192.168.7.85   rdu-es-data-01e n/a        n/a      67    67              100.0%        67          308491198    308491198       100.0%        308491198    0            0                      100.0%
filebeat-6.2.4-2019.01.10         1     16.6s peer           done  192.168.33.197 rdu-es-data-01c 192.168.7.87   rdu-es-data-01d n/a        n/a      91    91              100.0%        91          308500864    308500864       100.0%        308500864    0            0                      100.0%
filebeat-6.2.4-2019.01.10         1     23.9s peer           done  192.168.7.87   rdu-es-data-01d 192.168.33.197 rdu-es-data-01c n/a        n/a      91    91              100.0%        91          308500865    308500865       100.0%        308500865    0            0                      100.0%
filebeat-6.2.4-2019.01.11         0     216ms peer           done  192.168.7.87   rdu-es-data-01d 192.168.7.85   rdu-es-data-01e n/a        n/a      0     0               0.0%          0           0            0               0.0%          0            0            0                      100.0%
filebeat-6.2.4-2019.01.11         0     2.9s  peer           done  192.168.33.195 rdu-es-data-01a 192.168.33.197 rdu-es-data-01c n/a        n/a      46    46              100.0%        46          64958531     64958531        100.0%        64958531     0            0                      100.0%
filebeat-6.2.3-2018.12.30         0     72ms  peer           done  192.168.33.197 rdu-es-data-01c 192.168.33.196 rdu-es-data-01b n/a        n/a      0     0               0.0%          0           0            0               0.0%          0            0            0                      100.0%
filebeat-6.2.3-2018.12.30         0     2.7s  peer           done  192.168.33.196 rdu-es-data-01b 192.168.7.85   rdu-es-data-01e n/a        n/a      58    58              100.0%        58          38663198     38663198        100.0%        38663198     0            0                      100.0%
filebeat-6.2.3-2018.12.31         0     4.4s  peer           done  192.168.33.195 rdu-es-data-01a 192.168.7.87   rdu-es-data-01d n/a        n/a      43    43              100.0%        43          40098269     40098269        100.0%        40098269     0            0                      100.0%
```

### recovery queue (outstanding)
```
$ ./esl GET '_cat/recovery?v' | grep -v done | head
index                             shard time  type           stage source_host    source_node     target_host    target_node     repository snapshot files files_recovered files_percent files_total bytes        bytes_recovered bytes_percent bytes_total  translog_ops translog_ops_recovered translog_ops_percent
```

### recovery queue (subset of columns)
```
$ esp GET '_cat/recovery?bytes=gb&v&h=index,shard,time,type,stage,source_node,target_node,files,files_recovered,files_percent,bytes_total,bytes_percent' | grep -v done | head
index                             shard time  type           stage source_node     target_node     files files_recovered files_percent bytes_total  bytes_percent
filebeat-6.5.1-2019.03.06         0     2.7h  peer           index rdu-es-data-01e rdu-es-data-01b 268   262             97.8%         218212992946 85.2%
filebeat-6.5.1-2019.03.06         1     2.7h  peer           index rdu-es-data-01a rdu-es-data-01e 277   276             99.6%         228721023484 98.6%
filebeat-6.5.1-2019.03.05         1     2.1h  peer           index rdu-es-data-01d rdu-es-data-01b 271   262             96.7%         203869559392 77.1%
```

### recovery queue (watch progress)
```
$ watch "esp GET '_cat/recovery?bytes=gb&v&h=index,shard,time,type,stage,source_node,target_node,files,files_recovered,files_percent,bytes_total,bytes_percent' | grep -v done | head"
...
...
Every 2.0s: esp GET '_cat/recovery?bytes=gb&v&h=index,shard,time,type,stage,source_node,target_node,files,files_recovered,files...  unagi: Wed Mar 20 23:20:58 2019

index                             shard time  type           stage source_node     target_node     files files_recovered files_percent bytes_total  bytes_percent
filebeat-6.5.1-2019.03.07         0     8.7m  peer           index rdu-es-data-01a rdu-es-data-01d 316   249             78.8%         283609355791 4.2%
filebeat-6.5.1-2019.03.07         1     8.7m  peer           index rdu-es-data-01c rdu-es-data-01a 316   257             81.3%         283627200658 5.6%
filebeat-6.5.1-2019.03.05         1     2.7h  peer           index rdu-es-data-01d rdu-es-data-01b 271   269             99.3%         203869559392 97.0%
syslog-2019.03.17                 0     10.8m peer           index rdu-es-data-01d rdu-es-data-01a 217   186             85.7%         60932598146  22.0%
```
### HDD usage by node
```
$ ./esl GET '_cat/allocation?v&pretty'
shards disk.indices disk.used disk.avail disk.total disk.percent host           ip             node
   241          3tb       3tb      2.7tb      5.8tb           52 192.168.33.197 192.168.33.197 rdu-es-data-01c
   242          3tb     3.1tb      2.7tb      5.8tb           53 192.168.33.195 192.168.33.195 rdu-es-data-01a
   242          3tb       3tb      2.7tb      5.8tb           52 192.168.33.196 192.168.33.196 rdu-es-data-01b
   242        2.9tb     2.9tb    512.5gb      3.4tb           85 192.168.7.87   192.168.7.87   rdu-es-data-01d
   241        2.8tb     2.8tb    622.3gb      3.4tb           82 192.168.7.85   192.168.7.85   rdu-es-data-01e
```

### Check on cluster allocations (healthy)
```
$ ./esl GET '_cluster/allocation/explain?pretty'
{
  "error" : {
    "root_cause" : [
      {
        "type" : "remote_transport_exception",
        "reason" : "[rdu-es-master-01c][192.168.33.212:9300][cluster:monitor/allocation/explain]"
      }
    ],
    "type" : "illegal_argument_exception",
    "reason" : "unable to find any unassigned shards to explain [ClusterAllocationExplainRequest[useAnyUnassignedShard=true,includeYesDecisions?=false]"
  },
  "status" : 400
}
```

### Index health and HDD usage (sorted by HDD use)
```
$ ./esl GET '_cat/indices?pretty&v&s=pri.store.size:desc' | head
health status index                             uuid                   pri rep docs.count docs.deleted store.size pri.store.size
green  open   metricbeat-6.5.1-2019.01.15       kfIOe-JsSrG148hUZru--g   5   1  706222100            0    540.2gb          270gb
green  open   metricbeat-6.5.1-2019.01.14       6iOWjV06Sou7YcfAvS5JYA   5   1  706442770            0    536.9gb        268.3gb
green  open   metricbeat-6.5.1-2019.01.13       Xw56kXYnTHizDadjhKTjtg   5   1  705176649            0    532.5gb        266.2gb
green  open   metricbeat-6.5.1-2019.01.16       jgziDwp7TbGEAnFVs7ELvg   5   1  637363823            0    490.8gb        245.4gb
green  open   metricbeat-6.5.1-2019.01.12       rkjvwhLGRs6Fvqh6NeQjbw   5   1  624260901            0    471.7gb        235.8gb
green  open   metricbeat-6.5.1-2019.01.11       lkh9KqDCSvCDjVOduNdv5w   5   1  353330118            0    269.5gb        134.7gb
green  open   metricbeat-6.5.1-2019.01.17       -9xe28dXQlWSuhMJcK4p_A   5   1  337684266            0    261.1gb        130.6gb
green  open   filebeat-6.5.1-2019.01.14         KQpNOoC2Q1u0kTlDFJr59w   1   1  363580899            0    240.4gb        120.2gb
green  open   filebeat-6.5.1-2019.01.13         6mWyr5tGTFW5InKGlyJ7IQ   1   1  351797610            0    230.7gb        115.3gb
```

### help
```
$ ./esl GET '_cat/indices?pretty&v&help' | head
health                           | h                              | current health status
status                           | s                              | open/close status
index                            | i,idx                          | index name
uuid                             | id,uuid                        | index uuid
pri                              | p,shards.primary,shardsPrimary | number of primary shards
rep                              | r,shards.replica,shardsReplica | number of replica shards
docs.count                       | dc,docsCount                   | available docs
docs.deleted                     | dd,docsDeleted                 | deleted docs
creation.date                    | cd                             | index creation date (millisecond value)
creation.date.string             | cds                            | index creation date (as string)
```


### Analyzing volume of logs from container
```
$ ( gtimeout -s 2 60 oc -n message-router logs message-router-stateful-set-0 -f 2>&1 | awk '{ print length($0); }' 2>&1 ) | distribution
Key|Ct   (Pct)    Histogram
 24|8191 (10.00%) --------------------------------------------------------------
 27|6825  (8.33%) ---------------------------------------------------
 31|5462  (6.67%) -----------------------------------------
 29|5460  (6.67%) -----------------------------------------
 26|2731  (3.33%) ---------------------
 41|2730  (3.33%) ---------------------
 35|2730  (3.33%) ---------------------
 34|2730  (3.33%) ---------------------
 33|2730  (3.33%) ---------------------
 25|2730  (3.33%) ---------------------
 23|2730  (3.33%) ---------------------
 19|2730  (3.33%) ---------------------
 67|1366  (1.67%) -----------
204|1366  (1.67%) -----------
174|1366  (1.67%) -----------
```
