static void
evict_before_learning(struct mac_learning *ml)
    OVS_REQ_WRLOCK(ml->rwlock)
{
    const char *enabled = getenv("MAC_CONTROLLER");
    struct mac_entry *candidate,*other,*victim = NULL;
    size_t largest = 0;
    if(!enabled|| strcmp(enabled,"1")|| hmap_count(&ml->table) < ml->max_entries) {
        return;
    }
    LIST_FOR_EACH(candidate,lru_node,&ml->lrus) {
        size_t count = 0;
        if(!candidate->mlport|| candidate->expires == MAC_ENTRY_AGE_STATIC_ENTRY) {
            continue;
        }

        LIST_FOR_EACH(other,lru_node,&ml->lrus){
            if(other->mlport == candidate->mlport) {
                count++;
            }
        }

        if(count > largest) {
            largest = count;
            victim = candidate;
        }
    }
    if(victim) {
        fprintf(stderr,"MAC_CONTROLLER evict=" ETH_ADDR_FMT    " port_entries=%zu table_before=%zu\n",ETH_ADDR_ARGS(victim->mac),largest,hmap_count(&ml->table));
        COVERAGE_INC(mac_learning_evicted);
        ml->total_evicted++;
        mac_learning_expire(ml,victim);
    }
}
