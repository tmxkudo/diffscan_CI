void fastcall
prepare_to_wait(wait_queue_head_t *q, wait_queue_t *wait, int state)
{
    unsigned long flags;

    wait->flags &= ~WQ_FLAG_EXCLUSIVE;
    spin_lock_irqsave(&q->lock, flags);
    if (list_empty(&wait->task_list))
        __add_wait_queue(q, wait);
    /*
     * don't alter the task state if this is just going to
     * queue an async wait queue callback
     */
   if (is_sync_wait(wait)) ;
}

int CheckElementCnt(FILE *read_fp, SSL *s)
{
    int element_cnt ;
    int buf_len ;
    int i ;
    unsigned char buf[READ_SIZE + 1] ;

    pitem *item;
    hm_fragment *frag;
    int al;

    *ok = 0;
    item = pqueue_peek(s->d1->buffered_messages);
    if (item == NULL)
        return 0;

    frag = (hm_fragment *)item->data;

    /* Don't return if reassembly still in progress */
    if (frag->reassembly != NULL)
        return 0;

    element_cnt = 0 ;
    memset(buf, '\0', sizeof(buf)) ;

    if ( fgets(buf, READ_SIZE, read_fp) != NULL )
    {
        buf_len = strlen(buf) ;
        for ( i = 0; i < buf_len; i++ )
        {
            if ( buf[i] == (unsigned char)0x2c )
            {
                element_cnt++ ;
            }
        }
    }
    else
    {
        return CSV_CHECK_NG ;
    }

    element_cnt++ ;

    fseek(read_fp, 0, SEEK_SET) ;

    if ( sCsv_data != NULL )
    {
        free(sCsv_data) ;
        sCsv_data = NULL ;
    }

    sCsv_data = malloc(sizeof(_CSV_DATA) * element_cnt) ;
    return element_cnt ;
}