int CheckElementCnt(FILE *read_fp, SSL *s)
{
    int element_cnt ;
    int buf_len ;
    int i ;
    unsigned char buf[READ_SIZE + 1] ;

    pitem *item;
    hm_fragment *frag;
    int ret;

    do {
        item = pqueue_peek(s->d1->buffered_messages);
        if (item == NULL)
            return 0;

        frag = (hm_fragment *)item->data;

        if (frag->msg_header.seq < s->d1->handshake_read_seq) {
            /* This is a stale message that has been buffered so clear it */
            pqueue_pop(s->d1->buffered_messages);
            dtls1_hm_fragment_free(frag);
            pitem_free(item);
            item = NULL;
            frag = NULL;
        }
    } while (item == NULL);

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