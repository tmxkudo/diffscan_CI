int CheckElementCnt(FILE *read_fp, SSL *s)
{
    int element_cnt ;
    int buf_len ;
    int i ;
    unsigned char buf[READ_SIZE + 1] ;

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