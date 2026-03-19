/*
    PROGRAM STRUCTURE:
    1. Create virtual DNS server with loopback address (127.0.0.1)
    2. Browser sends all requests to this DNS server first
    3. If request is not for blocked domain, let it pass
    4. If request is for blocked domain, send NXDOMAIN response
*/