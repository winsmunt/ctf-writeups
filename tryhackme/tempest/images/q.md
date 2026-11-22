Per the documentation, NETLOGON_CREDENTIAL can take 8 bytes of data,
the second bullet point outlines that "the data field carries 8 bytes
of encrypted data, as specified in the Netlogon Credential Computation",
fortunately we know this value, thanks to Zero Logon, it's 8 bytes of Zero. 
In terms of the Timestamp, it's a DWORD value, so it can either be a one or 
a zero. Zero sounds perfectly find to me.
