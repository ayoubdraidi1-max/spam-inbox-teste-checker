import imaplib
import ssl

def check_sizes():
    email = "ardagulerozil44@gmail.com"
    pw = "jwwf uxls qqth ytpk"
    server = "imap.gmail.com"
    
    ctx = ssl.create_default_context()
    mail = imaplib.IMAP4_SSL(server, 993, ssl_context=ctx)
    mail.login(email, pw)
    mail.select("INBOX")
    
    status, data = mail.uid("search", None, "ALL")
    uids = data[0].split()
    last_uid = uids[-1].decode()
    
    print(f"Checking UID {last_uid} structure...")
    status, data = mail.uid("FETCH", last_uid, "(BODYSTRUCTURE)")
    print(f"Structure: {data[0]}")
    
    # Check sizes of parts
    status, data = mail.uid("FETCH", last_uid, "(RFC822.SIZE BODY.PEEK[1].SIZE BODY.PEEK[TEXT].SIZE)")
    print(f"Sizes: {data[0]}")
    
    mail.logout()

if __name__ == "__main__":
    check_sizes()
