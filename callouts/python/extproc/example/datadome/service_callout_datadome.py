import requests
import logging
from grpc import ServicerContext
from envoy.service.ext_proc.v3 import external_processor_pb2 as service_pb2
from extproc.service import callout_server
from extproc.service import callout_tools
from envoy.config.core.v3.base_pb2 import HeaderValueOption
actions = HeaderValueOption.HeaderAppendAction

import threading
lock = threading.Lock()
datadome_cookie_dict = {}


# DataDome constants
datadome_server_side_key = "datadome_server_side_key"
datadome_endpoint = "https://api.datadome.co/validate-request/"
datadome_request_headers = {
"Content-Type": "application/x-www-form-urlencoded",
"User-Agent": "DataDome"
}

class CalloutServerExample(callout_server.CalloutServer):

#######################################################################################
# on_request_headers : before origin, we are able to mutate (only) the request headers
#######################################################################################
  def on_request_headers(
      self, headers: service_pb2.HttpHeaders,
      context: ServicerContext) -> service_pb2.ImmediateResponse | service_pb2.HeadersResponse:

    logging.debug("DataDome : on_request_headers")
    #######################
    # DataDome code example
    #######################

    http_headers = headers.headers.headers 
    http_headers_dic={}
    for header in http_headers:
      http_headers_dic[header.key] = header.raw_value.decode()

    logging.debug("DataDome : headers receives from LB %s", http_headers_dic)
    logging.debug("DataDome : cookie logging %s", http_headers_dic.get('cookie'))

    # DataDome clientID simple test: this is only to make sure this is working properly and we are only considering our cookie
    clientId = http_headers_dic.get('cookie')
    if clientId != None:
      clientId = clientId.replace('datadome=','')

    logging.debug("DataDome : clientID logging %s", clientId)

    # Context infomation being used : is this the good key?
    logging.debug(context.__str__)

    # Test values
    datadome_payload = {
        "Key": datadome_server_side_key,
        "Accept": http_headers_dic.get('accept'),
        "AcceptEncoding": "gzip, deflate, sdch",
        "AcceptLanguage": "fr-FR,fr;q=0.8,en-US;q=0.6,en;q=0.4",
        "APIConnectionState": "new",
        "Connection": "keep-alive",
        "ClientID": clientId,
        "HeadersList": "Host,Connection,Pragma,Cookie,Cache-Control,User-Agent",
        "Host": "localhost", # importart for the local tests: used to set the cookie domain, so seeting to localhost
        "IP": "62.35.12.13",
        "Method": "GET",
        "ModuleVersion": "1.0",
        "Port": 60200,
        "Pragma": "no-cache",
        "Protocol": "http",
        "Referer": "http://sub.domain.com/home.php",
        "Request": "/folder/file.php?param=value",
        "RequestModuleName": "service-callout",
        "ServerHostname": "localhost",
        "ServerName": "Lauro",
        "TimeRequest": 1494584456492817,
        "UserAgent": http_headers_dic.get('user-agent'),
        "XForwardedForIP": http_headers_dic.get('X-Forwarded-For') 
    }

    response = requests.post(datadome_endpoint, data=datadome_payload, headers=datadome_request_headers)
    logging.debug("Called DataDome: %s response", response.status_code)
    logging.debug("Response body: %s", response.text) 

    header_pairs_dic = {} 
    header_pairs_list = [] 
    for header_name, header_value in response.headers.items():
      header_pairs_dic[header_name] =  header_value
      header_pairs_list.append((header_name, header_value))
    
    logging.debug(header_pairs_dic)

    # Check DataDome response
    datadome_response_code = response.status_code

    if datadome_response_code in [200, 403, 401, 400]:
      if response.status_code in [403 , 401] :
        return callout_tools.datadome_immediate_response(
            code=403,
            body=response.text,
            headers=header_pairs_list)

      # TODO: 400 code with immediate_response

      if datadome_response_code == 200 :
        # add DataDome cookie to the dictionnary to be reused inside on_response_headers
        with lock:
          datadome_cookie_dict[context.__str__] = header_pairs_dic['Set-Cookie']

        return callout_tools.add_header_mutation(
        add=header_pairs_list,
        append_action=actions.OVERWRITE_IF_EXISTS_OR_ADD)
      
      logging.debug(response.text)
    else :
     logging.debug("DataDome: Unexpected return code")
    
    return service_pb2.HeadersResponse()


#######################################################################################
# on_response_headers : after origin, we are able to mutate (only) the response headers
#######################################################################################
  def on_response_headers(
      self, headers: service_pb2.HttpHeaders,
      context: ServicerContext) -> service_pb2.HeadersResponse:
    
    logging.debug("DataDome : on_response_headers")

    with lock:
      # TODO: use get to avoid exception when cookie not present
      datadome_cookie = datadome_cookie_dict[context.__str__]
    logging.debug("DataDome cookie %s",datadome_cookie)

    http_headers = headers.headers.headers 
    http_headers_dic={}
    for header in http_headers:
      http_headers_dic[header.key + '_raw'] = header.raw_value
      http_headers_dic[header.key] = header.raw_value.decode()

    logging.debug("DataDome : headers on_response_headers %s", http_headers_dic)
    logging.debug(context.__str__)

    return callout_tools.add_header_mutation(
        add=[('Set-Cookie', datadome_cookie)],
        append_action=actions.OVERWRITE_IF_EXISTS_OR_ADD)


if __name__ == '__main__':
  logging.basicConfig(level=logging.DEBUG)
  # Run the gRPC service
  CalloutServerExample().run()