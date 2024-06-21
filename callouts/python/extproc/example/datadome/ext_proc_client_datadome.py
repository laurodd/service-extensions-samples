# Copyright 2024 Google LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import logging
from typing import Iterator
import grpc
from google.protobuf.json_format import Parse
from envoy.service.ext_proc.v3.external_processor_pb2 import (
  ProcessingRequest,
  ProcessingResponse,
)
from extproc.tests.basic_grpc_test import _addr_to_str
from extproc.service.callout_tools import _addr
from envoy.service.ext_proc.v3.external_processor_pb2_grpc import (
  ExternalProcessorStub,
)
from envoy.service.ext_proc.v3 import external_processor_pb2 as service_pb2
from envoy.config.core.v3.base_pb2 import HeaderMap
from envoy.config.core.v3.base_pb2 import HeaderValue
import json

class NoResponseError(Exception):
  pass

# Defining the headers here to test the gRPC call below
json_string = '''
[
    {"key": "user-agent", "value": "CI-Allowed"},
    {"key": "authorization", "value": "Bearer token"}
]
'''

def make_request(stub: ExternalProcessorStub, **kwargs) -> ProcessingResponse:
  request_iter = iter([ProcessingRequest(**kwargs)])
  responses = stub.Process(request_iter)
  # Get the first response
  for response in responses:
    return response
  raise NoResponseError("Response not found.")


def _make_channel(
  address: tuple[str, int], key: str | None = None
) -> grpc.Channel:
  addr_str = _addr_to_str(address)
  if key:
    with open(key, 'rb') as file:
      creds = grpc.ssl_channel_credentials(file.read())
      return grpc.secure_channel(addr_str, creds)
  else:
    return grpc.insecure_channel(addr_str)


def add_headers_from_json(json_string, header_map):
    headers = json.loads(json_string)
    for header in headers:
      header_map.headers.extend([HeaderValue(key=header['key'], value=header['value'])])


def datadome_call_test(address: tuple[str, int], key: str | None = None) -> None:
  with _make_channel(address, key) as channel:
    stub = ExternalProcessorStub(channel)

    # Construct the HeaderMap
    header_map = HeaderMap()
    add_headers_from_json(json_string,header_map)

    # Construct HttpHeaders with the HeaderMap
    headers = service_pb2.HttpHeaders(headers=header_map, end_of_stream=True)
    
    # This is going to be a list on the server
    response = make_request(stub, request_headers=headers)
    logging.info(response)


if __name__ == '__main__':
  # Set the debug level.
  logging.basicConfig(level=logging.DEBUG)

  # address of the gRPC server running
  datadome_call_test(address=("127.0.0.1",8080))  

