#!/usr/bin/env python

"""
    secure_proxy_client.py:
    Client application that can be used to test the ec2-imagebuilder-secure-proxy project.

    The client code can execute the following 4 test scenarios:

    1. Retrieve an oAuth configuration via the EC2 Secure Proxy instance.
    2. Retrieve an oAuth token via the EC2 Secure Proxy instance.
    3. Establish a Secure Web Socket connection (containing a valid JWT token) with the 
       EC2 Secure Proxy instance. Send and receive data along this connection. 
       This test scenario validates that:
        1. the client provided a valid JWT token.
        2. the client is sending and receiving data over a Secure Web Socket connection.
        3. the EC2 Secure Proxy instance is performing `wss://` → `tcp://`, `tcp://` → `wss://` protocol conversion.
        4. the TCP socket application is receiving data as standard TCP traffic.
    4. Attempt to establish a Secure Web Socket connection (containing an *invalid* JWT token) with the 
       EC2 Secure Proxy instance. The expected outcome is a Http Code 403 Forbidden error.
"""

import argparse
import json
import os
import random
import ssl
import string
import traceback

import requests
import websocket
from colorama import Fore

SSL_CLIENT_CERT_PATH = os.getenv("SSL_CLIENT_CERT_PATH", False)


def get_project_settings() -> dict:
    filename = "cdk.json"
    with open(filename, 'r') as cdk_json:
        data = cdk_json.read()
    return json.loads(data).get("projectSettings")


def generate_random_string(length: int) -> str:
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))


def generate_random_int(limit: int) -> int:
    return random.randint(0, limit)


class OAuthClient:
    """
        Class that can connect to an OAuth server and obtain a JWT token.
    """

    def __init__(self, url: str, port: int):
        base_url = f"https://{url}:{port}"
        self.config_url = f"{base_url}/configuration"
        self.authorize_url = f"{base_url}/authorize"
        self.token_url = f"{base_url}/token"
        self.callback_uri = "http://some-callback-url.com"


    def get_oauth_configuration(self) -> requests.Response:
        try:
            return requests.get(
                self.config_url, 
                verify=SSL_CLIENT_CERT_PATH,
                allow_redirects=False
            )
        except:
            traceback.print_exc()
            return None


    def get_jwt_token(self) -> str:
        authorization_code = generate_random_string(15)
        client_id = f"{generate_random_string(10)}@awsexample.com"
        client_secret = generate_random_string(20)
        data = {
            'grant_type': 'authorization_code', 
            'code': authorization_code, 
            'redirect_uri': self.callback_uri
        }
        try:
            access_token_response = requests.post(
                self.token_url, 
                data=data,
                verify=SSL_CLIENT_CERT_PATH,
                allow_redirects=False, 
                auth=(client_id, client_secret)
            )
            tokens = json.loads(access_token_response.text)
            access_token = tokens['access_token']
            return access_token
        except:
            traceback.print_exc()
            return None


class SecureProxyClient:
    """
        Class that establishes a Secure Web Socket connection and can
        send and receive binary data over the secure socket channel.
    """

    def __init__(self, address: str, wss_port: int, jwt_token: str):
        self.url = f"wss://{address}:{wss_port}"
        self.jwt_token = jwt_token


    def create_connection(self) -> websocket.WebSocket:
        header={
            'User-Agent': "Mozilla/5.0 (Macintosh; Intel Mac OS X x.y; rv:42.0) Gecko/20100101 Firefox/43.4",
            'Accept': '/',
            'Accept-Language': "en-US,en;q=0.5",
            'Pragma': 'no-cache',
            'Cache-Control': 'no-cache',
            'Authorization': f"Bearer {self.jwt_token}",
            'Sec-WebSocket-Key': 'n2wfgJF+qto2ahU4+aoNkQ==',
            'Sec-WebSocket-Protocol': 'binary',
            'Sec-WebSocket-Version': '13',
            'Upgrade': 'websocket'
        }
        ws = websocket.create_connection(
            self.url,
            sslopt={"cert_reqs": ssl.CERT_NONE,
                    "check_hostname": False
            },
            header=header
        )
        return ws


    def send_binary_message(self, ws: websocket.WebSocket, message: str) -> None:
        print("Sending" + Fore.YELLOW + f" {message}" + Fore.WHITE + " to TCP application over WSS connection")
        NEW_LINE_CHAR = "\n"
        payload_with_newline = message + NEW_LINE_CHAR
        bytearray(payload_with_newline.encode())
        ws.send_binary(payload_with_newline)
        bin_answer = ws.recv_frame()
        print("----BINARY RESPONSE CODE---")
        print(Fore.GREEN + websocket.ABNF.OPCODE_MAP[bin_answer.opcode] + Fore.WHITE)
        print("----BINARY RESPONSE DATA---")
        response = bytearray(bin_answer.data).decode()
        print("Received response from TCP application over WSS connection:" + Fore.GREEN + f" {response}" + Fore.WHITE)


    def close_connection(self, ws: websocket.WebSocket) -> None:
        ws.close()


class SecureProxyTestScenarios:
    """
        Class that can execute the following 4 test scenarios:

        1. Retrieve an oAuth configuration via the EC2 Secure Proxy instance.
        2. Retrieve an oAuth token via the EC2 Secure Proxy instance.
        3. Establish a Secure Web Socket connection (containing a valid JWT token) with the 
        EC2 Secure Proxy instance. Send and receive data along this connection. 
        This test scenario validates that:
            1. the client provided a valid JWT token.
            2. the client is sending and receiving data over a Secure Web Socket connection.
            3. the EC2 Secure Proxy instance is performing `wss://` → `tcp://`, `tcp://` → `wss://` protocol conversion.
            4. the TCP socket application is receiving data as standard TCP traffic.
        4. Attempt to establish a Secure Web Socket connection (containing an *invalid* JWT token) with the 
        EC2 Secure Proxy instance. The expected outcome is a Http Code 403 Forbidden error.
    """

    def __init__(self, address: str, wss_port: int, https_port: int):
        self.address = address
        self.wss_port = wss_port
        self.https_port = https_port


    def print_scenario_header(self, scenario_num: int, scenario_desc: str) -> None:
        print(Fore.WHITE + "######################################" + Fore.WHITE)
        print(Fore.BLUE + f"<START> SCENARIO_{scenario_num}"  + Fore.WHITE + f" {scenario_desc}" + Fore.WHITE)
        print(Fore.WHITE + "######################################" + Fore.WHITE)
        print("")


    def print_scenario_footer(self, scenario_num: int, scenario_desc: str) -> None:
        print("")
        print(Fore.WHITE + "######################################" + Fore.WHITE)
        print(Fore.BLUE + f"</END> SCENARIO_{scenario_num}"  + Fore.WHITE + f" {scenario_desc}" + Fore.WHITE)
        print(Fore.WHITE + "######################################" + Fore.WHITE)
        print("")


    def get_auth_config(self) -> None:
        self.print_scenario_header("01", f" Retrieve oAuth configuration from https://{self.address}:{self.https_port}/configuration.")
        response = OAuthClient(url=self.address, port=self.https_port).get_oauth_configuration()
        if response is not None:
            print(Fore.GREEN + "SUCCESS:" + Fore.WHITE + f" Displaying the oAuth configuration." + Fore.WHITE)
            print(response)
            print(json.dumps(response.json(), indent=4, sort_keys=True))
            self.print_scenario_footer("01", f" Retrieved oAuth configuration from https://{self.address}:{self.https_port}/configuration.")
        else:
            print(Fore.RED + "FAILURE:"  + Fore.WHITE + f" Unable to retrieve oAuth configuration from https://{self.address}:{self.https_port}/configuration." + Fore.WHITE)


    def get_jwt_token(self) -> None:
        self.print_scenario_header("02", "Obtain oAuth token.")
        response = OAuthClient(url=self.address, port=self.https_port).get_jwt_token()
        if response is not None:
            print(Fore.GREEN + "SUCCESS:" + Fore.WHITE + " Displaying the oAuth token." + Fore.WHITE)
            print(response)
            self.print_scenario_footer("02", "Obtained oAuth token.")
        else:
            print(Fore.RED + "FAILURE:"  + Fore.WHITE + " Unable to retrieve oAuth token." + Fore.WHITE)


    def send_web_socket_data(self) -> None:
        self.print_scenario_header("03", f" Sending websocket data to TCP application at wss://{self.address}:{self.wss_port}.")
        messages = ["world!", "mundo!", "monde!", "mondo!", "welt!"]
        access_token = OAuthClient(url=self.address, port=self.https_port).get_jwt_token()
        secure_proxy_client = SecureProxyClient(
            address=self.address,
            wss_port=self.wss_port,
            jwt_token=access_token
        )
        try:
            # establish wss connection
            ws_connection = secure_proxy_client.create_connection()
            if ws_connection is None:
                print(Fore.RED + "FAILURE:"  + Fore.WHITE + f" Unable to send websocket data to TCP application at wss://{self.address}:{self.wss_port}." + Fore.WHITE)
                return
            # send wss messages
            for message in messages:
                secure_proxy_client.send_binary_message(ws_connection, message)
            # close wss connection
            secure_proxy_client.close_connection(ws_connection)
            print(Fore.GREEN + "SUCCESS:" + Fore.WHITE + f" Sending websocket data to TCP application at wss://{self.address}:{self.wss_port}." + Fore.WHITE)
            self.print_scenario_footer("03", f" Sent websocket data to wss://{self.address}:{self.wss_port}.")
        except:
            traceback.print_exc()
            print(Fore.RED + "FAILURE:"  + Fore.WHITE + f" Unable to send websocket data to TCP application at wss://{self.address}:{self.wss_port}." + Fore.WHITE)


    def send_web_socket_data_with_invalid_jwt_token(self) -> None:
        self.print_scenario_header("04", f" Sending websocket data with invalid JWT token to TCP application at wss://{self.address}:{self.wss_port}.")
        messages = ["world!", "mundo!", "monde!", "mondo!", "welt!"]
        access_token = "1234567890abcdefghijklmnopqrstuvwxyz"
        secure_proxy_client = SecureProxyClient(
            address=self.address, 
            wss_port=self.wss_port, 
            jwt_token=access_token
        )
        try:
            # establish wss connection
            ws_connection = secure_proxy_client.create_connection()
            if ws_connection is None:
                print(Fore.RED + "FAILURE:"  + Fore.WHITE + f" Unable to send websocket data to TCP application at wss://{self.address}:{self.wss_port}." + Fore.WHITE)
                return
            # send wss messages
            for message in messages:
                secure_proxy_client.send_binary_message(ws_connection, message)
            # close wss connection
            secure_proxy_client.close_connection(ws_connection)
            print(Fore.GREEN + "SUCCESS:" + Fore.WHITE + f" Sending websocket data invalid JWT token to TCP application at wss://{self.address}:{self.wss_port}." + Fore.WHITE)
            self.print_scenario_footer("03", f" Sent websocket data invalid JWT token to wss://{self.address}:{self.wss_port}.")
        except websocket._exceptions.WebSocketBadStatusException:
            print(Fore.GREEN + "FAILURE:"  + Fore.WHITE + f" This is an expected failure caused as a result of including an invalid JWT token." + Fore.WHITE)


if __name__ == "__main__":
    config = get_project_settings()
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-addr", 
        "--ec2-address", 
        type=str, 
        help="Public IP address or public DNS name of the Secure Proxy EC2 instance",
        required=True
    )
    parser.add_argument(
        "-wssp", 
        "--wss-port", 
        type=int, 
        help="WSS port number of the Secure Proxy",
        default=int(config["proxySettings"]["wssProxyBindPort"]),
        required=False
    )
    parser.add_argument(
        "-hssp", 
        "--https-port",
        type=int, 
        help="HTTPS port number of the Secure Proxy",
        default=int(config["proxySettings"]["oAuthProxyBindPort"]),
        required=False
    )
    args = parser.parse_args()

    secure_proxy_test_scenarios = SecureProxyTestScenarios(
        address=args.ec2_address,
        wss_port=args.wss_port,
        https_port=args.https_port
    )
        
    # scenario 1 - get oAuth configuration
    secure_proxy_test_scenarios.get_auth_config()

    # scenario 2 - get oAuth token
    secure_proxy_test_scenarios.get_jwt_token()

    # scenario 3 - send websocket data to TCP application
    secure_proxy_test_scenarios.send_web_socket_data()

    # scenario 4 - send websocket data to TCP application with invalid jwt token
    secure_proxy_test_scenarios.send_web_socket_data_with_invalid_jwt_token()
