import json
from jsii.python import classproperty


class CdkUtils():

    @classproperty
    def stack_prefix(self) -> str:
        return "ec2-imagebuilder-secure-proxy"

    @staticmethod
    def get_project_settings():
        filename = "cdk.json"
        with open(filename, 'r') as cdk_json:
            data = cdk_json.read()
        return json.loads(data).get("projectSettings")