import json
from .config import AVATO_HOST, AVATO_PORT, AVATO_USE_SSL
from .api import API, Endpoints, NotFoundError


class Client:
    class UnknownInstanceTypeError(Exception):
        """Raised when the instance type requested is not supported"""

        pass

    class UnknownUserEmail(Exception):
        """Raised when the user email doesn't exist"""

        pass

    def __init__(
        self,
        api_token,
        instance_types=[],
        backend_host=AVATO_HOST,
        backend_port=AVATO_PORT,
        use_ssl=AVATO_USE_SSL,
        http_proxy=None,
        https_proxy=None,
    ):
        self.registered_instances = instance_types
        self.api = API(
            api_token,
            backend_host,
            backend_port,
            use_ssl,
            http_proxy,
            https_proxy,
        )

    def get_instances(self):
        url = Endpoints.INSTANCES_COLLECTION
        response = self.api.get(url)
        return response.json()

    def _instance_from_type(self, type):
        for instance in self.registered_instances:
            if instance.type == type:
                return instance
        raise Client.UnknownInstanceTypeError

    def _get_user_id(self, email):
        url = f"{Endpoints.USERS_COLLECTION}?email={email}"
        response = self.api.get(url)
        users = response.json()
        if len(users) != 1:
            raise Client.UnknownUserEmail
        user_id = users[0]["id"]
        return user_id

    def get_instance(self, id):
        url = Endpoints.INSTANCE.replace(":instanceId", id)
        response = self.api.get(url)
        instance_info = response.json()
        instance_constructor = self._instance_from_type(instance_info["type"])
        return instance_constructor(
            self,
            id,
            instance_info["name"],
            instance_info["owner"],
        )

    def create_instance(self, name, type, participants):
        url = Endpoints.INSTANCES_COLLECTION
        data = {
            "name": name,
            "type": type,
            "participants": list(map(lambda x: {"id": self._get_user_id(x)}, participants)),
        }
        data_json = json.dumps(data)
        response = self.api.post(url, data_json, {"Content-type": "application/json"})
        response_json = response.json()
        instance_constructor = self._instance_from_type(type)
        return instance_constructor(self, response_json["id"], name, response_json["owner"])
