import json
from .authentication import sign_in
from .config import AVATO_HOST, AVATO_PORT, AVATO_USE_SSL
from .api import API, Endpoints, NotFoundError


class Client:
    class UnknownInstanceTypeError(Exception):
        """Raised when the instance type requested is not supported"""

        pass

    def __init__(
        self,
        username,
        password,
        instance_types=[],
        backend_host=AVATO_HOST,
        backend_port=AVATO_PORT,
        use_ssl=AVATO_USE_SSL,
        http_proxy=None,
        https_proxy=None,
    ):
        self.user = sign_in(username, password)
        self.registered_instances = instance_types
        self.api = API(
            self.user.id_token,
            backend_host,
            backend_port,
            use_ssl,
            http_proxy,
            https_proxy,
        )

    def check_user_exists(self, email):
        url = Endpoints.HEAD_USERS_EMAIL.replace(":email", email)
        try:
            self.api.head(url)
        except NotFoundError:
            return False
        return True

    def get_instances(self):
        url = Endpoints.GET_INSTANCES
        response = self.api.get(url)
        return response.json()["instanceIds"]

    def _instance_from_type(self, type):
        for instance in self.registered_instances:
            if instance.type == type:
                return instance
        raise Client.UnknownInstanceTypeError

    def get_instance(self, id):
        url = Endpoints.GET_INFO.replace(":instanceId", id)
        response = self.api.get(url)
        instance_info = response.json()
        instance_constructor = self._instance_from_type(instance_info["type"])
        return instance_constructor(
            self,
            id,
            instance_info["name"],
            instance_info["adminId"],
        )

    def create_instance(self, name, type, participants):
        url = Endpoints.POST_CREATE_INSTANCE
        data = {
            "instanceName": name,
            "instanceType": type,
            "participantIds": participants,
        }
        data_json = json.dumps(data)
        response = self.api.post(url, data_json, {"Content-type": "application/json"})
        id = response.json()["instanceId"]
        instance_constructor = self._instance_from_type(type)
        return instance_constructor(self, id, name, self.user.email)

    def reset_backend(self):
        url = Endpoints.POST_RESET
        self.api.post(url)

    def __str__(self):
        return f"Client user: {self.user}"
