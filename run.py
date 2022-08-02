# -*- encoding: utf-8 -*-
import argparse
import base64
import json
import os
import shutil
import sys
import threading
import time
import uuid

import requests
from flask import Blueprint, request, make_response, jsonify, g, Flask, current_app
import docker

blueprint = Blueprint(
    'base',
    __name__,
    url_prefix='',
    template_folder='templates'
)

ALL_IMAGES = {}
DEFAULT_IMAGES = []
DEFAULT_RESOURCES = []
DOCKER_PRIVATE_IMAGE_REPO = "ghcr.io/private/vnv-private-images"

# This is the port the GUI runs on -- It hardcoded into the launch.sh script of the gui
# server, so dont change it.
IMAGE_PORT = 5000

# Little cache to keep state in while we update stuff.
CONTAINER_CACHE = {}


def benc(msg):
    message_bytes = msg.encode('ascii')
    base64_bytes = base64.b64encode(message_bytes)
    return base64_bytes.decode('ascii')


def bdec(msg):
    base64_bytes = msg.encode('ascii')
    message_bytes = base64.b64decode(base64_bytes)
    return message_bytes.decode('ascii')


class Container:
    def __init__(self, id, user, name, repo, desc, code=uuid.uuid4().hex, tag="latest", status="RUNNING"):
        self.id = id
        self.user = user
        self.name = name
        self.repo = repo
        self.tag = tag
        self.desc = desc
        self.dstatus = status
        self.code = code

    def status(self):
        if self.dstatus == "RUNNING":
            try:
                a = ContainerImplementation.docker_client.containers.get(self.id)
                if a is not None:
                    return a.status
                print("Not Found" , self.id)
            except Exception as e:
                print(e)
                pass

            return "Launching Container"

        return self.dstatus

    def to_json(self):
        return {
            "id": self.id,
            "user": self.user,
            "name": self.name,
            "repo": self.repo,
            "tag": self.tag,
            "code": self.code,
            "status": self.status(),
            "description": self.desc
        }

    @staticmethod
    def from_json(j):
        return Container(id=j["id"],
                         user=j["user"],
                         name=j["name"],
                         repo=j["repo"],
                         tag=j["tag"],
                         code=j["code"],
                         desc=j["description"],
                         )


class ContainerImplementation:
    docker_client = docker.from_env()

    @classmethod
    def load_all(cls):
        docker_containers = cls.docker_client.containers.list(all=True, filters={"label": "vnv-container-info"})
        for container in docker_containers:
            try:
                inf = json.loads(container.labels["vnv-container-info"])
                cont = Container.from_json(inf)
                cont.port = container.ports[f"{IMAGE_PORT}/tcp"][0]["HostPort"]
                cont.code = container.labels["vnv-gui-code"]
                cont.dstatus = "RUNNING"
                cont.status()
                CONTAINER_CACHE[cont.id] = cont

            except:
                pass

    @classmethod
    def get_image(cls, repo, tag, **kwargs):
        return cls.docker_client.images.pull(repository=repo, tag=tag, **kwargs)

    @classmethod
    def get_container(cls, container_id, uid):

        container = CONTAINER_CACHE.get(container_id)
        if container is not None and uid == container.user:
            return container
        return None

    @classmethod
    def get_docker_container(cls, container_id):
        try:
            return cls.docker_client.containers.get(container_id)
        except:
            return None

    @classmethod
    def create_(cls, container, imageKwargs, config):

        try:
            gui_code = uuid.uuid4().hex
            container.code = gui_code

            image = cls.get_image(repo=container.repo, tag=container.tag, **imageKwargs)



            if image is not None:
                volumes = {}
                ssl_opts = ""
                if config["SSL"]:
                    volumes[config.SSL_DIR] : {'bind': config.SSL_DIR, "mode": "ro"}
                    ssl_opts = f"--ssl 1 --ssl_cert {config.SSLCTX[0]} --ssl_key {config.SSLCTX[1]}"

                opts = dict(
                    command=f"/vnv-gui/launch.sh --code {container.code} {ssl_opts}",
                    labels={
                        "vnv-container-info": json.dumps(container.to_json()),
                        "vnv-gui-code": gui_code,
                    },
                    volumes=volumes,
                    name=container.id,
                    ports={5000: None},
                    detach=True
                )

                cls.docker_client.containers.run(f"{container.repo}:{container.tag}", **opts)

        except Exception as e:
            print(e)
            pass

    @classmethod
    def stop_(cls, container_id, uid):
        c = cls.get_container(container_id, uid)
        if c is not None:
            dc = cls.get_docker_container(c)
            if dc is not None:
                dc.stop(timeout=0)
                return True
        return False

    @classmethod
    def start_(cls, container_id, uid):
        c = cls.get_container(container_id, uid)
        if c is not None:
            dc = cls.get_docker_container(c)
            if dc is not None:
                dc.start()
                return True
        return False

    @classmethod
    def delete_(cls, container_id, uid):
        c = cls.get_container(container_id, uid)
        if c is not None:
            a = cls.get_docker_container(c)
            if a is not None:
                a.stop(timeout=0)
                a.remove(force=True, v=False)
                return True
        return False

    @classmethod
    def snapshot_(cls, container_id, uid, kwargs):
        c = cls.get_container(container_id, uid)
        repo = kwargs.pop("repo")
        tag = kwargs.pop("tag", None)
        if c is not None:
            newlabel = 'LABEL vnv-container-info=""\nLABEL vnv-gui-code=""'
            a = cls.get_docker_container(c)
            if a is not None:
                a.commit(repo, tag=tag, changes=newlabel)
                cls.docker_client.push(repo, tag=tag, **kwargs)
                return True
        return False

    @classmethod
    def port_and_code(cls, container_id, uid):

        c = cls.get_container(container_id, uid)
        if c is not None:
            container = cls.get_docker_container(container_id)
            if container is not None:
                return container.ports[f"{IMAGE_PORT}/tcp"][0]["HostPort"], {
                    "vnv-gui-code": container.labels["vnv-gui-code"]}
        return None, None

    @classmethod
    def list_containers(cls, uid):
        containers = []
        for container in CONTAINER_CACHE.values():
            try:
                if container.user == uid:
                    containers.append(container)
            except:
                pass
        return containers


@blueprint.before_request
def check_valid_login():
    g.user = request.cookies.get("vnv-resource-user")
    return  ####DEBUG
    g.user = request.cookies.get("vnv-resource-user")
    if g.user is None or request.cookies.get("vnv-resource-auth") != current_app.config["AUTHCODE"]:
        return make_response("Error", 201)


@blueprint.route("/ready", methods=["GET"])
def ready():
    return make_response("", 200)


# Return a list of containers and their status.
@blueprint.route('/list', methods=["GET"])
def container_management():
    containers = ContainerImplementation.list_containers(g.user)
    r = [c.to_json() for c in containers]
    return make_response(jsonify(r), 200)


@blueprint.route('/create', methods=["POST"])
def create_container():
    try:
        j = request.get_json()
        container_id = j["cid"]
        repo = j.pop("repo")
        tag = j.pop("tag", "latest")
        name = j.pop("name", "Untitled")
        desc = j.pop("desc", "No Description")
        extra = j.pop("extra", {})

        container = Container(container_id, g.user, name=name, repo=repo, desc=desc, tag=tag)
        CONTAINER_CACHE[container_id] = container

        threading.Thread(target=ContainerImplementation.create_,
                         args=[container,  extra, current_app.config ]).start()
        return make_response(container_id, 200)
    except Exception as e:
        return make_response("invalid container config" + str(e), 400)


@blueprint.route('/stop/<cid>', methods=["POST"])
def stop_container(cid):
    try:
        CONTAINER_CACHE[cid].dstatus = "Stopped"
        threading.Thread(target=ContainerImplementation.stop_, args=[cid, g.user]).start()
        return make_response("", 200)
    except:
        return make_response("", 201)


@blueprint.route('/start/<cid>', methods=["POST"])
def start_container(cid):
    try:
        CONTAINER_CACHE[cid].dstatus = "RUNNING"
        threading.Thread(target=ContainerImplementation.start_, args=[cid, g.user]).start()
        return make_response("", 200)
    except:
        return make_response("", 201)


@blueprint.route('/delete/<cid>', methods=["POST"])
def delete_container(cid):
    try:
        CONTAINER_CACHE.pop(cid)
        threading.Thread(target=ContainerImplementation.delete_, args=[cid, g.user]).start()
        return make_response("", 200)
    except:
        return make_response("", 201)


@blueprint.route('/port/<cid>', methods=["POST"])
def get_container_port(cid):
    try:

        port, cookies = ContainerImplementation.port_and_code(cid, g.user)
        return make_response(jsonify({"port": port, "cookies": cookies}), 200)
    except:
        pass

    return make_response(jsonify({}), 201)


@blueprint.route('/snapshot/<cid>', methods=["POST"])
def create_image(cid):
    try:
        j = request.get_json()
        threading.Thread(target=ContainerImplementation.snapshot_, args=[cid, g.user, j]).start()
        return make_response("", 200)
    except:
        return make_response("", 201)


class Config:
    DEBUG = False
    port = 5010
    HOST = "0.0.0.0"
    AUTHCODE = "secret"
    LOGOUT_COOKIE = "vnvnginxcode"

    SSL = False
    SSL_DIR = "tmp_ssl_dir"
    SSLCTX = (os.path.join(SSL_DIR, "cert.crt"), os.path.join(SSL_DIR, "cert.key"))


ContainerImplementation.load_all()

if __name__ == "__main__":
    app_config = Config()

    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, help="port to run on (default 5001)", default=5000)
    parser.add_argument("--host", help="host to run on (default localhost)", default="0.0.0.0")
    parser.add_argument("--code", type=str, help="authorization-code", default="secret")
    parser.add_argument("--logout", help="name of logout cookie", default="vnvnginxcookie")
    parser.add_argument("--ssl", type=bool, help="should we use ssl", default=False)
    parser.add_argument("--ssl_cert", type=str, help="file containing the ssl cert", default=None)
    parser.add_argument("--ssl_key", type=str, help="file containing the ssl cert key", default=None)

    args = parser.parse_args()
    Config.port = args.port
    Config.HOST = args.host
    Config.AUTHCODE = args.code
    Config.LOGOUT_COOKIE = args.logout
    Config.SSL = args.ssl

    app = Flask(__name__, static_folder="static")
    app.config.from_object(app_config)
    app.register_blueprint(blueprint)

    opts = {
        "use_reloader": False,
        "host": app_config.HOST,
        "port": app_config.port
    }

    if args.ssl:

        if not os.path.exists(Config.SSL_DIR):
            os.mkdir(Config.SSL_DIR)
        shutil.copy(args.ssl_cert, Config.SSLCTX[0])
        shutil.copy(args.ssl_key, Config.SSLCTX[1])
        opts["ssl_context"] = Config.SSLCTX

    app.run(**opts)
