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
from io import StringIO, BytesIO
from threading import Thread
import requests
from flask import Blueprint, request, make_response, jsonify, g, Flask, current_app
import docker

blueprint = Blueprint(
    'base',
    __name__,
    url_prefix='',
    template_folder='templates'
)

REFS = {}

# This is the port the GUI runs on inside the container.-- It hardcoded into the launch.sh script of the gui
# server, so dont change it!
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
    def __init__(self, id, user, name, repo, desc, code=None, tag="latest", dstatus="CHECK", error=""):
        self.id = id
        self.user = user
        self.name = name
        self.repo = repo
        self.tag = tag
        self.desc = desc
        self.dstatus = dstatus
        self.code = code if code is not None else uuid.uuid4().hex
        self.error = error

    def status(self):
        if self.dstatus == "CHECK":
            try:
                a = ContainerImplementation.docker_client.containers.get(self.id)
                if a is not None:
                    return a.status #  created, restarting, running, removing, paused, exited, dead

            except Exception as e:
                pass

            return "error"

        return self.dstatus

    def to_json(self):
        return {
            "id": self.id,
            "user": self.user,
            "name": self.name,
            "repo": self.repo,
            "tag": self.tag,
            "code": self.code,
            "dstatus": self.dstatus,
            "status": self.status(),
            "description": self.desc,
            "error" : self.error
        }

    @staticmethod
    def from_json(j):
        return Container(id=j["id"],
                         user=j["user"],
                         name=j["name"],
                         repo=j["repo"],
                         tag=j["tag"],
                         code=j["code"],
                         dstatus = j["dstatus"],
                         desc=j["description"],
                         error=j["error"]
                         )


class ContainerImplementation:
    docker_client = docker.from_env()

    @classmethod
    def configureUserDatabase(cls,userId, size=1000):
        try:
            vol = cls.docker_client.volumes.get("vol-" + userId)
        except:
            vol = cls.docker_client.volumes.create("vol-" + userId,
                                                   driver="local",
                                                   driver_opts={
                                                       "type": "tmpfs",
                                                       "device": "tmpfs",
                                                       "o": f"size={size}m,uid=1000"
                                                   })
        return "vol-" + userId

    ### Load all containers available inside the environment 
    @classmethod
    def load_all(cls):
        docker_containers = cls.docker_client.containers.list(all=True, filters={"label": "vnv-container-info"})
        for container in docker_containers:
            try:
                inf = json.loads(container.labels["vnv-container-info"])
                cont = Container.from_json(inf)
                cont.port = container.ports[f"{IMAGE_PORT}/tcp"][0]["HostPort"]
                cont.code = container.labels["vnv-gui-code"]
                cont.dstatus = "CHECK"
                CONTAINER_CACHE[cont.id] = cont

            except:
                pass

    @classmethod
    def get_image(cls, repo, tag, **kwargs):
        try:
            if "private" in kwargs and kwargs["private"]:
                auth_config = {
                    "username" :kwargs.get("username"),
                    "password" : kwargs.get("passw")
                }
                return cls.docker_client.images.pull(repository=repo, tag=tag, auth_config=auth_config)

            return cls.docker_client.images.pull(repository=repo, tag=tag)
        except Exception as e:
            #Try find it locally.
            return cls.docker_client.images.get(repo + ":" + (tag if tag is not None else "latest"))

    @classmethod
    def get_container(cls, container_id, uid):

        container = CONTAINER_CACHE.get(container_id)
        if container is not None and uid == container.user:
            return container
        return None

    @classmethod
    def wrap_image(cls, run_image, config, container):
        try:
                gui_code = uuid.uuid4().hex
                ri = f"wrapped-{gui_code}"                
                cls.docker_client.images.build(
                    path=config["DOCKERFILEWRAP"],
                    tag=ri, 
                    buildargs = {
                        "FROM_IMAGE" : run_image,
                        "GUI_IMAGE" : config["GUI_IMAGE"],
                    }
                )
                return ri
        except Exception as e:
            print(e)
            raise Exception("Failed to wrap image: " + str(e))

    @classmethod
    def get_docker_container(cls, container_id):
        try:
            return cls.docker_client.containers.get(container_id)
        except:
            return None

    @classmethod
    def create_(cls, container, imageKwargs, config):

        try:
            container.error = "Downloading Image"
            try:
                image = cls.get_image(repo=container.repo, tag=container.tag, **imageKwargs)
            except:
                image = None

            if image is not None:
              
                container.error = "Configuring Container"
                run_image =  container.repo + (":" + container.tag) if container.tag is not None else ""
                ssl_opts = ""

                #Build in the SSL Configuration 
                if config['SSL']:
                    container.error = "Configuring SSL "
                   
                    with open(os.path.abspath(config["SSLCTX"][0])) as f:
                        crt = f.readlines()
                    with open(os.path.abspath(config["SSLCTX"][1])) as f:
                        key = f.readlines()

                    s = BytesIO()
                    ss = "from " + run_image + "\n"
                    s.write(str.encode(ss))
                    s.write(b"run mkdir -p /certs\n")
                    s.write(b"run echo '\\\n")
                    for i in crt:
                        ss = i.strip() + "\\n\\\n"
                        s.write(str.encode(ss))
                    s.write(b"' > /certs/cert.crt\n")
                    s.write(b"run echo '\\\n")
                    for i in key:
                        ss = i.strip() + "\\n\\\n"
                        s.write(str.encode(ss))
                    s.write(b"' > /certs/cert.key\n")

                    #Update the run image to this new image and build it. 
                    run_image = f"vci-{container.id}"
                    ssl_opts = f" --ssl 1 --ssl_cert /certs/cert.crt --ssl_key /certs/cert.key"
                    cls.docker_client.images.build(fileobj=s, tag=run_image)
                
                #Wrap the GUI into this thing. 
                if image.labels.get("VNV_GUI_EQUIPT") is None:
                   container.error = "Installing VnV Toolkit GUI"
                   run_image = cls.wrap_image(run_image, config, container)
                        
                wsp = ""
                if config["WSPATH"] is not None:
                    wsp = "--wspath " + config["WSPATH"] + " "
                
                if config["THEIAPATH"] is not None:
                    wsp += "--theiapath" + config["THEIAPATH"] + " "   
 
                opts = dict(
                    command=f"/vnv-gui/launch.sh --code {container.code} {wsp} {ssl_opts} ",
                    labels={
                        "vnv-container-info": json.dumps(container.to_json()),
                        "vnv-gui-code": container.code,
                    },
                    name=container.id,
                    ports={5000: None},
                    detach=True
                )

                if config["DATABASE"]:
                    vol = cls.configureUserDatabase(container.user, size=config["DATABASE_SIZE"])
                    opts["volumes"] = [f"{vol}:{config['DATABASE_DIR']}"]

                container.error = "Launching Container"
                cls.docker_client.containers.run(run_image, **opts)
                container.error = ""
                container.dstatus = "CHECK"
            else:
                container.dstatus = "error"
                container.error = "Image not found"

        except Exception as e:
            container.dstatus = "error"
            container.error = str(e)

    @classmethod
    def stop_(cls, container_id, uid):
        c = cls.get_container(container_id, uid)
        if c is not None:
    
            try:
                dc = cls.get_docker_container(container_id)
                if dc is not None:
                    dc.stop(timeout=0)
                    c.error = ""
                    c.dstatus = "CHECK"
                    return True
            except:
                pass

            c.error="Could Not Stop Container."
            c.dstatus = "CHECK"
            return False
        
        return False
        
    @classmethod
    def start_(cls, container_id, uid):
        c = cls.get_container(container_id, uid)
        if c is not None:
            try:
                dc = cls.get_docker_container(container_id)
                if dc is not None:
                    dc.start()
                    c.dstatus = "CHECK"
                    c.error = ""
                    return True
            except:
                pass

            c.error = "Could not start container"
            c.dstatus = "CHECK"
        return False

    @classmethod
    def delete_(cls, container_id, uid):

        c = cls.get_container(container_id, uid)
        if c is not None:
            try:
                a = cls.get_docker_container(container_id)
                if a is not None:
                    a.stop(timeout=0)
                    a.remove(force=True, v=False)
                else:
                    c.dstatus = "CHECK"
                    c.error = "Underlying Docker Container is missing"
                
                CONTAINER_CACHE.pop(container_id)

            except:
                pass

            c.dstatus = "CHECK"
            c.error = "Could not delete container"
            

    @classmethod
    def snapshot_(cls,ref, container_id, uid, kwargs):
        
        c = cls.get_container(container_id, uid)
        repo = kwargs.pop("repo",None)
        tag = kwargs.pop("tag", None)
        if c is None or repo is None or tag is None:
            REFS[ref] = "Invalid Repo,tag or container"
            return

        if "username" not in kwargs or "password" not in kwargs:
            REFS[ref] = "Please provide a username and password"

        newlabel = 'LABEL vnv-container-info=""\nLABEL vnv-gui-code=""'
        a = cls.get_docker_container(container_id)
        if a is not None:
            try:
                a.commit(repo, tag=tag, changes=newlabel)
                a = cls.docker_client.images.push(repo, tag=tag, auth_config={
                    "username": kwargs.get("username"),
                    "password": kwargs.get("password")
                }, decode = True, stream=True)

                success = True
                REFS[ref] = "Pending"
                for i in a:
                    if "errorDetail" in i:
                        REFS[ref] = "Failed: " + i["errorDetail"]["message"]
                        success=False
                if success:
                    REFS[ref] = "Success"

                return True
            except Exception as e:
                REFS[ref] = "Snapshot Failed because " + str(e)
                return False

        REFS[ref] = "Could not find contanier to snapshot"
        return False

    @classmethod
    def port_and_code(cls, container_id, uid):

        c = cls.get_container(container_id, uid)
        if c is not None:
            container = cls.get_docker_container(container_id)
            if container is not None:
                return container.ports[f"{IMAGE_PORT}/tcp"][0]["HostPort"], {"vnv-gui-code": container.labels["vnv-gui-code"]}
            raise Exception("Docker container does not exist")
        raise Exception("Container ID does not exist")
        
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
    if g.user is None:
        return make_response("Error No user name provided", 201)
    if request.cookies.get("vnv-resource-auth") != current_app.config["AUTHCODE"]:
        return make_response("Error: Incorrect Authorization Code", 201)
    

@blueprint.route("/ready", methods=["GET"])
def ready():
    return make_response(f'Hi {g.user}', 200)


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
        code = j.pop("code", uuid.uuid4().hex)


        extra = dict(
            private=j.get("private", False),
            username = j.get("username", None),
            password = j.get("password", None)
        )

        cont = ContainerImplementation.get_container(container_id, g.user)
        if cont is not None:
            return make_response("Error: Container Id already exists", 201)        

        container = Container(container_id, g.user, name=name, repo=repo, desc=desc, tag=tag, code=code)
        CONTAINER_CACHE[container_id] = container
        container.dstatus = "creating"
        threading.Thread(target=ContainerImplementation.create_,
                         args=[container,  extra, current_app.config ]).start()

        return make_response(container_id, 200)
    except Exception as e:
        return make_response("invalid container config: " + str(e), 400)


@blueprint.route('/status/<cid>', methods=["GET"])
def container_status(cid):
    container= ContainerImplementation.get_container(cid, g.user)
    if container is not None:
        return make_response(jsonify(container.to_json()), 200)
    else:
        return make_response("Container Does not exist", 201)


@blueprint.route('/stop/<cid>', methods=["POST"])
def stop_container(cid):
    container = CONTAINER_CACHE.get(cid)
    if container is not None and container.user == g.user:
        try:
            container.dstatus = "stopping"
            threading.Thread(target=ContainerImplementation.stop_, args=[cid, g.user]).start()
            return make_response("", 200)
        except:
            pass

    return make_response("", 201)


@blueprint.route('/start/<cid>', methods=["POST"])
def start_container(cid):
    container = CONTAINER_CACHE.get(cid)
    if container is not None and container.user == g.user:
        try:
            CONTAINER_CACHE[cid].dstatus = "starting"
            threading.Thread(target=ContainerImplementation.start_, args=[cid, g.user]).start()
            return make_response("", 200)
        except:
            pass
    return make_response("", 201)


@blueprint.route('/delete/<cid>', methods=["POST"])
def delete_container(cid):
    try:
        container = CONTAINER_CACHE.get(cid)
        if container is not None and container.user == g.user:
            container.dstatus = "deleting"
            threading.Thread(target=ContainerImplementation.delete_, args=[cid, g.user]).start()
            return make_response("ref", 200)
    except:
        pass

    return make_response("", 201)

@blueprint.route('/ref/<cid>', methods=["POST"])
def get_ref(cid):
    return make_response(REFS.get(cid,"Not Found"),200)

@blueprint.route('/port/<cid>', methods=["POST"])
def get_container_port(cid):
    try:
        port, cookies = ContainerImplementation.port_and_code(cid, g.user)
        return make_response(jsonify({"port": port, "cookies": cookies}), 200)
    except Exception as e:
        return make_response(f"Error: {e}", 201)


@blueprint.route('/snapshot/<cid>', methods=["POST"])
def create_image(cid):
    try:
        j = request.get_json()
        ref = uuid.uuid4().hex
        REFS[ref] = "Starting Snapshot"
        threading.Thread(target=ContainerImplementation.snapshot_, args=[ref, cid, g.user, j]).start()
        return make_response(ref, 200)
    except:
        return make_response("", 201)


class Config:

    DEBUG = False
    port = 5010
    HOST = "0.0.0.0"
    AUTHCODE = "secret"
    SSL = False
    SSL_DIR = "tmp_ssl_dir"
    SSLCTX = (os.path.join(SSL_DIR, "cert.crt"), os.path.join(SSL_DIR, "cert.key"))
    DATABASE = True
    DATABASE_SIZE = 1000
    DATABASE_DIR="/vnv-shared"
    WSPATH = None
    THEIAPATH = None
    DOCKERFILEWRAP = ""
    GUI_IMAGE = ""
    
ContainerImplementation.load_all()

def download_gui_image(gui_image): 
    
    rr = gui_image.split(":")
    repo = rr[0]
    tag = rr[1] if len(rr) == 2 else "latest"
    try:
        docker.from_env().images.pull(repo,tag=tag)
    except Exception as e:
        try:
            docker.from_env().images.get(gui_image)
        except Exception as ee:
            print(f"Warning: Could not pull gui image {e}")
            print(f"Warning: Image does not exist locally: {ee}")
    print("GUI Image Update Complete")
    
if __name__ == "__main__":

    DEFAULT_GUI_IMAGE = os.getenv("VNV_GUI_IMAGE", "ghcr.io/vnvlabs/gui:v1.0.1")

    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, help="port to run on (default 5001)", default=5000)
    parser.add_argument("--host", help="host to run on (default localhost)", default="0.0.0.0")
    parser.add_argument("--code", type=str, help="authorization-code", default="secret")
    parser.add_argument("--ssl", type=bool, help="should we use ssl", default=False)
    parser.add_argument("--database", type=bool, help="should we provide the users a database", default=True)
    parser.add_argument("--database-size", type=int, help="size of the database in mb", default=200)
    parser.add_argument("--database-dir", type=str, help="mount directory for database", default="/vnv-shared")
    parser.add_argument("--ssl_cert", type=str, help="file containing the ssl cert", default=None)
    parser.add_argument("--ssl_key", type=str, help="file containing the ssl cert key", default=None)
    parser.add_argument("--wspath", type=str, help="web socket path", default=None)
    parser.add_argument("--theiapath", type=str, help="web socket path", default=None)
    parser.add_argument("--wrapper", type=str, help="path to the dockerfile that wraps the gui.", default="./wrap")
    parser.add_argument("--image", type=str, help="image name for the vnv gui to use during wrapping", default=DEFAULT_GUI_IMAGE)

    args = parser.parse_args()
    Config.port = args.port
    Config.HOST = args.host
    Config.AUTHCODE = args.code
    Config.SSL = args.ssl
    Config.DATABASE = args.database
    Config.DATABASE_SIZE = args["database-size"]
    Config.DATABASE_DIR = args["database-dir"]

    Config.DOCKERFILEWRAP = args.wrapper
    Config.GUI_IMAGE = args.image
    Config.WSPATH = args.wspath
    Config.THEIAPATH = args.theiapath
    

    app_config = Config()
        
    thread = Thread(target=download_gui_image, args=(Config.GUI_IMAGE,) )
    thread.start()
    
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
