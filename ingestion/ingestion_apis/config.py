from pathlib import Path

OPA_PORT = 8181
OPA_IP = '127.0.0.1'
OPA_NAME = 'magen_opa'


def inside_docker():
    docker_env = Path('/.dockerenv')
    return docker_env.is_file()


def opa_locator():
    opa_ip, opa_port = opa_host_port()
    return '{ip}:{port}'.format(ip=opa_ip, port=opa_port)


def opa_host_port():
    magen_opa = OPA_IP if not inside_docker() else OPA_NAME
    return magen_opa, OPA_PORT


OPA_BASE_DOC_URL = "http://"+opa_locator()+"/v1/data/"
OPA_POLICY_URL = "http://"+opa_locator()+"/v1/policies/"
