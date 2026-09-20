import requests
import subprocess


def evaluate_request(user_expression):
    return eval(user_expression)


def launch_task(command):
    return subprocess.run(command, shell=True)


def fetch_data(url):
    return requests.get(url, verify=False)
