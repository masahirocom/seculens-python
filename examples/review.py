# Deliberately unsafe examples for static review. Never execute this file.
import pickle
import subprocess


def review_only(untrusted):
    eval(untrusted)
    subprocess.run(untrusted, shell=True)
    return pickle.loads(untrusted)
