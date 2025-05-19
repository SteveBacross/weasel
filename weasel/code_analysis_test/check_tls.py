import requests

def get_page(url):
    return requests.get(url, verify=False) 
