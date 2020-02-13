import ssl

from requests.adapters import HTTPAdapter

original_init_poolmanager = HTTPAdapter.init_poolmanager


def custom_init_poolmanager(self, *args, **kwargs):
    ssl_context = ssl.create_default_context()
    ssl_context.load_default_certs()
    kwargs["ssl_context"] = ssl_context

    original_init_poolmanager(self, *args, **kwargs)


HTTPAdapter.init_poolmanager = custom_init_poolmanager


def obtain_credentials_hook(url, previous_username):
    if url.startswith("https://..."):
        # Implement your own logic here
        pass

    return None


def settings_hook(settings):
    pass
