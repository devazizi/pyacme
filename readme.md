_## PYACME
# language=python
#### You can get certificate from using cloudflare webhook, arvancloud webhooks, acme dns cname, raw txt

### Help

    python -m pyacmecli.__main__ --help                                                                                                                                                                                         ─╯
    Usage: app.py [OPTIONS] COMMAND [ARGS]...
    
    Options:
      --help  Show this message and exit.
    
    Commands:
      cleanup  Remove ~/.pyacme directory and remove everything be careful
      init     init pyacme script
      list     List of certificates
      new      Get new certificate
      renew    Renew certificate

### How I can get certificate

```bash
 python -m pyacmecli.__main__ new --domain mydomain.ir --domain '*.mydomain.ir' --provider cloudflare --email mygmail@gmail.com --access-token 'cloudflare-access-token' --renew-command 'docker restart mycontainer_name'
```

### List of certificate

```bash
 python -m pyacmecli.__main__ list
```

### Cron to renew certificates

```
# will develop it
```

### build project 
```shell
# rebuild your wheel
python -m build
# install it 
pip install dist/pyacmecli-0.1.0-py3-none-any.whl 

#upload project to pypi
twine upload dist/*
```
