## PYACME

#### You can get certificate from using cloudflare webhook, arvancloud webhooks, acme dns cname, raw txt records 

##### installing it using pip
```shell
pip install pyacmecli
```

### Help

    Usage: python -m pyacmecli [OPTIONS] COMMAND [ARGS]...
    
      PyACME CLIA powerful tools you can get letsencrypt certificates with dns
      providers (Arvancloud, Cloudflare, AcmeDNS) or get certificate using dns
      records)To debug application, or watch you can use: pyacmecli --verbose
      {command}
    
    Options:
      -v, --verbose  Application Log verbosity
      --help         Show this message and exit.
    
    Commands:
      cron  Renew certificate
      init  init pyacme script
      list  List of certificates
      new   Get new certificate


### How I can get certificate

```bash
 pyacmecli new --domain mydomain.ir --domain '*.mydomain.ir' --provider cloudflare --email mygmail@gmail.com --access-token 'cloudflare-access-token' --renew-command 'docker restart mycontainer_name'
```

### how to use it in production env
```shell
mkdir pyacmecli
cd pyacmecli
virtualenv .venv
source .venv/bin/active
pip install pyacmecli
/apps/pyacmecli/.venv/bin/pyacmecli init # to init pyacmecli project
/apps/pyacmecli/.venv/bin/pyacmecli new --domain mydomain.ir --domain '*.mydomain.ir' --provider cloudflare --email mygmail@gmail.com --access-token 'cloudflare-access-token' --renew-command 'docker restart mycontainer_name'
/apps/pyacmecli/.venv/bin/pyacmecli list # list of certificates
/apps/pyacmecli/.venv/bin/pyacmecli cron cron --force-renewal # force renewal certificates
/apps/pyacmecli/.venv/bin/pyacmecli cron
# example cron job (run every day at 2 AM)
crontab -e
0 2 * * * /apps/pyacmecli/.venv/bin/pyacmecli cron
```

### build and publish project
```shell
uv build
uv publish
```

### build project (legacy)
```shell
# rebuild your wheel
python -m build
# install it 
pip install dist/pyacmecli-0.1.0-py3-none-any.whl 

#upload project to pypi
twine upload dist/*
```
