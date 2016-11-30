uData-youckan
=============

[![Build status][circleci-badge]][circleci-url]
[![Join the chat at https://gitter.im/opendatateam/udata][gitter-badge]][gitter-url]

This plugin provide integration between [uData][] and [YouCKAN][]

Compatibility
-------------

**udata-youckan** requires Python 2.7+ and [uData][].


Installation
------------

Install [uData][].

Remain in the same virtual environment (for Python) and use the same version of npm (for JS).

Install **udata-youckan**:

```shell
pip install udata-youckan
```

Configuration
-------------

In order to use YouCKAN as authentication provider, you need to enable the plugin
and add the following mandatory parameters to you uData configuration
(typically, `udata.cfg`) as following:

```python
PLUGINS = ['youckan']
YOUCKAN_URL = 'https://your.youckan.url/'
YOUCKAN_CONSUMER_KEY = 'your-youckan-client-key',
YOUCKAN_CONSUMER_SECRET = 'your-youckan-secret-key'
```

[circleci-url]: https://circleci.com/gh/opendatateam/udata-youckan
[circleci-badge]: https://circleci.com/gh/opendatateam/udata-youckan.svg?style=shield
[gitter-badge]: https://badges.gitter.im/Join%20Chat.svg
[gitter-url]: https://gitter.im/opendatateam/udata
[uData]: https://github.com/opendatateam/udata
[YouCKAN]: https://github.com/etalab/youckan
