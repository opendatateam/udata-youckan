=============
udata-youckan
=============

.. image:: https://travis-ci.org/etalab/udata-youckan.svg?branch=master
    :target: http://travis-ci.org/etalab/udata-youckan
    :alt: Build status
.. image:: https://coveralls.io/repos/etalab/udata-youckan/badge.png?branch=master
    :target: https://coveralls.io/r/etalab/udata-youckan
    :alt: Code coverage
.. image:: https://requires.io/github/etalab/udata-youckan/requirements.png?branch=master
    :target: https://requires.io/github/etalab/udata-youckan/requirements/?branch=master
    :alt: Requirements Status

YouCKAN Auth for uData.

Compatibility
=============

udata-youckan requires Python 2.7+ and uData X.X+.


Installation
============

You can install udata-youckan with pip:

.. code-block:: console

    $ pip install udata-youckan

or with easy_install:

.. code-block:: console

    $ easy_install udata-youckan


Configuration
=============

In order to use YouCKAN as authentication provider, you need to enable the plugin
and add the following mandatory parameters to you uData configuration:

.. code-block:: python

    PLUGINS = ['youckan']
    YOUCKAN_URL = 'https://your.youckan.url/'
    YOUCKAN_CONSUMER_KEY = 'your-youckan-client-key',
    YOUCKAN_CONSUMER_SECRET = 'your-youckan-secret-key'
