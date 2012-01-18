symmetric-encryption
====================

* http://github.com/ClarityServices/symmetric-encryption

### Introduction

Any project that wants to meet PCI compliance has to ensure that the data is encrypted
whilst in flight and at rest. Amongst many other other requirements all passwords
in configuration files have to be encrypted

This Gem helps achieve compliance by supporting encryption of data in a simple
and consistent way

### Features

* Encryption of passwords in configuration files
* attr_encrypted replacement
* Externalization of symmetric encryption keys so that they are not in the
  source code

### Install

  gem install symmetric-encryption

Meta
----

* Code: `git clone git://github.com/ClarityServices/symmetric-encryption.git`
* Home: <https://github.com/ClarityServices/symmetric-encryption>
* Docs: TODO <http://ClarityServices.github.com/symmetric-encryption/>
* Bugs: <http://github.com/reidmorrison/symmetric-encryption/issues>
* Gems: <http://rubygems.org/gems/symmetric-encryption>

This project uses [Semantic Versioning](http://semver.org/).

Authors
-------

Reid Morrison :: reidmo@gmail.com :: @reidmorrison

License
-------

Copyright 2012 Clarity Services, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
