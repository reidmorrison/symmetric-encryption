---
layout: default
---

### Encrypting Passwords in configuration files

Passwords can be encrypted in any YAML configuration file.

For example config/database.yml

```yaml
---
production:
  adapter:  mysql
  host:     db1w
  database: myapp_production
  username: admin
  password: <%= SymmetricEncryption.try_decrypt "JqLJOi6dNjWI9kX9lSL1XQ==\n" %>
```

Note: Use SymmetricEncryption.try_decrypt method which will return nil if it
  fails to decrypt the value, which is essential when the encryption keys differ
  between environments

Note: In order for the above technique to work in other YAML configuration files
  the YAML file must be processed using ERB prior to passing to YAML. For example

```ruby
    config_file = Rails.root.join('config', 'redis.yml')
    raise "redis config not found. Create a config file at: config/redis.yml" unless config_file.file?

    cfg = YAML.load(ERB.new(File.new(config_file).read).result)[Rails.env]
    raise("Environment #{Rails.env} not defined in redis.yml") unless cfg
```
