# munge-operator

This charm installs the munge package, generates and stores the munge-key, and starts the munge systemd service.

# Example Usage
```bash
juju deploy slurmd --base ubuntu@22.04
juju deploy munge --channel edge

juju integrate slurmd munge
```

### Copyright
* Omnivector, LLC &copy; <admin@omnivector.solutions>

### License
* Apache v2 - see [LICENSE](./LICENSE)
