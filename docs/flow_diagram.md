# How is the environment created

This document shows the flow the client is following to create an environment.

Before the actual environment is created, the client makes sure that there
is a lock-file where the environment can be based on. This lock-file contains
all requested packages and their dependencies together with their version and
build number. Every environment created based on this lock-file will be
the same.

The following diagram demonstrates how the lock-file is created.

```
+--------------------------------+
|                                |
|    Locate environment file     +-----+
|     (conda-environment.yaml)   |     |
+---------------+----------------+     |
                |                      |
                |not found             |found
                v                      |
+--------------------------------+     |
|                                |     |
| Create simple environment file |     |
|                                |     |
+---------------+----------------+     |
                |                      |
                v                      |
+--------------------------------+     |
|                                |<----+
| Locate lock-file and verify it |
|  (conda_environment_xxx.lock)  +-----+
+---------------+----------------+     |
                |                      |
                |not valid/not found   |valid
                v                      |
+--------------------------------+     |
|                                |     |
|     (Re)create lock-file       |     |
|      (raises error on Jenkins) |     |
+---------------+----------------+     |
                |                      |
                v                      |
+--------------------------------+     |
|                                |     |
|       Lock-file created        |<----+
|                                |
+--------------------------------+
```

The client can be used in two modes. By default, a console prompt is
started with the environment activated. The other mode allows executing
a specific command within the environment, without activating it. The execute
mode can be used from local scripts or for example in Jenkins scripts.

The following diagram shows how the environment itself is created and/or
activated.

```
+--------------------------------+
|                                |
|       Read the lock-file       |
|                                |
+---------------+----------------+
               |
+---------------+----------------+
|                                |
|  Check if env already exists   +-------------+
|                                |             |
+---------------+----------------+             |
               |env not exists                 |
               |                               |
               v                               |
+--------------------------------+             |
|                                |             |if env
|  Create an environment in      +---+         | exists
|  <envs-dir>/<lock-file-hash>/  |   |         |
|                                |   |         |
+---------------+----------------+   |         |
               |in activation mode   |         |
               |                     |         |
               v                     |         |
+--------------------------------+   |         |
|                                |   |in exec  |
| Create a virtual folder which  |   | mode    |
|  links to the actual env dir   |   |         |
|                                |   |         |
+---------------+----------------+   |         |
               |                     |         |
               |                     |         |
               v                     |         |
+--------------------------------+   |         |
|                                |<--+         |
| Activate the environment or    |             |
| just execute the given command |<------------+
|                                |
+--------------------------------+
```
