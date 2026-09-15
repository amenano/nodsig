"""The C sources of the native kernel and their builder (`build.py`).
The kernel itself, once built, is the extension module `nodsig._native`;
`nodsig.kernel` is the one place that chooses between it and the Python
reference."""
