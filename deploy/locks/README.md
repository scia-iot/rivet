# Container dependency lock maintenance

These locks are independent of the broad development requirements. `api.txt`
is the complete runtime closure; `agent.txt` is the pydantic/cryptography
closure also needed by the OpenVPN event hook. Do not run an unpinned install
at container startup or copy a developer virtual environment into an image.

The initial API closure was resolved on CPython 3.14 using:

```sh
python -m pip install --dry-run --ignore-installed --only-binary=:all: \
  --report /tmp/ovpncp-image-deps.json \
  cryptography==50.0.1 fastapi==0.141.1 PyYAML==6.0.3 sqlmodel==0.0.42 \
  uvicorn==0.52.4 python-jose==3.5.0 azure-storage-blob==12.30.1 \
  python-multipart==0.0.32 httpx==0.28.1 pydantic==2.13.5
```

For each `install` record, its `metadata.name` and `metadata.version` select
`https://pypi.org/pypi/NAME/VERSION/json`. Collect the distinct sorted
`urls[].digests.sha256` values where `packagetype == "bdist_wheel"` and emit
`NAME==VERSION` followed by a `--hash=sha256:VALUE` for every wheel. No source
archive hash is admitted. The committed exact versions are the source of truth;
rerunning resolution later is an intentional dependency update requiring review.

The agent closure is exactly annotated-types, cffi, cryptography, pycparser,
pydantic, pydantic-core, typing-extensions and typing-inspection, with versions
and wheel hashes copied from the API lock. Hashes cover published platforms;
installation still selects only a compatible wheel for the requested platform.

Check the committed AMD64 closure without installing anything:

```sh
python -m pip install --dry-run --ignore-installed --require-hashes \
  --only-binary=:all: --python-version 3.14 --implementation cp \
  --abi cp314 --abi abi3 --abi none \
  --platform manylinux_2_34_x86_64 --platform manylinux_2_28_x86_64 \
  --platform manylinux2014_x86_64 -r deploy/locks/api.txt
```

Repeat for `agent.txt` and for ARM64 by replacing `x86_64` with `aarch64`.
This checks resolution, hashes and wheel availability; it does not replace
building the images and testing their actual runtime imports. Refresh exact
versions, all wheel hashes, source pins and Debian/base pins together only as
a reviewed change, then repeat the container and application gates.
