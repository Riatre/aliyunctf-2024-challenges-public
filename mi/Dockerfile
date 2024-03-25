# python:3.11.8-slim
FROM python@sha256:4bcdb5d5bc81caf410bc880ca7d47d6ce3f05dc50f81166eb42827fcdc98cfca

RUN apt-get update && apt-get install -y git && apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    pip install --no-cache \
    'zstandard>=0.22.0,<0.23.0' \
    'git+https://github.com/google-deepmind/tracr.git@9ce2b8c82b6ba10e62e86cf6f390e7536d4fd2cd'
ADD __main__.py challenge.pkl.zst /
CMD ["python", "__main__.py"]
