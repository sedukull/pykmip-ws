"""
__Author__:Santhosh
__Version__:1.0
__Desc__: Setup file for pykmip flask web service called as kis\kmis.
          Provides cryptographic key management facilities to applications.
          KIS\KMIS : Key Integration Service (or) Key Management Integration Service.
          Interface between KMS(Key Management Solution\Server) and enterprise applications
"""

try:
    from setuptools import setup, find_packages
except ImportError:
    try:
        from distribute_setup import use_setuptools
        use_setuptools()
        from setuptools import setup, find_packages
    except ImportError:
        raise RuntimeError("python setuptools is required to build kmis ws")

#VERSION = "1.0"

exec(open('kmis/version.py').read())

setup(name="kmis",
      version=__version__,
      description="web service implementation for pykmip, providing kms facilities to applications",
      author="Santhosh Kumar Edukulla",
      author_email="santhosh.edukulla@gmail.com",
      maintainer="Santhosh",
      maintainer_email="santhosh.edukulla@gmail.com",
      platforms=("Any",),
      packages=["kmis",
                "kmis.lib",
                "kmis.test",
                "kmis.deploy",
                "kmis.db",
                "kmis.src",
                "kmis.src.api",
                "kmis.src.api.v1",
                "kmis.src.api.v2",
                "kmis.src.templates",
                "kmis.src.static"],
      long_description="kmis is the web service implementation for pykmip lib,"
      "which provides key\cert retrieval services to applications",
      url="https://dummyhda.com",
      license="LICENSE.txt",
      include_package_data=True,
      package_data={'': ['*.txt', '*.html', '*.crt', '*.pem']},
      install_requires=[
          "MySQL-python",
          "flask",
          "flask-wtf",
          "gevent",
          "pyminizip",
          "requests"
      ],
      zip_safe=False,
      )
