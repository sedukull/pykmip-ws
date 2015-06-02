'''
__Author__:Santhosh
__Version__:1.0
__Desc__: Setup file for pykmip flask web service called as kis. Provides cryptographic key management facilities to applications

'''
try:
    from setuptools import setup, find_packages
except ImportError:
    try:
        from distribute_setup import use_setuptools
        use_setuptools()
        from setuptools import setup, find_packages
    except ImportError:
        raise RuntimeError("python setuptools is required to build kis ws")

VERSION = "1.0"


setup(name="kis",
      version=VERSION,
      description="web service implementation for py kmip providing kms facilities to applications",
      author="Santhosh Kumar Edukulla",
      author_email="santhosh.edukulla@gmail.com",
      maintainer="Santhosh",
      maintainer_email="santhosh.edukulla@gmail.com",
      long_description="kis is the web service implementation for pykmip which provides key management facilities to applications",
      url="https://dummy.com",
      license="LICENSE.txt",
      install_requires=[
          "MySQL-python",
          "flask",
          "flask-wtf"
      ],
      zip_safe=False,
      )
