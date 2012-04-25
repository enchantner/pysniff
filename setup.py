from setuptools import setup, Extension
setup(name='pysniff',
      version='0.1',
      description='Test Python Sniffer',
      author='Nikolay Markov',
      author_email='enchantner@gmail.com',
      ext_modules=[Extension('pysniff', ['src/pysniff.c'], include_dirs=['src'])]
)
