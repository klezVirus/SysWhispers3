# Installation
You want to contribute to this project ? :tada:  
You are more than welcome, but before you head-start, please read the few instructions below...

## OS supported
- Debian 10
- Debian 11
- Ubuntu 20.04
- Ubuntu 22.04

## Setup a virtual environment
Python Virtual Environment is **strongly** suggested in order to avoid dependecy conflicts on your system. The [poetry](https://python-poetry.org/) project is used for development.  

Tools to generate your doc are strongly advised except if you like to do this manually. This project use

- lazydoc to auto-generate markdown doc from DocString
- mkdocs to auto-generate html page from basic markdown structure and lazydoc output
- mkdocs-awesome-pages-plugin in order to have a beautiful theme ;)

## Adapt code exceptions
If you are using vscode along with poetry you can find inside `pyproject.toml` some exclusion on Google style code. If you need to add some extras ones [here](http://www.pydocstyle.org/en/6.2.2/error_codes.html) is the Error codes.

## Install project
Once your [prerequises](contribute/prerequise) are met, you should then launch poetry and install dependencies
```bash
cd /path/to/project
poetry shell
poetry install
```