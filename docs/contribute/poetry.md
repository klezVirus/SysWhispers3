# Poetry cheat-sheet
The [Poetry](https://python-poetry.org/) project setup python virtual environment that jail dependencies of each project so it does not impact your host system.

#### Create a new project
```bash
poetry new <project-name>
```
#### Add a new lib
```bash
poetry add <library>
```
#### Remove a lib
```bash
poetry remove <library>
```
#### Update a lib
```bash
poetry update <library>
```
#### Add a new development lib
```bash
poetry add -G dev <library>
```
#### Get venv path
```bash
poetry run which python
```
#### Run app
```bash
poetry run python app.py
```
#### Run tests
```bash
poetry run python -m unittest discover
```
#### Show dependencies
```bash
poetry show
```
#### Disable virtual environment creation
```bash
poetry config virtualenvs.create false
```
#### List configuratiom
```bash
poetry config --list
```

## Configure your editor
- Set lint to `pylint`
- ...
