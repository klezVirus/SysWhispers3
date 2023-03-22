# Tests
This application should be used as a dependency from other projects. Development has been made using poetry, so you should have it installed.  
In case you really do not want to use poetry, you coul run test using `pytest` 

## Commands
While using poetry framework you could simply run
```bash
poetry run pytest
```

If you do not want to use poetry you can run
```bash
python3 -m pytest
```

## Behaviour
If everything is right you should generate 3 different files `syscalls.h`, `syscalls.c` and `syscalls-x64.asm` using the default command line:
```bash
./syswhispers3.py -p common
```

Some samples files are stored in `examples-output` so you can compare them with your results.

## Documentation
This project use [mkdocs](https://www.mkdocs.org/getting-started/) associated with [lazydocs](https://github.com/ml-tooling/lazydocs) to auto-generate documentation.  

1. Write your Doc-String by using [AutoDocString](https://marketplace.visualstudio.com/items?itemName=njpwerner.autodocstring) in VSCode
2. Generate the project documentation using LazyDoc
```sh
export PYTHONPATH=$PWD; lazydocs --output-path="./docs/documentation" --overview-file="README.md" --src-base-url="https://github.com/klezVirus/SysWhispers3/blob/master" syswhispers3/
```
3. Serving local docs for preview using mkdocs
```sh
mkdocs serve
```