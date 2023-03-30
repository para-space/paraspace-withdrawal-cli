init:
	python -m pip install -r ./requirements.txt

install:
	python setup.py install

install-local:
	python -m pip install -v -e .

build_macos:
	python -m pip install -r ./build_configs/macos/requirements.txt
	export PYTHONHASHSEED=42;
	pyinstaller ./build_configs/macos/build.spec;
