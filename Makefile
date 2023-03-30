init:
	python3 -m pip install -r ./requirements.txt

install:
	python3 setup.py install

install-local:
	python3 -m pip install -v -e .

sign:
	./sign.sh sign-agreement

build_init:
	export PATH=$PATH:~/.local/bin

build_macos:
	python3 -m pip install -r ./build_configs/macos/requirements.txt
	pyinstaller ./build_configs/macos/build.spec;

build_linux:
	python3 -m pip install -r ./build_configs/linux/requirements.txt
	pyinstaller ./build_configs/linux/build.spec;

build_windows:
	python3 -m pip install -r ./build_configs/windows/requirements.txt
	pyinstaller ./build_configs/windows/build.spec;