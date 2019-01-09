.PHONY: clean

help:
	@echo "  clean           remove unwanted stuff"
	@echo "  dev             make a development package"
	@echo "  test            run the tests"
	@echo "  publish-test    package and upload a release to test.pypi.org"
	@echo "  publish-release package and upload a release to pypi.org"
	@echo "  html            use the sphinx-build based on reST build HTML file"

clean:
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +
	find . -name '.DS_Store' -exec rm -f {} +
	find . -name '__pycache__' -exec rm -rf {} +
	find . -name '.coverage' -exec rm -rf {} +
	rm -rf build dist *.egg-info +

dev:
	pip install .
	$(MAKE) clean

test:
	python setup.py test
	$(MAKE) clean

publish-test:
	python setup.py publish --test
	$(MAKE) clean

publish-release:
	python setup.py publish --release
	$(MAKE) clean

html:
	cd docs && sphinx-build -b html . _build/html
