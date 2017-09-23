ifndef TRAVIS
	CIENV = $(shell pwd)/.ci-env/bin/
endif

test: testenv version
	coverage erase
	$(CIENV)pep8 cryptorito
	$(CIENV)pylint --rcfile=/dev/null cryptorito
	CRYPTORITO_LOG_LEVEL=debug COVERAGE_FILE=.coverage \
		$(CIENV)nose2 --verbose \
		-C --coverage cryptorito
	$(CIENV)bandit -r cryptorito
	$(CIENV)vulture cryptorito cryptorito.py tests/whitelist.py
	./scripts/integration
	coverage report -m
	test -z $(TRAVIS) && coverage erase|| true

version:
	cp version cryptorito/version

testenv:
	test -z $(TRAVIS) && (test -d .ci-env || ( mkdir .ci-env && virtualenv .ci-env )) || true
	test -z $(TRAVIS) && \
		(echo "Non Travis" && .ci-env/bin/pip install -r requirements.txt -r requirements-dev.txt --upgrade) || \
		(echo "Travis" && pip install -r requirements.txt -r requirements-dev.txt)

package: version
	python setup.py sdist

clean:
	rm -rf cryptorito.egg-info dist build *.pyc cryptorito/__pycache__ cryptorito/version

distclean: clean
	rm -rf .bats .bats-git .ci-env

.PHONY: package test clean testenv version
