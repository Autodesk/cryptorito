test: testenv version
	./scripts/ci

version:
	cp version cryptorito/version

testenv:
	test -z $(TRAVIS) && (test -d .ci-env || ( mkdir .ci-env && virtualenv .ci-env )) || true
	test -z $(TRAVIS) && \
		(echo "Non Travis" && .ci-env/bin/pip install -r requirements.txt -r requirements-dev.txt --upgrade) || \
		(echo "Travis" && pip install -r requirements.txt -r requirements-dev.txt)

package: version
	python setup.py sdist

.PHONY: package test clean testenv
